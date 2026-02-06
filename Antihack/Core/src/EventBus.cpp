/**
 * AntiCheatCore - Thread-Safe Event Bus Implementation
 */

#include "../include/internal/EventBus.hpp"
#include <algorithm>

namespace AntiCheat {

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

EventBus::EventBus()
    : m_nextSubscriptionId(1)
    , m_running(false)
    , m_shouldStop(false)
    , m_flushOnStop(true)
    , m_publishedCount(0)
    , m_deliveredCount(0) {
}

EventBus::~EventBus() {
    Stop(false);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool EventBus::Start() {
    if (m_running.load(std::memory_order_acquire)) {
        return true; // Already running
    }

    m_shouldStop.store(false, std::memory_order_release);

    // Create wake event (auto-reset)
    m_wakeEvent = MakeEvent(/*manualReset=*/false, /*initialState=*/false);
    if (!m_wakeEvent) {
        return false;
    }

    // Create dispatch thread
    DWORD threadId = 0;
    HANDLE rawThread = ::CreateThread(
        nullptr, 0, DispatchThreadProc, this, 0, &threadId);

    if (rawThread == nullptr) {
        m_wakeEvent.Reset();
        return false;
    }

    m_dispatchThread = KernelHandle(rawThread);

    // Set below-normal priority to avoid impacting game
    ::SetThreadPriority(m_dispatchThread.Get(), THREAD_PRIORITY_BELOW_NORMAL);

    m_running.store(true, std::memory_order_release);
    return true;
}

void EventBus::Stop(bool flushRemaining) {
    if (!m_running.load(std::memory_order_acquire)) {
        return;
    }

    m_flushOnStop.store(flushRemaining, std::memory_order_release);
    m_shouldStop.store(true, std::memory_order_release);

    // Wake the dispatch thread so it can exit
    if (m_wakeEvent) {
        ::SetEvent(m_wakeEvent.Get());
    }

    // Wait for dispatch thread to finish
    if (m_dispatchThread) {
        DWORD waitResult = ::WaitForSingleObject(m_dispatchThread.Get(), 5000);
        if (waitResult == WAIT_TIMEOUT) {
            // Last resort: force terminate. This should never happen in practice
            // because DispatchLoop checks m_shouldStop regularly.
            ::TerminateThread(m_dispatchThread.Get(), 1);
        }
    }

    m_dispatchThread.Reset();
    m_wakeEvent.Reset();
    m_running.store(false, std::memory_order_release);
}

// ============================================================================
// PUBLISHING
// ============================================================================

void EventBus::Publish(const DetectionEvent& event) {
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        m_eventQueue.push(event);
    }

    m_publishedCount.fetch_add(1, std::memory_order_relaxed);

    // Wake the dispatch thread
    if (m_wakeEvent) {
        ::SetEvent(m_wakeEvent.Get());
    }
}

// ============================================================================
// SUBSCRIPTIONS
// ============================================================================

EventBus::SubscriptionId EventBus::Subscribe(Subscriber subscriber) {
    std::lock_guard<std::mutex> lock(m_subscriberMutex);

    SubscriptionId newId = m_nextSubscriptionId++;

    SubscriptionEntry entry;
    entry.id = newId;
    entry.callback = std::move(subscriber);

    m_subscribers.push_back(std::move(entry));

    return newId;
}

void EventBus::Unsubscribe(SubscriptionId id) {
    std::lock_guard<std::mutex> lock(m_subscriberMutex);

    m_subscribers.erase(
        std::remove_if(m_subscribers.begin(), m_subscribers.end(),
                        [id](const SubscriptionEntry& entry) {
                            return entry.id == id;
                        }),
        m_subscribers.end());
}

// ============================================================================
// DISPATCH THREAD
// ============================================================================

DWORD WINAPI EventBus::DispatchThreadProc(LPVOID param) {
    EventBus* self = static_cast<EventBus*>(param);
    self->DispatchLoop();
    return 0;
}

void EventBus::DispatchLoop() {
    while (!m_shouldStop.load(std::memory_order_acquire)) {
        // Wait for events or stop signal (timeout every 100ms for responsiveness)
        ::WaitForSingleObject(m_wakeEvent.Get(), 100);

        // Process all queued events
        FlushQueue();
    }

    // Final flush if requested
    if (m_flushOnStop.load(std::memory_order_acquire)) {
        FlushQueue();
    }
}

void EventBus::DeliverEvent(const DetectionEvent& event) {
    // Take a snapshot of subscribers to avoid holding the lock during callbacks
    std::vector<SubscriptionEntry> subscriberSnapshot;
    {
        std::lock_guard<std::mutex> lock(m_subscriberMutex);
        subscriberSnapshot = m_subscribers;
    }

    for (const auto& entry : subscriberSnapshot) {
        try {
            entry.callback(event);
        } catch (...) {
            // Never allow a subscriber exception to crash the dispatch thread.
            // In a production system, this would be logged.
        }
    }

    m_deliveredCount.fetch_add(1, std::memory_order_relaxed);
}

void EventBus::FlushQueue() {
    // Drain the queue in batches to minimize lock contention
    while (true) {
        DetectionEvent event;
        bool hasEvent = false;

        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            if (!m_eventQueue.empty()) {
                event = m_eventQueue.front();
                m_eventQueue.pop();
                hasEvent = true;
            }
        }

        if (!hasEvent) {
            break;
        }

        DeliverEvent(event);
    }
}

} // namespace AntiCheat
