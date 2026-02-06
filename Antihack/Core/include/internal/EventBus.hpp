/**
 * AntiCheatCore - Thread-Safe Event Bus
 *
 * Implements the Observer pattern to decouple detection producers
 * (modules) from detection consumers (engine, IPC, loggers).
 *
 * Before: Each module held its own callback, callbacks invoked
 *         directly from module threads with inconsistent locking.
 * After:  All modules publish events to the EventBus. Subscribers
 *         receive events on a dedicated dispatch thread, eliminating
 *         deadlock risk and ensuring consistent ordering.
 *
 * Follows: Open/Closed Principle, Dependency Inversion
 */

#pragma once

#ifndef AC_EVENT_BUS_HPP
#define AC_EVENT_BUS_HPP

#include "common.h"
#include "HandleGuard.hpp"
#include <queue>
#include <vector>
#include <functional>
#include <mutex>
#include <atomic>
#include <string>

namespace AntiCheat {

/**
 * Thread-safe event bus for DetectionEvent distribution.
 *
 * Producers call Publish() from any thread.
 * Subscribers receive events sequentially on the dispatch thread,
 * guaranteeing no concurrent callback invocations.
 *
 * Lifetime: Create one instance in AntiCheatEngine. Pass non-owning
 * reference to modules. Destroy after all modules are stopped.
 */
class EventBus final {
public:
    using Subscriber = std::function<void(const DetectionEvent&)>;
    using SubscriptionId = uint32_t;

    EventBus();
    ~EventBus();

    // Non-copyable, non-movable (shared resource)
    EventBus(const EventBus&) = delete;
    EventBus& operator=(const EventBus&) = delete;
    EventBus(EventBus&&) = delete;
    EventBus& operator=(EventBus&&) = delete;

    /**
     * Starts the dispatch thread. Events published before Start()
     * are queued and delivered once started.
     *
     * @return true if the dispatch thread was created successfully.
     */
    bool Start();

    /**
     * Stops the dispatch thread. Remaining queued events are flushed
     * (delivered) before the thread exits.
     *
     * @param flushRemaining  If true, dispatch remaining events before stopping.
     */
    void Stop(bool flushRemaining = true);

    /**
     * Publishes a detection event. Thread-safe: may be called from any thread.
     * The event is queued and delivered asynchronously on the dispatch thread.
     *
     * @param event  The detection event to publish.
     */
    void Publish(const DetectionEvent& event);

    /**
     * Subscribes to detection events.
     *
     * @param subscriber  Callback invoked for each event.
     * @return Unique subscription ID for later unsubscription.
     */
    [[nodiscard]] SubscriptionId Subscribe(Subscriber subscriber);

    /**
     * Removes a subscription.
     *
     * @param id  The subscription ID returned by Subscribe().
     */
    void Unsubscribe(SubscriptionId id);

    /**
     * Returns the number of events published since Start().
     */
    [[nodiscard]] uint64_t GetPublishedCount() const noexcept {
        return m_publishedCount.load(std::memory_order_relaxed);
    }

    /**
     * Returns the number of events delivered to subscribers since Start().
     */
    [[nodiscard]] uint64_t GetDeliveredCount() const noexcept {
        return m_deliveredCount.load(std::memory_order_relaxed);
    }

    /**
     * Returns true if the dispatch thread is running.
     */
    [[nodiscard]] bool IsRunning() const noexcept {
        return m_running.load(std::memory_order_acquire);
    }

private:
    struct SubscriptionEntry {
        SubscriptionId id;
        Subscriber     callback;
    };

    // Event queue (protected by m_queueMutex)
    std::queue<DetectionEvent>     m_eventQueue;
    mutable std::mutex             m_queueMutex;

    // Subscriber list (protected by m_subscriberMutex)
    std::vector<SubscriptionEntry> m_subscribers;
    mutable std::mutex             m_subscriberMutex;
    SubscriptionId                 m_nextSubscriptionId;

    // Dispatch thread
    KernelHandle                   m_dispatchThread;
    KernelHandle                   m_wakeEvent;
    std::atomic<bool>              m_running;
    std::atomic<bool>              m_shouldStop;
    std::atomic<bool>              m_flushOnStop;

    // Statistics
    std::atomic<uint64_t>          m_publishedCount;
    std::atomic<uint64_t>          m_deliveredCount;

    // Thread entry point
    static DWORD WINAPI DispatchThreadProc(LPVOID param);

    /**
     * Main dispatch loop: dequeues events and delivers to subscribers.
     */
    void DispatchLoop();

    /**
     * Delivers a single event to all current subscribers.
     * Called only from the dispatch thread.
     */
    void DeliverEvent(const DetectionEvent& event);

    /**
     * Drains all remaining events from the queue and delivers them.
     */
    void FlushQueue();
};

} // namespace AntiCheat

#endif // AC_EVENT_BUS_HPP
