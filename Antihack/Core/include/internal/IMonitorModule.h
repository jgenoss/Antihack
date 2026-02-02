/**
 * AntiCheatCore - Monitor Module Interface
 * Base class for all monitoring modules to ensure proper OOP and thread safety
 */

#pragma once

#ifndef AC_IMONITOR_MODULE_H
#define AC_IMONITOR_MODULE_H

#include "common.h"

namespace AntiCheat {

/**
 * Thread-safe base class for monitoring modules.
 *
 * Key features:
 * - Safe start/stop with proper synchronization
 * - Monitoring thread won't block main process
 * - Callbacks are ALWAYS invoked outside of locks to prevent deadlocks
 * - Low-priority thread to minimize impact on game performance
 */
class IMonitorModule {
public:
    // Module state
    enum class ModuleState {
        Stopped = 0,
        Starting,
        Running,
        Stopping
    };

protected:
    // Thread control
    std::atomic<ModuleState> m_state{ModuleState::Stopped};
    std::atomic<bool> m_shouldStop{false};
    HANDLE m_monitorThread;
    DWORD m_threadId;
    DWORD m_monitorInterval;

    // Synchronization
    mutable std::mutex m_dataMutex;       // Protects module data
    mutable std::mutex m_callbackMutex;   // Separate mutex for callbacks
    HANDLE m_stopEvent;                    // Event for clean shutdown

    // Identification
    std::string m_moduleName;
    std::string m_lastError;

    // Detection callback
    DetectionCallback m_detectionCallback;

    // Pending events to dispatch outside of lock
    std::vector<DetectionEvent> m_pendingEvents;
    std::mutex m_eventsMutex;

    /**
     * Thread procedure wrapper - DO NOT OVERRIDE
     */
    static DWORD WINAPI ThreadProc(LPVOID param) {
        IMonitorModule* self = static_cast<IMonitorModule*>(param);

        // Set thread priority to below normal to not affect game
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

        self->m_state = ModuleState::Running;
        self->OnMonitorStart();

        while (!self->m_shouldStop) {
            // Perform monitoring work
            self->DoMonitorCycle();

            // Dispatch any pending events OUTSIDE of data lock
            self->DispatchPendingEvents();

            // Wait for interval or stop signal
            DWORD waitResult = WaitForSingleObject(self->m_stopEvent, self->m_monitorInterval);
            if (waitResult == WAIT_OBJECT_0) {
                // Stop signal received
                break;
            }
        }

        self->OnMonitorStop();
        self->m_state = ModuleState::Stopped;
        return 0;
    }

    /**
     * Override this to perform actual monitoring work.
     * Called periodically at m_monitorInterval.
     * Use QueueEvent() to report detections - never call callbacks directly!
     */
    virtual void DoMonitorCycle() = 0;

    /**
     * Optional: Called when monitor thread starts
     */
    virtual void OnMonitorStart() {}

    /**
     * Optional: Called when monitor thread is about to stop
     */
    virtual void OnMonitorStop() {}

    /**
     * Queue a detection event for dispatch.
     * SAFE to call from within DoMonitorCycle() while holding data mutex.
     * Events are dispatched outside of any locks.
     */
    void QueueEvent(const DetectionEvent& event) {
        std::lock_guard<std::mutex> lock(m_eventsMutex);
        m_pendingEvents.push_back(event);
    }

    /**
     * Dispatch pending events - called OUTSIDE of data lock
     */
    void DispatchPendingEvents() {
        std::vector<DetectionEvent> events;

        // Quickly grab pending events
        {
            std::lock_guard<std::mutex> lock(m_eventsMutex);
            events.swap(m_pendingEvents);
        }

        // Now dispatch without any locks held
        if (!events.empty()) {
            std::lock_guard<std::mutex> cbLock(m_callbackMutex);
            if (m_detectionCallback) {
                for (const auto& event : events) {
                    try {
                        m_detectionCallback(event);
                    } catch (...) {
                        // Never let callback exceptions crash monitoring
                    }
                }
            }
        }
    }

public:
    IMonitorModule(const std::string& name, DWORD defaultInterval = 1000)
        : m_monitorThread(NULL)
        , m_threadId(0)
        , m_monitorInterval(defaultInterval)
        , m_stopEvent(NULL)
        , m_moduleName(name) {
    }

    virtual ~IMonitorModule() {
        StopMonitoring();
        if (m_stopEvent) {
            CloseHandle(m_stopEvent);
            m_stopEvent = NULL;
        }
    }

    // Prevent copying
    IMonitorModule(const IMonitorModule&) = delete;
    IMonitorModule& operator=(const IMonitorModule&) = delete;

    /**
     * Initialize the module. Override to add custom initialization.
     */
    virtual bool Initialize() {
        if (!m_stopEvent) {
            m_stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            if (!m_stopEvent) {
                m_lastError = "Failed to create stop event";
                return false;
            }
        }
        return true;
    }

    /**
     * Shutdown the module. Override to add custom cleanup.
     */
    virtual void Shutdown() {
        StopMonitoring();
    }

    /**
     * Start the monitoring thread.
     * Thread runs at BELOW_NORMAL priority to not affect main process.
     *
     * @param intervalMs Monitoring interval in milliseconds
     * @return true if started successfully
     */
    bool StartMonitoring(DWORD intervalMs = 0) {
        // Check if already running
        ModuleState expected = ModuleState::Stopped;
        if (!m_state.compare_exchange_strong(expected, ModuleState::Starting)) {
            // Already running or in transition
            return m_state == ModuleState::Running;
        }

        if (intervalMs > 0) {
            m_monitorInterval = intervalMs;
        }

        // Ensure stop event is created
        if (!m_stopEvent) {
            if (!Initialize()) {
                m_state = ModuleState::Stopped;
                return false;
            }
        }

        // Reset stop event and flag
        ResetEvent(m_stopEvent);
        m_shouldStop = false;

        // Create monitoring thread
        m_monitorThread = CreateThread(
            NULL,
            0,
            ThreadProc,
            this,
            0,
            &m_threadId
        );

        if (!m_monitorThread) {
            m_state = ModuleState::Stopped;
            m_lastError = "Failed to create monitor thread: " + std::to_string(GetLastError());
            return false;
        }

        return true;
    }

    /**
     * Stop the monitoring thread gracefully.
     * Uses event signaling for clean shutdown without blocking main thread.
     *
     * @param waitMs Maximum time to wait for thread to stop
     */
    void StopMonitoring(DWORD waitMs = 5000) {
        ModuleState expected = ModuleState::Running;
        if (!m_state.compare_exchange_strong(expected, ModuleState::Stopping)) {
            // Not running
            return;
        }

        // Signal thread to stop
        m_shouldStop = true;
        if (m_stopEvent) {
            SetEvent(m_stopEvent);
        }

        // Wait for thread to finish
        if (m_monitorThread) {
            DWORD waitResult = WaitForSingleObject(m_monitorThread, waitMs);
            if (waitResult == WAIT_TIMEOUT) {
                // Thread didn't stop gracefully - force terminate as last resort
                TerminateThread(m_monitorThread, 1);
            }
            CloseHandle(m_monitorThread);
            m_monitorThread = NULL;
            m_threadId = 0;
        }

        m_state = ModuleState::Stopped;
    }

    /**
     * Check if monitoring is active
     */
    bool IsMonitoring() const {
        return m_state == ModuleState::Running;
    }

    /**
     * Get current module state
     */
    ModuleState GetState() const {
        return m_state.load();
    }

    /**
     * Set the detection callback.
     * Callbacks are invoked on the monitoring thread, OUTSIDE of any locks.
     */
    void SetDetectionCallback(DetectionCallback callback) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_detectionCallback = callback;
    }

    /**
     * Set monitoring interval (takes effect on next cycle)
     */
    void SetMonitorInterval(DWORD intervalMs) {
        m_monitorInterval = intervalMs;
    }

    /**
     * Get monitoring interval
     */
    DWORD GetMonitorInterval() const {
        return m_monitorInterval;
    }

    /**
     * Get module name
     */
    const std::string& GetModuleName() const {
        return m_moduleName;
    }

    /**
     * Get last error message
     */
    const std::string& GetLastError() const {
        return m_lastError;
    }

    /**
     * Get thread ID (0 if not running)
     */
    DWORD GetThreadId() const {
        return m_threadId;
    }
};

/**
 * Helper class for modules that need multiple specialized callbacks
 */
template<typename TEvent>
class TypedMonitorModule : public IMonitorModule {
public:
    using TypedCallback = std::function<void(const TEvent&)>;

protected:
    TypedCallback m_typedCallback;
    std::vector<TEvent> m_pendingTypedEvents;
    std::mutex m_typedEventsMutex;

    void QueueTypedEvent(const TEvent& event) {
        std::lock_guard<std::mutex> lock(m_typedEventsMutex);
        m_pendingTypedEvents.push_back(event);
    }

    void DispatchTypedEvents() {
        std::vector<TEvent> events;
        {
            std::lock_guard<std::mutex> lock(m_typedEventsMutex);
            events.swap(m_pendingTypedEvents);
        }

        if (!events.empty()) {
            std::lock_guard<std::mutex> cbLock(m_callbackMutex);
            if (m_typedCallback) {
                for (const auto& event : events) {
                    try {
                        m_typedCallback(event);
                    } catch (...) {}
                }
            }
        }
    }

public:
    TypedMonitorModule(const std::string& name, DWORD defaultInterval = 1000)
        : IMonitorModule(name, defaultInterval) {}

    void SetTypedCallback(TypedCallback callback) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_typedCallback = callback;
    }
};

} // namespace AntiCheat

#endif // AC_IMONITOR_MODULE_H
