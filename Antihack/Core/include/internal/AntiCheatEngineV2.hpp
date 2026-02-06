/**
 * AntiCheatCore - Refactored AntiCheat Engine (V2)
 *
 * Main orchestrator that manages all security modules.
 *
 * Improvements over V1 (AntiCheatEngine.h):
 *   - Thread-safe Meyer's Singleton (no raw new/delete)
 *   - RAII HandleGuard for all thread handles
 *   - EventBus for decoupled event distribution (Observer pattern)
 *   - ConfigParser integration (replaces TODO stubs)
 *   - IConfigurable interface for runtime reconfiguration
 *   - Const-correctness throughout
 *   - No global mutable state
 *
 * Follows: SOLID, RAII, Rule of Five/Zero
 */

#pragma once

#ifndef AC_ANTICHEAT_ENGINE_V2_HPP
#define AC_ANTICHEAT_ENGINE_V2_HPP

#include "common.h"
#include "HandleGuard.hpp"
#include "EventBus.hpp"
#include "ConfigParser.hpp"
#include "IConfigurable.hpp"
#include "ModuleTypes.hpp"

// Forward declarations to avoid including heavy module headers
namespace AntiCheat {
    class FileProtectionV2;
    class EncryptionLibV2;
    class ProcessMonitorV2;
    class MacroDetector;
    class HookDetector;
    class CheatSignatures;
    class IPCManager;
}

namespace AntiCheat {

/**
 * Central orchestrator for the anti-cheat system.
 *
 * Owns all detection modules via unique_ptr.
 * Coordinates scanning schedules and event routing.
 *
 * Usage:
 *   auto& engine = AntiCheatEngineV2::GetInstance();
 *   engine.Initialize(config);
 *   engine.Start();
 *   // ... game runs ...
 *   engine.Stop();
 *   engine.Shutdown();
 */
class AntiCheatEngineV2 final : public IConfigurable {
public:
    /**
     * Engine configuration - all intervals in milliseconds.
     */
    struct Config {
        // Scan intervals
        DWORD memoryScanIntervalMs;
        DWORD hookScanIntervalMs;
        DWORD fileScanIntervalMs;
        DWORD processScanIntervalMs;
        DWORD antiDebugIntervalMs;

        // Feature toggles
        bool enableMemoryScan;
        bool enableHookDetection;
        bool enableFileProtection;
        bool enableMacroDetection;
        bool enableProcessMonitoring;
        bool enableAntiDebug;

        // IPC settings
        std::wstring pipeName;
        DWORD heartbeatIntervalMs;

        // Paths
        std::wstring gameBasePath;
        std::wstring configFilePath;
        std::wstring signaturesFilePath;

        Config()
            : memoryScanIntervalMs(5000)
            , hookScanIntervalMs(3000)
            , fileScanIntervalMs(10000)
            , processScanIntervalMs(2000)
            , antiDebugIntervalMs(1000)
            , enableMemoryScan(true)
            , enableHookDetection(true)
            , enableFileProtection(true)
            , enableMacroDetection(true)
            , enableProcessMonitoring(true)
            , enableAntiDebug(true)
            , pipeName(L"\\\\.\\pipe\\AntiCheatIPC")
            , heartbeatIntervalMs(1000) {
        }
    };

    /**
     * Snapshot of the engine's current operational status.
     */
    struct EngineStatus {
        bool        isRunning;
        bool        isIpcConnected;
        int         totalDetections;
        int         criticalDetections;
        DWORD       uptimeMs;
        DWORD       lastScanTimeMs;
        uint64_t    eventsPublished;
        uint64_t    eventsDelivered;
        std::string statusMessage;
    };

    // ========================================================================
    // SINGLETON ACCESS (Meyer's - thread-safe in C++11+)
    // ========================================================================

    /**
     * Returns the singleton instance. Thread-safe per C++11 6.7 [stmt.dcl].
     * No raw new/delete: the instance lives in static storage.
     */
    static AntiCheatEngineV2& GetInstance();

    // Non-copyable, non-movable (singleton)
    AntiCheatEngineV2(const AntiCheatEngineV2&) = delete;
    AntiCheatEngineV2& operator=(const AntiCheatEngineV2&) = delete;
    AntiCheatEngineV2(AntiCheatEngineV2&&) = delete;
    AntiCheatEngineV2& operator=(AntiCheatEngineV2&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    /**
     * Creates and initializes all modules. Must be called before Start().
     *
     * @param config  Engine configuration. Defaults are used for any unset fields.
     * @return true if all enabled modules initialized successfully.
     */
    bool Initialize(const Config& config = Config());

    /**
     * Starts monitoring threads and connects IPC.
     * Initialize() must have been called first.
     *
     * @return true if the engine started successfully.
     */
    bool Start();

    /**
     * Stops all monitoring threads and disconnects IPC.
     * Safe to call even if not started.
     */
    void Stop();

    /**
     * Shuts down and destroys all modules.
     * After this call, Initialize() must be called again to reuse.
     */
    void Shutdown();

    // ========================================================================
    // CONFIGURATION (IConfigurable)
    // ========================================================================

    bool ApplyConfig(const ConfigMap& config) override;
    void ExportConfig(ConfigMap& outConfig) const override;
    [[nodiscard]] std::string GetConfigSection() const override { return "Engine"; }

    /**
     * Loads configuration from an INI file and distributes to all modules.
     *
     * @param filePath  Path to the INI configuration file.
     * @return true if loaded and applied successfully.
     */
    bool LoadConfigFromFile(const std::wstring& filePath);

    /**
     * Saves current configuration of all modules to an INI file.
     *
     * @param filePath  Path for the output INI file.
     * @return true if saved successfully.
     */
    bool SaveConfigToFile(const std::wstring& filePath) const;

    /** Replaces the entire engine configuration at runtime. */
    void SetConfig(const Config& config);

    /** Returns a const reference to the current configuration. */
    [[nodiscard]] const Config& GetConfig() const noexcept { return m_config; }

    // ========================================================================
    // EVENT BUS ACCESS
    // ========================================================================

    /**
     * Returns a non-owning reference to the event bus.
     * Modules and external code can subscribe to detection events.
     */
    [[nodiscard]] EventBus& GetEventBus() noexcept { return m_eventBus; }
    [[nodiscard]] const EventBus& GetEventBus() const noexcept { return m_eventBus; }

    // ========================================================================
    // MANUAL SCAN TRIGGERS
    // ========================================================================

    bool ForceMemoryScan();
    bool ForceHookScan();
    bool ForceFileScan();
    bool ForceProcessScan();
    bool ForceFullScan();

    // ========================================================================
    // MODULE ACCESS (non-owning pointers, may be nullptr if disabled)
    // ========================================================================

    [[nodiscard]] FileProtectionV2*  GetFileProtection()   const noexcept { return m_fileProtection.get(); }
    [[nodiscard]] EncryptionLibV2*   GetEncryption()       const noexcept { return m_encryption.get(); }
    [[nodiscard]] ProcessMonitorV2*  GetProcessMonitor()   const noexcept { return m_processMonitor.get(); }
    [[nodiscard]] MacroDetector*     GetMacroDetector()    const noexcept { return m_macroDetector.get(); }
    [[nodiscard]] HookDetector*      GetHookDetector()     const noexcept { return m_hookDetector.get(); }
    [[nodiscard]] CheatSignatures*   GetSignatures()       const noexcept { return m_signatures.get(); }
    [[nodiscard]] IPCManager*        GetIPCManager()       const noexcept { return m_ipcManager.get(); }

    // ========================================================================
    // STATUS
    // ========================================================================

    [[nodiscard]] bool IsRunning()     const noexcept { return m_running.load(std::memory_order_acquire); }
    [[nodiscard]] bool IsInitialized() const noexcept { return m_initialized.load(std::memory_order_acquire); }
    [[nodiscard]] EngineStatus GetStatus() const;
    [[nodiscard]] const std::string& GetLastError() const noexcept { return m_lastError; }

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR (Singleton)
    // ========================================================================

    AntiCheatEngineV2();
    ~AntiCheatEngineV2();

    // ========================================================================
    // MODULES (owned via unique_ptr - RAII)
    // ========================================================================

    std::unique_ptr<FileProtectionV2>  m_fileProtection;
    std::unique_ptr<EncryptionLibV2>   m_encryption;
    std::unique_ptr<ProcessMonitorV2>  m_processMonitor;
    std::unique_ptr<MacroDetector>     m_macroDetector;
    std::unique_ptr<HookDetector>      m_hookDetector;
    std::unique_ptr<CheatSignatures>   m_signatures;
    std::unique_ptr<IPCManager>        m_ipcManager;

    // ========================================================================
    // INFRASTRUCTURE
    // ========================================================================

    EventBus        m_eventBus;
    ConfigParser    m_configParser;

    // ========================================================================
    // STATE
    // ========================================================================

    Config              m_config;
    std::atomic<bool>   m_running;
    std::atomic<bool>   m_initialized;
    DWORD               m_startTime;
    std::atomic<int>    m_totalDetections;
    std::atomic<int>    m_criticalDetections;
    std::string         m_lastError;
    mutable std::mutex  m_mutex;

    // ========================================================================
    // MONITOR THREAD (RAII handle)
    // ========================================================================

    KernelHandle m_monitorThread;
    KernelHandle m_stopEvent;

    static DWORD WINAPI MonitorThreadProc(LPVOID param);
    void MonitorLoop();

    // ========================================================================
    // SCAN METHODS
    // ========================================================================

    void PerformMemoryScan();
    void PerformHookScan();
    void PerformFileScan();
    void PerformProcessScan();
    void PerformAntiDebugCheck();

    // ========================================================================
    // EVENT HANDLING
    // ========================================================================

    /**
     * Central detection handler. Publishes events to the EventBus,
     * updates statistics, and forwards to IPC.
     */
    void OnDetection(const DetectionEvent& event);

    /**
     * Handles incoming IPC commands from the C# application.
     */
    void OnIPCMessage(const IPCManager::Message& msg);

    // ========================================================================
    // LOGGING
    // ========================================================================

    /** Subscriber ID for our own event bus subscription (for IPC forwarding). */
    EventBus::SubscriptionId m_ipcForwarderSubscription;

    void Log(const std::string& message) const;
    void LogError(const std::string& message);
};

} // namespace AntiCheat

#endif // AC_ANTICHEAT_ENGINE_V2_HPP
