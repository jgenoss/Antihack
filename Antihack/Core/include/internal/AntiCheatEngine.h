/**
 * AntiCheatCore - Unified AntiCheat Engine
 * Main orchestrator that manages all security modules
 */

#pragma once

#ifndef AC_ANTICHEAT_ENGINE_H
#define AC_ANTICHEAT_ENGINE_H

#include "common.h"
#include "FileProtection.h"
#include "EncryptionLib.h"
#include "MacroDetector.h"
#include "HookDetector.h"
#include "CheatSignatures.h"
#include "IPCManager.h"

namespace AntiCheat {

class AntiCheatEngine {
public:
    struct Config {
        // Scan intervals (ms)
        DWORD memoryScanInterval;
        DWORD hookScanInterval;
        DWORD fileScanInterval;
        DWORD processScanInterval;

        // Feature flags
        bool enableMemoryScan;
        bool enableHookDetection;
        bool enableFileProtection;
        bool enableMacroDetection;
        bool enableProcessMonitoring;
        bool enableAntiDebug;

        // IPC settings
        std::wstring pipeName;
        DWORD heartbeatInterval;

        // Paths
        std::wstring gameBasePath;
        std::wstring configPath;
        std::wstring signaturesPath;

        Config() {
            memoryScanInterval = 5000;
            hookScanInterval = 3000;
            fileScanInterval = 10000;
            processScanInterval = 2000;

            enableMemoryScan = true;
            enableHookDetection = true;
            enableFileProtection = true;
            enableMacroDetection = true;
            enableProcessMonitoring = true;
            enableAntiDebug = true;

            pipeName = L"\\\\.\\pipe\\AntiCheatIPC";
            heartbeatInterval = 1000;
        }
    };

    struct EngineStatus {
        bool isRunning;
        bool isConnected;
        int totalDetections;
        int criticalDetections;
        DWORD uptime;
        DWORD lastScanTime;
        std::string statusMessage;
    };

private:
    // Modules
    std::unique_ptr<FileProtection> m_fileProtection;
    std::unique_ptr<EncryptionLib> m_encryption;
    std::unique_ptr<MacroDetector> m_macroDetector;
    std::unique_ptr<HookDetector> m_hookDetector;
    std::unique_ptr<CheatSignatures> m_signatures;
    std::unique_ptr<IPCManager> m_ipcManager;

    // State
    Config m_config;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_initialized{false};
    DWORD m_startTime;
    int m_totalDetections;
    int m_criticalDetections;
    std::string m_lastError;
    std::mutex m_mutex;

    // Monitor threads
    HANDLE m_monitorThread;
    std::vector<HANDLE> m_workerThreads;

    // Callbacks
    DetectionCallback m_detectionCallback;
    MessageCallback m_logCallback;

    // Thread procedures
    static DWORD WINAPI MonitorThreadProc(LPVOID param);
    void MonitorLoop();

    // Scan methods
    void PerformMemoryScan();
    void PerformHookScan();
    void PerformFileScan();
    void PerformProcessScan();
    void PerformAntiDebugCheck();

    // Event handling
    void OnDetection(const DetectionEvent& event);
    void OnIPCMessage(const IPCManager::Message& msg);

    // Logging
    void Log(const std::string& message);
    void LogError(const std::string& message);

public:
    AntiCheatEngine();
    ~AntiCheatEngine();

    // Lifecycle
    bool Initialize(const Config& config = Config());
    bool Start();
    void Stop();
    void Shutdown();

    // Configuration
    bool LoadConfig(const std::wstring& path);
    bool SaveConfig(const std::wstring& path);
    void SetConfig(const Config& config);
    const Config& GetConfig() const { return m_config; }

    // Callbacks
    void SetDetectionCallback(DetectionCallback callback);
    void SetLogCallback(MessageCallback callback);

    // Manual operations
    bool ForceMemoryScan();
    bool ForceHookScan();
    bool ForceFileScan();
    bool ForceProcessScan();
    bool ForceFullScan();

    // Module access
    FileProtection* GetFileProtection() { return m_fileProtection.get(); }
    EncryptionLib* GetEncryption() { return m_encryption.get(); }
    MacroDetector* GetMacroDetector() { return m_macroDetector.get(); }
    HookDetector* GetHookDetector() { return m_hookDetector.get(); }
    CheatSignatures* GetSignatures() { return m_signatures.get(); }
    IPCManager* GetIPCManager() { return m_ipcManager.get(); }

    // Status
    bool IsRunning() const { return m_running; }
    bool IsInitialized() const { return m_initialized; }
    EngineStatus GetStatus() const;
    const std::string& GetLastError() const { return m_lastError; }

    // Singleton access
    static AntiCheatEngine& GetInstance();
};

} // namespace AntiCheat

#endif // AC_ANTICHEAT_ENGINE_H
