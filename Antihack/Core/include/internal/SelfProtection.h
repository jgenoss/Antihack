/**
 * AntiCheatCore - Self Protection Module
 * Protects anticheat from being suspended/terminated by tools like Process Hacker
 */

#pragma once

#ifndef AC_SELF_PROTECTION_H
#define AC_SELF_PROTECTION_H

#include "common.h"

namespace AntiCheat {

class SelfProtection {
public:
    // Thread protection info
    struct ThreadInfo {
        DWORD threadId;
        HANDLE handle;
        DWORD lastCheckTime;
        bool isCritical;
        bool wasSuspended;
    };

    // Protection events
    struct ProtectionEvent {
        DWORD timestamp;
        std::string eventType;
        std::string description;
        DWORD processId;
        std::wstring processName;
    };

    using ThreatCallback = std::function<void(const ProtectionEvent&)>;

private:
    // Thread monitoring
    std::vector<ThreadInfo> m_protectedThreads;
    std::atomic<bool> m_monitoring{false};
    HANDLE m_watchdogThread;
    DWORD m_checkInterval;

    // Process info
    DWORD m_processId;
    HANDLE m_processHandle;

    // Anti-tampering
    std::atomic<bool> m_integrityCheckEnabled{true};
    void* m_codeBaseAddress;
    size_t m_codeSize;
    uint32_t m_originalCodeCRC;

    // Callbacks
    ThreatCallback m_threatCallback;
    ThreatCallback m_onSuspendAttempt;
    ThreatCallback m_onTerminateAttempt;

    // Sync
    std::mutex m_mutex;
    std::string m_lastError;

    // Internal methods
    static DWORD WINAPI WatchdogThreadProc(LPVOID param);
    void WatchdogLoop();

    // Thread protection
    bool IsThreadSuspended(HANDLE hThread);
    bool ResumeProtectedThread(ThreadInfo& thread);
    void CheckAndRecoverThreads();

    // Handle protection
    bool ProtectHandle(HANDLE handle);
    bool HideFromHandleList();

    // Process protection helpers
    bool SetCriticalProcess(bool critical);
    bool SetProcessDEP();
    bool SetHandleProtection();

    // Detection helpers
    std::vector<DWORD> GetProcessesWithOurHandle();
    bool IsDebugToolProcess(DWORD pid);
    std::wstring GetProcessName(DWORD pid);

    // Integrity
    uint32_t CalculateCodeCRC();
    bool VerifyCodeIntegrity();

public:
    SelfProtection();
    ~SelfProtection();

    // Initialization
    bool Initialize();
    void Shutdown();

    // Thread protection
    bool RegisterThread(DWORD threadId, bool critical = true);
    bool RegisterCurrentThread(bool critical = true);
    bool UnregisterThread(DWORD threadId);
    void ProtectAllThreads();

    // Process protection
    bool EnableCriticalProcess();          // Makes process critical (BSOD if killed)
    bool DisableCriticalProcess();
    bool ProtectProcessMemory();           // Prevent memory access
    bool HideThreadsFromDebugger();        // NtSetInformationThread

    // Watchdog
    bool StartWatchdog(DWORD intervalMs = 100);
    void StopWatchdog();
    bool IsWatchdogRunning() const { return m_monitoring; }

    // Anti-handle detection
    bool DetectHandleOpens();              // Check for processes opening our handle
    bool CloseExternalHandles();           // Close handles from other processes

    // Anti-suspension
    bool IsAnyThreadSuspended();
    int RecoverSuspendedThreads();
    void SetAutoRecovery(bool enabled);

    // Code integrity
    bool EnableIntegrityChecks();
    bool DisableIntegrityChecks();
    bool IsCodeModified();

    // Callbacks
    void SetThreatCallback(ThreatCallback callback) { m_threatCallback = callback; }
    void SetSuspendAttemptCallback(ThreatCallback callback) { m_onSuspendAttempt = callback; }
    void SetTerminateAttemptCallback(ThreatCallback callback) { m_onTerminateAttempt = callback; }

    // Status
    int GetProtectedThreadCount() const { return static_cast<int>(m_protectedThreads.size()); }
    const std::vector<ThreadInfo>& GetProtectedThreads() const { return m_protectedThreads; }
    const std::string& GetLastError() const { return m_lastError; }
};

} // namespace AntiCheat

#endif // AC_SELF_PROTECTION_H
