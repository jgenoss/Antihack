/**
 * AntiCheatCore - Process Monitor Module
 * Detects DLL injection, suspicious threads, and process tampering
 */

#pragma once

#ifndef AC_PROCESS_MONITOR_H
#define AC_PROCESS_MONITOR_H

#include "common.h"
#include <set>

namespace AntiCheat {

class ProcessMonitor {
public:
    // Module information
    struct ModuleInfo {
        std::wstring name;
        std::wstring path;
        void* baseAddress;
        size_t size;
        uint32_t checksum;
        bool isSigned;
        bool isTrusted;
        FILETIME loadTime;
    };

    // Thread information
    struct ThreadInfo {
        DWORD threadId;
        void* startAddress;
        void* stackBase;
        DWORD creationFlags;
        std::wstring ownerModule;
        bool isSuspicious;
        std::string suspicionReason;
    };

    // Injection detection result
    struct InjectionInfo {
        enum class Type {
            None,
            DLLInjection,
            RemoteThread,
            APCInjection,
            ManualMapping,
            ProcessHollowing,
            CodeCave
        };

        Type type;
        std::wstring moduleName;
        void* address;
        DWORD threadId;
        std::string details;
        Severity severity;
    };

    // Callback types
    using ModuleCallback = std::function<void(const ModuleInfo&, bool isLoading)>;
    using ThreadCallback = std::function<void(const ThreadInfo&)>;
    using InjectionCallback = std::function<void(const InjectionInfo&)>;

private:
    // Known modules at startup
    std::map<std::wstring, ModuleInfo> m_baselineModules;
    std::set<std::wstring> m_trustedModules;
    std::set<std::wstring> m_suspiciousModuleNames;

    // Thread tracking
    std::map<DWORD, ThreadInfo> m_knownThreads;
    std::set<DWORD> m_baselineThreads;

    // Monitoring state
    std::atomic<bool> m_monitoring{false};
    HANDLE m_monitorThread;
    DWORD m_monitorInterval;

    // Callbacks
    ModuleCallback m_moduleCallback;
    ThreadCallback m_threadCallback;
    InjectionCallback m_injectionCallback;
    DetectionCallback m_detectionCallback;

    // Synchronization
    std::mutex m_mutex;
    std::string m_lastError;

    // Hooks for real-time detection (optional)
    void* m_originalLoadLibrary;
    void* m_originalCreateThread;
    void* m_originalNtCreateThreadEx;
    bool m_hooksInstalled;

    // Internal methods
    static DWORD WINAPI MonitorThreadProc(LPVOID param);
    void MonitorLoop();

    // Detection methods
    bool CheckNewModules();
    bool CheckNewThreads();
    bool CheckMemoryRegions();
    bool CheckThreadStartAddresses();

    // Analysis
    bool IsModuleSuspicious(const ModuleInfo& module);
    bool IsThreadSuspicious(const ThreadInfo& thread);
    bool IsAddressInModule(void* address, std::wstring& moduleName);
    bool IsAddressExecutable(void* address);

    // Module verification
    bool VerifyModuleSignature(const std::wstring& path);
    uint32_t CalculateModuleChecksum(HMODULE module);

public:
    ProcessMonitor();
    ~ProcessMonitor();

    // Initialization
    bool Initialize();
    void Shutdown();

    // Baseline capture
    bool CaptureBaseline();
    bool AddTrustedModule(const std::wstring& moduleName);
    bool AddTrustedModules(const std::vector<std::wstring>& modules);
    void ClearTrustedModules();

    // Suspicious patterns
    void AddSuspiciousModuleName(const std::wstring& pattern);
    void ClearSuspiciousPatterns();

    // Monitoring
    bool StartMonitoring(DWORD intervalMs = 1000);
    void StopMonitoring();
    bool IsMonitoring() const { return m_monitoring; }

    // Manual scanning
    std::vector<ModuleInfo> GetLoadedModules();
    std::vector<ThreadInfo> GetThreads();
    std::vector<ModuleInfo> GetNewModules();
    std::vector<ThreadInfo> GetNewThreads();

    // Injection detection
    InjectionInfo CheckForInjection();
    bool DetectRemoteThreads();
    bool DetectManualMapping();
    bool DetectCodeCaves();
    bool DetectHollowing();

    // Real-time hooks (advanced)
    bool InstallLoadLibraryHook();
    bool InstallThreadCreationHook();
    void RemoveHooks();

    // Module analysis
    ModuleInfo GetModuleInfo(HMODULE module);
    ModuleInfo GetModuleInfo(const std::wstring& name);
    bool IsModuleLoaded(const std::wstring& name);
    bool IsModuleTrusted(const std::wstring& name);

    // Thread analysis
    ThreadInfo GetThreadInfo(DWORD threadId);
    bool IsThreadFromTrustedModule(DWORD threadId);
    void* GetThreadStartAddress(HANDLE thread);

    // Callbacks
    void SetModuleCallback(ModuleCallback callback) { m_moduleCallback = callback; }
    void SetThreadCallback(ThreadCallback callback) { m_threadCallback = callback; }
    void SetInjectionCallback(InjectionCallback callback) { m_injectionCallback = callback; }
    void SetDetectionCallback(DetectionCallback callback) { m_detectionCallback = callback; }

    // Status
    int GetBaselineModuleCount() const { return static_cast<int>(m_baselineModules.size()); }
    int GetBaselineThreadCount() const { return static_cast<int>(m_baselineThreads.size()); }
    const std::string& GetLastError() const { return m_lastError; }
};

} // namespace AntiCheat

#endif // AC_PROCESS_MONITOR_H
