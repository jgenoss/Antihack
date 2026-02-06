/**
 * AntiCheatCore - Refactored Process Monitor (V2)
 *
 * Detects DLL injection, suspicious threads, and process tampering.
 *
 * Improvements over V1 (ProcessMonitor.h):
 *   - Properly inherits from IMonitorModule (Template Method pattern)
 *   - Uses HandleGuard RAII for all snapshot/thread handles
 *   - Implements IConfigurable for runtime reconfiguration
 *   - Uses unified ModuleTypes instead of local struct definitions
 *   - Complete DetectCodeCaves() implementation (was dead code in V1)
 *   - Const-correctness throughout
 *   - No raw HANDLE management
 *
 * Follows: SOLID, RAII, Template Method, Liskov Substitution
 */

#pragma once

#ifndef AC_PROCESS_MONITOR_V2_HPP
#define AC_PROCESS_MONITOR_V2_HPP

#include "IMonitorModule.h"
#include "IConfigurable.hpp"
#include "HandleGuard.hpp"
#include "ModuleTypes.hpp"
#include <set>
#include <map>

namespace AntiCheat {

/**
 * Monitors the current process for DLL injection, suspicious threads,
 * and other process-level attacks.
 *
 * Inherits from IMonitorModule to use the shared thread management
 * infrastructure with proper start/stop synchronization.
 */
class ProcessMonitorV2 final : public IMonitorModule, public IConfigurable {
public:
    // Callback types using unified types from ModuleTypes.hpp
    using ModuleCallback    = std::function<void(const LoadedModuleInfo&, bool isLoading)>;
    using ThreadCallback    = std::function<void(const ThreadSnapshot&)>;
    using InjectionCallback = std::function<void(const InjectionResult&)>;

    ProcessMonitorV2();
    ~ProcessMonitorV2() override;

    // Non-copyable (inherited from IMonitorModule)
    ProcessMonitorV2(const ProcessMonitorV2&) = delete;
    ProcessMonitorV2& operator=(const ProcessMonitorV2&) = delete;

    // ========================================================================
    // INITIALIZATION (overrides IMonitorModule)
    // ========================================================================

    bool Initialize() override;
    void Shutdown() override;

    // ========================================================================
    // BASELINE
    // ========================================================================

    /** Captures current modules and threads as the "known good" baseline. */
    bool CaptureBaseline();

    /** Adds a module name to the trusted whitelist (case-insensitive). */
    bool AddTrustedModule(const std::wstring& moduleName);

    /** Adds multiple modules to the trusted whitelist. */
    bool AddTrustedModules(const std::vector<std::wstring>& modules);

    /** Clears the trusted module whitelist. */
    void ClearTrustedModules();

    /** Adds a keyword pattern that flags a module as suspicious. */
    void AddSuspiciousPattern(const std::wstring& pattern);

    /** Clears all suspicious patterns. */
    void ClearSuspiciousPatterns();

    // ========================================================================
    // MANUAL SCANNING
    // ========================================================================

    /** Returns all currently loaded modules in the process. */
    [[nodiscard]] std::vector<LoadedModuleInfo> GetLoadedModules() const;

    /** Returns all threads belonging to the current process. */
    [[nodiscard]] std::vector<ThreadSnapshot> GetThreads() const;

    /** Returns modules loaded since the baseline was captured. */
    [[nodiscard]] std::vector<LoadedModuleInfo> GetNewModules() const;

    /** Returns threads created since the baseline was captured. */
    [[nodiscard]] std::vector<ThreadSnapshot> GetNewThreads() const;

    // ========================================================================
    // INJECTION DETECTION
    // ========================================================================

    /** Runs all injection detection heuristics and returns the result. */
    [[nodiscard]] InjectionResult CheckForInjection() const;

    /** Checks for threads originating outside any loaded module. */
    [[nodiscard]] bool DetectRemoteThreads() const;

    /** Scans for executable memory regions not backed by any module. */
    [[nodiscard]] bool DetectManualMapping() const;

    /**
     * Detects code caves: executable padding regions in modules that
     * have been written to (potential shellcode injection).
     *
     * FULLY IMPLEMENTED - V1 had dead code here.
     */
    [[nodiscard]] bool DetectCodeCaves() const;

    /** Checks if the main executable has been hollowed out. */
    [[nodiscard]] bool DetectHollowing() const;

    // ========================================================================
    // MODULE ANALYSIS
    // ========================================================================

    /** Gets detailed info about a module by handle. */
    [[nodiscard]] LoadedModuleInfo GetModuleInfo(HMODULE module) const;

    /** Gets detailed info about a module by name. */
    [[nodiscard]] LoadedModuleInfo GetModuleInfo(const std::wstring& name) const;

    /** Checks if a module is currently loaded. */
    [[nodiscard]] bool IsModuleLoaded(const std::wstring& name) const;

    /** Checks if a module is in the trusted whitelist. */
    [[nodiscard]] bool IsModuleTrusted(const std::wstring& name) const;

    // ========================================================================
    // THREAD ANALYSIS
    // ========================================================================

    /** Gets info about a specific thread. */
    [[nodiscard]] ThreadSnapshot GetThreadInfo(DWORD threadId) const;

    /** Checks if a thread started from a trusted module. */
    [[nodiscard]] bool IsThreadFromTrustedModule(DWORD threadId) const;

    /** Retrieves the start address of a thread (via NtQueryInformationThread). */
    [[nodiscard]] static void* GetThreadStartAddress(HANDLE threadHandle);

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void SetModuleCallback(ModuleCallback callback);
    void SetThreadCallback(ThreadCallback callback);
    void SetInjectionCallback(InjectionCallback callback);

    // ========================================================================
    // STATUS
    // ========================================================================

    [[nodiscard]] int GetBaselineModuleCount() const;
    [[nodiscard]] int GetBaselineThreadCount() const;

    // ========================================================================
    // IConfigurable
    // ========================================================================

    bool ApplyConfig(const ConfigMap& config) override;
    void ExportConfig(ConfigMap& outConfig) const override;
    [[nodiscard]] std::string GetConfigSection() const override { return "ProcessMonitor"; }

protected:
    // ========================================================================
    // IMonitorModule overrides (Template Method)
    // ========================================================================

    /** Called every monitoring cycle by IMonitorModule's thread. */
    void DoMonitorCycle() override;

    /** Called when the monitoring thread starts. */
    void OnMonitorStart() override;

    /** Called when the monitoring thread is about to stop. */
    void OnMonitorStop() override;

private:
    // ========================================================================
    // BASELINE DATA
    // ========================================================================

    std::map<std::wstring, LoadedModuleInfo> m_baselineModules;
    std::set<std::wstring>                   m_trustedModules;
    std::set<std::wstring>                   m_suspiciousPatterns;

    // Thread tracking
    std::map<DWORD, ThreadSnapshot>          m_knownThreads;
    std::set<DWORD>                          m_baselineThreads;

    // ========================================================================
    // CALLBACKS (protected by IMonitorModule::m_callbackMutex)
    // ========================================================================

    ModuleCallback    m_moduleCallback;
    ThreadCallback    m_threadCallback;
    InjectionCallback m_injectionCallback;

    // ========================================================================
    // NTDLL FUNCTION POINTER
    // ========================================================================

    using NtQueryInfoThreadFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static NtQueryInfoThreadFn s_ntQueryInformationThread;
    static bool                s_ntdllResolved;

    /** Lazily resolves NtQueryInformationThread from ntdll.dll. */
    static void ResolveNtdllFunctions();

    // ========================================================================
    // DETECTION HELPERS
    // ========================================================================

    /** Checks for new modules loaded since baseline. */
    bool CheckNewModules();

    /** Checks for new threads created since baseline. */
    bool CheckNewThreads();

    /** Verifies that all thread start addresses fall within known modules. */
    bool CheckThreadStartAddresses();

    /** Heuristic: is this module suspicious based on name/path/signature? */
    [[nodiscard]] bool IsModuleSuspicious(const LoadedModuleInfo& module) const;

    /** Heuristic: is this thread suspicious based on start address/owner? */
    [[nodiscard]] bool IsThreadSuspicious(const ThreadSnapshot& thread) const;

    /** Looks up which module contains a given memory address. */
    [[nodiscard]] bool IsAddressInModule(void* address, std::wstring& outModuleName) const;

    /** Checks if a memory address has execute permissions. */
    [[nodiscard]] static bool IsAddressExecutable(void* address);

    // ========================================================================
    // MODULE VERIFICATION
    // ========================================================================

    /** Verifies the digital signature of a PE file. */
    [[nodiscard]] static bool VerifyModuleSignature(const std::wstring& path);

    /** Calculates CRC32 of a module's image in memory. */
    [[nodiscard]] static uint32_t CalculateModuleChecksum(HMODULE module);

    /**
     * Calculates the Shannon entropy of a byte sequence.
     * Used by DetectCodeCaves to distinguish code from padding.
     *
     * @param data   Pointer to the byte buffer.
     * @param size   Number of bytes.
     * @return Entropy value (0.0 = all same bytes, 8.0 = maximum entropy).
     */
    [[nodiscard]] static double CalculateEntropy(const uint8_t* data, size_t size);
};

} // namespace AntiCheat

#endif // AC_PROCESS_MONITOR_V2_HPP
