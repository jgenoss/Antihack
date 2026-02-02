/**
 * AntiCheatCore - Hook Detection Module
 * Detects inline hooks, IAT hooks, and API modifications
 */

#pragma once

#ifndef AC_HOOK_DETECTOR_H
#define AC_HOOK_DETECTOR_H

#include "common.h"
#include <Psapi.h>
#include <TlHelp32.h>

#pragma comment(lib, "psapi.lib")

namespace AntiCheat {

class HookDetector {
public:
    enum class HookType {
        None,
        InlineHook,      // JMP/CALL at function start
        IATHook,         // Import Address Table modification
        EATHook,         // Export Address Table modification
        VTableHook,      // Virtual function table modification
        HotPatch,        // Windows hot-patching hooks
        Trampoline       // Detours-style trampoline
    };

    struct HookInfo {
        HookType type;
        std::string moduleName;
        std::string functionName;
        void* originalAddress;
        void* hookedAddress;
        ByteVector originalBytes;
        ByteVector currentBytes;
        std::string targetModule;  // Where the hook redirects to
    };

    struct ModuleInfo {
        std::wstring name;
        std::wstring path;
        void* baseAddress;
        size_t size;
        uint32_t checksum;
        bool isSystem;
        bool isSigned;
    };

    struct ScanResult {
        std::vector<HookInfo> detectedHooks;
        std::vector<ModuleInfo> suspiciousModules;
        bool hasCriticalHooks;
        int totalHooksFound;
    };

private:
    std::vector<std::string> m_criticalAPIs;
    std::vector<std::wstring> m_trustedModules;
    std::map<std::string, ByteVector> m_originalPrologues;
    DetectionCallback m_callback;
    std::mutex m_mutex;
    std::string m_lastError;

    // Detection methods
    HookInfo CheckInlineHook(HMODULE module, const char* functionName);
    HookInfo CheckIATHook(HMODULE targetModule, HMODULE sourceModule, const char* functionName);
    bool IsHookInstruction(const uint8_t* bytes);
    bool IsJmpInstruction(const uint8_t* bytes);
    bool IsCallInstruction(const uint8_t* bytes);

    // Module analysis
    bool IsSystemModule(const std::wstring& path);
    bool IsSignedModule(const std::wstring& path);
    std::wstring GetModuleFromAddress(void* address);

    // IAT walking
    bool WalkIAT(HMODULE module, std::function<bool(const char*, const char*, void**)> callback);

public:
    HookDetector();
    ~HookDetector();

    // Initialization
    bool Initialize();
    void Shutdown();
    void SetDetectionCallback(DetectionCallback callback);

    // API registration (specify which APIs to monitor)
    void AddCriticalAPI(const std::string& moduleName, const std::string& functionName);
    void AddCriticalAPIs(const std::vector<std::pair<std::string, std::string>>& apis);
    void ClearCriticalAPIs();

    // Trusted modules (hooks from these are ignored)
    void AddTrustedModule(const std::wstring& moduleName);
    void ClearTrustedModules();

    // Scanning
    ScanResult ScanAllHooks();
    ScanResult ScanModuleHooks(HMODULE module);
    ScanResult ScanCriticalAPIs();
    HookInfo CheckFunction(const char* moduleName, const char* functionName);

    // Module verification
    std::vector<ModuleInfo> GetLoadedModules();
    std::vector<ModuleInfo> GetSuspiciousModules();
    bool VerifyModuleIntegrity(HMODULE module);
    bool VerifyModuleSignature(const std::wstring& path);

    // Prologue storage (for comparison)
    bool StoreFunctionPrologue(const char* moduleName, const char* functionName);
    bool StoreCriticalPrologues();
    bool VerifyStoredPrologues();

    // Anti-debugging checks
    bool IsDebuggerPresent();
    bool IsRemoteDebuggerPresent();
    bool CheckDebugRegisters();
    bool CheckDebugFlags();

    // Getters
    const std::string& GetLastError() const { return m_lastError; }
    int GetCriticalAPICount() const { return static_cast<int>(m_criticalAPIs.size()); }
};

} // namespace AntiCheat

#endif // AC_HOOK_DETECTOR_H
