/**
 * AntiCheatCore - Process Monitor Implementation
 * Detects DLL injection, suspicious threads, and process tampering
 */

#include "stdafx.h"
#include "../include/internal/ProcessMonitor.h"
#include <Softpub.h>
#include <WinTrust.h>

#pragma comment(lib, "Wintrust.lib")

namespace AntiCheat {

// NtQueryInformationThread for getting thread start address
typedef NTSTATUS(NTAPI* pNtQueryInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

static pNtQueryInformationThread NtQueryInformationThread = nullptr;

// Thread information class for start address
#define ThreadQuerySetWin32StartAddress 9

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

ProcessMonitor::ProcessMonitor()
    : m_monitorThread(nullptr),
      m_monitorInterval(1000),
      m_originalLoadLibrary(nullptr),
      m_originalCreateThread(nullptr),
      m_originalNtCreateThreadEx(nullptr),
      m_hooksInstalled(false) {

    // Get NtQueryInformationThread
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        NtQueryInformationThread = reinterpret_cast<pNtQueryInformationThread>(
            GetProcAddress(ntdll, "NtQueryInformationThread"));
    }
}

ProcessMonitor::~ProcessMonitor() {
    Shutdown();
}

// ============================================================================
// INITIALIZATION
// ============================================================================

bool ProcessMonitor::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Add common suspicious module patterns
    m_suspiciousModuleNames.insert(L"inject");
    m_suspiciousModuleNames.insert(L"hook");
    m_suspiciousModuleNames.insert(L"cheat");
    m_suspiciousModuleNames.insert(L"hack");
    m_suspiciousModuleNames.insert(L"trainer");
    m_suspiciousModuleNames.insert(L"aimbot");
    m_suspiciousModuleNames.insert(L"wallhack");
    m_suspiciousModuleNames.insert(L"esp");

    // Add system DLLs as trusted
    m_trustedModules.insert(L"ntdll.dll");
    m_trustedModules.insert(L"kernel32.dll");
    m_trustedModules.insert(L"kernelbase.dll");
    m_trustedModules.insert(L"user32.dll");
    m_trustedModules.insert(L"gdi32.dll");
    m_trustedModules.insert(L"advapi32.dll");
    m_trustedModules.insert(L"shell32.dll");
    m_trustedModules.insert(L"ole32.dll");
    m_trustedModules.insert(L"oleaut32.dll");
    m_trustedModules.insert(L"msvcrt.dll");
    m_trustedModules.insert(L"ucrtbase.dll");
    m_trustedModules.insert(L"vcruntime140.dll");
    m_trustedModules.insert(L"msvcp140.dll");

    return true;
}

void ProcessMonitor::Shutdown() {
    StopMonitoring();
    RemoveHooks();

    std::lock_guard<std::mutex> lock(m_mutex);
    m_baselineModules.clear();
    m_baselineThreads.clear();
    m_knownThreads.clear();
}

// ============================================================================
// BASELINE CAPTURE
// ============================================================================

bool ProcessMonitor::CaptureBaseline() {
    std::lock_guard<std::mutex> lock(m_mutex);

    m_baselineModules.clear();
    m_baselineThreads.clear();

    // Capture modules
    auto modules = GetLoadedModules();
    for (const auto& mod : modules) {
        std::wstring lowerName = mod.name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
        m_baselineModules[lowerName] = mod;
    }

    // Capture threads
    auto threads = GetThreads();
    for (const auto& thread : threads) {
        m_baselineThreads.insert(thread.threadId);
        m_knownThreads[thread.threadId] = thread;
    }

    return true;
}

bool ProcessMonitor::AddTrustedModule(const std::wstring& moduleName) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::wstring lower = moduleName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    m_trustedModules.insert(lower);
    return true;
}

bool ProcessMonitor::AddTrustedModules(const std::vector<std::wstring>& modules) {
    for (const auto& mod : modules) {
        AddTrustedModule(mod);
    }
    return true;
}

void ProcessMonitor::ClearTrustedModules() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_trustedModules.clear();
}

void ProcessMonitor::AddSuspiciousModuleName(const std::wstring& pattern) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::wstring lower = pattern;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    m_suspiciousModuleNames.insert(lower);
}

void ProcessMonitor::ClearSuspiciousPatterns() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_suspiciousModuleNames.clear();
}

// ============================================================================
// MONITORING
// ============================================================================

bool ProcessMonitor::StartMonitoring(DWORD intervalMs) {
    if (m_monitoring) return true;

    m_monitorInterval = intervalMs;
    m_monitoring = true;

    m_monitorThread = CreateThread(nullptr, 0, MonitorThreadProc, this, 0, nullptr);
    if (!m_monitorThread) {
        m_monitoring = false;
        m_lastError = "Failed to create monitor thread";
        return false;
    }

    return true;
}

void ProcessMonitor::StopMonitoring() {
    if (!m_monitoring) return;

    m_monitoring = false;

    if (m_monitorThread) {
        WaitForSingleObject(m_monitorThread, 5000);
        CloseHandle(m_monitorThread);
        m_monitorThread = nullptr;
    }
}

DWORD WINAPI ProcessMonitor::MonitorThreadProc(LPVOID param) {
    ProcessMonitor* self = static_cast<ProcessMonitor*>(param);
    self->MonitorLoop();
    return 0;
}

void ProcessMonitor::MonitorLoop() {
    while (m_monitoring) {
        // Check for new modules
        CheckNewModules();

        // Check for new threads
        CheckNewThreads();

        // Check thread start addresses
        CheckThreadStartAddresses();

        // Check for injection patterns
        auto injection = CheckForInjection();
        if (injection.type != InjectionInfo::Type::None) {
            if (m_injectionCallback) {
                m_injectionCallback(injection);
            }
            if (m_detectionCallback) {
                DetectionEvent event;
                event.type = DetectionType::SuspiciousModule;
                event.severity = injection.severity;
                event.description = injection.details;
                event.moduleName = WStringToString(injection.moduleName);
                event.address = injection.address;
                event.timestamp = GetTickCount();
                m_detectionCallback(event);
            }
        }

        Sleep(m_monitorInterval);
    }
}

// ============================================================================
// MODULE SCANNING
// ============================================================================

std::vector<ProcessMonitor::ModuleInfo> ProcessMonitor::GetLoadedModules() {
    std::vector<ModuleInfo> modules;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return modules;

    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(snapshot, &me32)) {
        do {
            ModuleInfo info;
            info.name = me32.szModule;
            info.path = me32.szExePath;
            info.baseAddress = me32.modBaseAddr;
            info.size = me32.modBaseSize;
            info.checksum = CalculateModuleChecksum(me32.hModule);
            info.isSigned = VerifyModuleSignature(me32.szExePath);
            info.isTrusted = IsModuleTrusted(me32.szModule);
            GetSystemTimeAsFileTime(&info.loadTime);

            modules.push_back(info);
        } while (Module32NextW(snapshot, &me32));
    }

    CloseHandle(snapshot);
    return modules;
}

std::vector<ProcessMonitor::ModuleInfo> ProcessMonitor::GetNewModules() {
    std::vector<ModuleInfo> newModules;
    auto currentModules = GetLoadedModules();

    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& mod : currentModules) {
        std::wstring lowerName = mod.name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

        if (m_baselineModules.find(lowerName) == m_baselineModules.end()) {
            newModules.push_back(mod);
        }
    }

    return newModules;
}

bool ProcessMonitor::CheckNewModules() {
    auto newModules = GetNewModules();

    for (const auto& mod : newModules) {
        // Add to baseline
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::wstring lowerName = mod.name;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
            m_baselineModules[lowerName] = mod;
        }

        // Check if suspicious
        if (IsModuleSuspicious(mod)) {
            if (m_moduleCallback) {
                m_moduleCallback(mod, true);
            }
            if (m_detectionCallback) {
                DetectionEvent event;
                event.type = DetectionType::SuspiciousModule;
                event.severity = Severity::Warning;
                event.description = "Suspicious module loaded: " + WStringToString(mod.name);
                event.moduleName = WStringToString(mod.name);
                event.address = mod.baseAddress;
                event.timestamp = GetTickCount();
                m_detectionCallback(event);
            }
            return true;
        }
    }

    return false;
}

// ============================================================================
// THREAD SCANNING
// ============================================================================

std::vector<ProcessMonitor::ThreadInfo> ProcessMonitor::GetThreads() {
    std::vector<ThreadInfo> threads;

    DWORD processId = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return threads;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(snapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                ThreadInfo info;
                info.threadId = te32.th32ThreadID;
                info.creationFlags = 0;
                info.isSuspicious = false;

                // Get thread handle to query start address
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                if (hThread) {
                    info.startAddress = GetThreadStartAddress(hThread);

                    // Find owning module
                    IsAddressInModule(info.startAddress, info.ownerModule);

                    CloseHandle(hThread);
                }

                // Check if suspicious
                info.isSuspicious = IsThreadSuspicious(info);

                threads.push_back(info);
            }
        } while (Thread32Next(snapshot, &te32));
    }

    CloseHandle(snapshot);
    return threads;
}

std::vector<ProcessMonitor::ThreadInfo> ProcessMonitor::GetNewThreads() {
    std::vector<ThreadInfo> newThreads;
    auto currentThreads = GetThreads();

    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& thread : currentThreads) {
        if (m_baselineThreads.find(thread.threadId) == m_baselineThreads.end()) {
            newThreads.push_back(thread);
        }
    }

    return newThreads;
}

bool ProcessMonitor::CheckNewThreads() {
    auto newThreads = GetNewThreads();

    for (const auto& thread : newThreads) {
        // Add to baseline
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_baselineThreads.insert(thread.threadId);
            m_knownThreads[thread.threadId] = thread;
        }

        // Notify
        if (m_threadCallback) {
            m_threadCallback(thread);
        }

        // Check if suspicious
        if (thread.isSuspicious) {
            if (m_detectionCallback) {
                DetectionEvent event;
                event.type = DetectionType::SuspiciousThread;
                event.severity = Severity::Warning;
                event.description = "Suspicious thread created: " + thread.suspicionReason;
                event.address = thread.startAddress;
                event.timestamp = GetTickCount();
                m_detectionCallback(event);
            }
            return true;
        }
    }

    return false;
}

bool ProcessMonitor::CheckThreadStartAddresses() {
    auto threads = GetThreads();

    for (const auto& thread : threads) {
        if (!thread.startAddress) continue;

        std::wstring moduleName;
        if (!IsAddressInModule(thread.startAddress, moduleName)) {
            // Thread start address not in any module - possible manual mapping
            if (m_detectionCallback) {
                DetectionEvent event;
                event.type = DetectionType::SuspiciousThread;
                event.severity = Severity::Critical;
                event.description = "Thread with start address outside any module";
                event.address = thread.startAddress;
                event.timestamp = GetTickCount();
                m_detectionCallback(event);
            }
            return true;
        }
    }

    return false;
}

void* ProcessMonitor::GetThreadStartAddress(HANDLE thread) {
    if (!NtQueryInformationThread) return nullptr;

    void* startAddress = nullptr;
    NtQueryInformationThread(thread, ThreadQuerySetWin32StartAddress,
                             &startAddress, sizeof(startAddress), nullptr);
    return startAddress;
}

// ============================================================================
// INJECTION DETECTION
// ============================================================================

ProcessMonitor::InjectionInfo ProcessMonitor::CheckForInjection() {
    InjectionInfo info;
    info.type = InjectionInfo::Type::None;

    // Check for new unsigned/untrusted modules
    auto newModules = GetNewModules();
    for (const auto& mod : newModules) {
        if (!mod.isSigned && !mod.isTrusted) {
            info.type = InjectionInfo::Type::DLLInjection;
            info.moduleName = mod.name;
            info.address = mod.baseAddress;
            info.severity = Severity::Critical;
            info.details = "Unsigned DLL loaded: " + WStringToString(mod.name);
            return info;
        }

        if (IsModuleSuspicious(mod)) {
            info.type = InjectionInfo::Type::DLLInjection;
            info.moduleName = mod.name;
            info.address = mod.baseAddress;
            info.severity = Severity::Critical;
            info.details = "Suspicious DLL loaded: " + WStringToString(mod.name);
            return info;
        }
    }

    // Check for remote threads
    if (DetectRemoteThreads()) {
        info.type = InjectionInfo::Type::RemoteThread;
        info.severity = Severity::Critical;
        info.details = "Remote thread creation detected";
        return info;
    }

    // Check for manual mapping
    if (DetectManualMapping()) {
        info.type = InjectionInfo::Type::ManualMapping;
        info.severity = Severity::Fatal;
        info.details = "Manually mapped code detected";
        return info;
    }

    // Check for code caves
    if (DetectCodeCaves()) {
        info.type = InjectionInfo::Type::CodeCave;
        info.severity = Severity::Critical;
        info.details = "Code cave detected in module";
        return info;
    }

    return info;
}

bool ProcessMonitor::DetectRemoteThreads() {
    auto threads = GetThreads();

    for (const auto& thread : threads) {
        // Thread with no associated module could be remote
        if (thread.ownerModule.empty() && thread.startAddress) {
            // Verify the address is not in any known module
            std::wstring moduleName;
            if (!IsAddressInModule(thread.startAddress, moduleName)) {
                return true;
            }
        }
    }

    return false;
}

bool ProcessMonitor::DetectManualMapping() {
    // Scan memory for executable regions not backed by modules
    MEMORY_BASIC_INFORMATION mbi;
    void* address = nullptr;

    while (VirtualQuery(address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {

            // Check if this region is backed by a module
            std::wstring moduleName;
            if (!IsAddressInModule(mbi.BaseAddress, moduleName)) {
                // Executable memory not in any module
                // Check if it looks like code (has PE header or code patterns)
                uint8_t* data = static_cast<uint8_t*>(mbi.BaseAddress);

                // Check for PE header
                if (mbi.RegionSize >= 2 && data[0] == 'M' && data[1] == 'Z') {
                    return true; // PE file manually mapped
                }

                // Check for common code patterns (function prologue)
                if (mbi.RegionSize >= 3) {
                    // push ebp; mov ebp, esp
                    if (data[0] == 0x55 && data[1] == 0x8B && data[2] == 0xEC) {
                        return true;
                    }
                    // sub esp, X (common in functions)
                    if (data[0] == 0x83 && data[1] == 0xEC) {
                        return true;
                    }
                }
            }
        }

        address = reinterpret_cast<void*>(
            reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize);
    }

    return false;
}

bool ProcessMonitor::DetectCodeCaves() {
    // Check modules for suspicious executable sections with low entropy
    // (code caves are often filled with NOPs or zeros)
    auto modules = GetLoadedModules();

    for (const auto& mod : modules) {
        if (mod.isTrusted) continue;

        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(mod.baseAddress);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) continue;

        PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<uint8_t*>(mod.baseAddress) + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) continue;

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
            if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                // Check for padding areas in executable sections
                uint8_t* sectionData = reinterpret_cast<uint8_t*>(mod.baseAddress) +
                                       section->VirtualAddress;
                size_t sectionSize = section->Misc.VirtualSize;

                // Look for large runs of NOPs or zeros that have been modified
                int nopCount = 0;
                for (size_t j = 0; j < sectionSize && j < 0x10000; j++) {
                    if (sectionData[j] == 0x90 || sectionData[j] == 0x00) {
                        nopCount++;
                    } else {
                        if (nopCount > 100) {
                            // Large padding area followed by code - suspicious
                            // But this could be normal, so we need more heuristics
                        }
                        nopCount = 0;
                    }
                }
            }
        }
    }

    return false;
}

bool ProcessMonitor::DetectHollowing() {
    // Check if main module has been hollowed
    HMODULE mainModule = GetModuleHandleW(nullptr);
    if (!mainModule) return false;

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(mainModule);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return true; // DOS header corrupted
    }

    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(mainModule) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return true; // NT header corrupted
    }

    // Verify entry point is within the module
    void* entryPoint = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(mainModule) + ntHeaders->OptionalHeader.AddressOfEntryPoint);

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(entryPoint, &mbi, sizeof(mbi))) {
        if (mbi.AllocationBase != mainModule) {
            return true; // Entry point not in main module
        }
    }

    return false;
}

// ============================================================================
// ANALYSIS HELPERS
// ============================================================================

bool ProcessMonitor::IsModuleSuspicious(const ModuleInfo& module) {
    std::wstring lowerName = module.name;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

    // Check against suspicious patterns
    for (const auto& pattern : m_suspiciousModuleNames) {
        if (lowerName.find(pattern) != std::wstring::npos) {
            return true;
        }
    }

    // Unsigned + not trusted = suspicious
    if (!module.isSigned && !module.isTrusted) {
        // Check if loaded from temp directory
        std::wstring lowerPath = module.path;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

        if (lowerPath.find(L"\\temp\\") != std::wstring::npos ||
            lowerPath.find(L"\\appdata\\") != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

bool ProcessMonitor::IsThreadSuspicious(const ThreadInfo& thread) {
    // Thread with no owner module
    if (thread.ownerModule.empty() && thread.startAddress) {
        return true;
    }

    // Thread from suspicious module
    if (!thread.ownerModule.empty()) {
        std::wstring lower = thread.ownerModule;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        for (const auto& pattern : m_suspiciousModuleNames) {
            if (lower.find(pattern) != std::wstring::npos) {
                return true;
            }
        }
    }

    return false;
}

bool ProcessMonitor::IsAddressInModule(void* address, std::wstring& moduleName) {
    moduleName.clear();

    HMODULE module = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(address), &module)) {
        wchar_t path[MAX_PATH];
        if (GetModuleFileNameW(module, path, MAX_PATH)) {
            moduleName = path;
            return true;
        }
    }

    return false;
}

bool ProcessMonitor::IsAddressExecutable(void* address) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi))) {
        return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    }
    return false;
}

bool ProcessMonitor::IsModuleLoaded(const std::wstring& name) {
    return GetModuleHandleW(name.c_str()) != nullptr;
}

bool ProcessMonitor::IsModuleTrusted(const std::wstring& name) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::wstring lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    return m_trustedModules.find(lower) != m_trustedModules.end();
}

bool ProcessMonitor::IsThreadFromTrustedModule(DWORD threadId) {
    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!hThread) return false;

    void* startAddr = GetThreadStartAddress(hThread);
    CloseHandle(hThread);

    if (!startAddr) return false;

    std::wstring moduleName;
    if (IsAddressInModule(startAddr, moduleName)) {
        // Extract just filename
        size_t pos = moduleName.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            moduleName = moduleName.substr(pos + 1);
        }
        return IsModuleTrusted(moduleName);
    }

    return false;
}

// ============================================================================
// MODULE VERIFICATION
// ============================================================================

bool ProcessMonitor::VerifyModuleSignature(const std::wstring& path) {
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = path.c_str();

    GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA winTrustData = {};
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG status = WinVerifyTrust(NULL, &guidAction, &winTrustData);

    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &guidAction, &winTrustData);

    return status == ERROR_SUCCESS;
}

uint32_t ProcessMonitor::CalculateModuleChecksum(HMODULE module) {
    if (!module) return 0;

    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), module, &modInfo, sizeof(modInfo))) {
        return 0;
    }

    return CalculateCRC32(static_cast<uint8_t*>(modInfo.lpBaseOfDll), modInfo.SizeOfImage);
}

ProcessMonitor::ModuleInfo ProcessMonitor::GetModuleInfo(HMODULE module) {
    ModuleInfo info = {};

    if (!module) return info;

    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(module, path, MAX_PATH)) {
        info.path = path;

        // Extract filename
        std::wstring pathStr = path;
        size_t pos = pathStr.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            info.name = pathStr.substr(pos + 1);
        } else {
            info.name = pathStr;
        }
    }

    MODULEINFO modInfo;
    if (GetModuleInformation(GetCurrentProcess(), module, &modInfo, sizeof(modInfo))) {
        info.baseAddress = modInfo.lpBaseOfDll;
        info.size = modInfo.SizeOfImage;
    }

    info.checksum = CalculateModuleChecksum(module);
    info.isSigned = VerifyModuleSignature(info.path);
    info.isTrusted = IsModuleTrusted(info.name);

    return info;
}

ProcessMonitor::ModuleInfo ProcessMonitor::GetModuleInfo(const std::wstring& name) {
    HMODULE module = GetModuleHandleW(name.c_str());
    return GetModuleInfo(module);
}

ProcessMonitor::ThreadInfo ProcessMonitor::GetThreadInfo(DWORD threadId) {
    ThreadInfo info = {};
    info.threadId = threadId;

    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (hThread) {
        info.startAddress = GetThreadStartAddress(hThread);
        IsAddressInModule(info.startAddress, info.ownerModule);
        info.isSuspicious = IsThreadSuspicious(info);
        CloseHandle(hThread);
    }

    return info;
}

// ============================================================================
// HOOKS (PLACEHOLDER - Would need Detours or similar)
// ============================================================================

bool ProcessMonitor::InstallLoadLibraryHook() {
    // This would require Microsoft Detours or similar hooking library
    // Placeholder for now
    m_lastError = "Hook installation requires Detours library";
    return false;
}

bool ProcessMonitor::InstallThreadCreationHook() {
    // This would require Microsoft Detours or similar hooking library
    m_lastError = "Hook installation requires Detours library";
    return false;
}

void ProcessMonitor::RemoveHooks() {
    if (!m_hooksInstalled) return;

    // Would remove hooks here if installed
    m_hooksInstalled = false;
}

} // namespace AntiCheat
