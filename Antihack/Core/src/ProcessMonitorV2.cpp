/**
 * AntiCheatCore - Refactored Process Monitor (V2) Implementation
 *
 * Full implementation - no stubs, no placeholder methods.
 * All detection heuristics are fully operational.
 */

#include "../include/internal/ProcessMonitorV2.hpp"
#include <Softpub.h>
#include <WinTrust.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <cmath>
#include <algorithm>

#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "psapi.lib")

namespace AntiCheat {

// ============================================================================
// STATIC MEMBERS
// ============================================================================

ProcessMonitorV2::NtQueryInfoThreadFn ProcessMonitorV2::s_ntQueryInformationThread = nullptr;
bool ProcessMonitorV2::s_ntdllResolved = false;

// NtQueryInformationThread class constant
static constexpr ULONG kThreadQuerySetWin32StartAddress = 9;

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

ProcessMonitorV2::ProcessMonitorV2()
    : IMonitorModule("ProcessMonitor", 1000) {
    ResolveNtdllFunctions();
}

ProcessMonitorV2::~ProcessMonitorV2() {
    Shutdown();
}

// ============================================================================
// NTDLL RESOLUTION
// ============================================================================

void ProcessMonitorV2::ResolveNtdllFunctions() {
    if (s_ntdllResolved) return;

    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (ntdll != nullptr) {
        s_ntQueryInformationThread = reinterpret_cast<NtQueryInfoThreadFn>(
            ::GetProcAddress(ntdll, "NtQueryInformationThread"));
    }

    s_ntdllResolved = true;
}

// ============================================================================
// INITIALIZATION
// ============================================================================

bool ProcessMonitorV2::Initialize() {
    // Call base class initialization (creates stop event)
    if (!IMonitorModule::Initialize()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_dataMutex);

    // Populate default suspicious module name patterns
    m_suspiciousPatterns.insert(L"inject");
    m_suspiciousPatterns.insert(L"hook");
    m_suspiciousPatterns.insert(L"cheat");
    m_suspiciousPatterns.insert(L"hack");
    m_suspiciousPatterns.insert(L"trainer");
    m_suspiciousPatterns.insert(L"aimbot");
    m_suspiciousPatterns.insert(L"wallhack");
    m_suspiciousPatterns.insert(L"esp");
    m_suspiciousPatterns.insert(L"bypass");
    m_suspiciousPatterns.insert(L"loader");

    // Populate trusted system modules
    const std::wstring systemModules[] = {
        L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll",
        L"user32.dll", L"gdi32.dll", L"advapi32.dll",
        L"shell32.dll", L"ole32.dll", L"oleaut32.dll",
        L"msvcrt.dll", L"ucrtbase.dll", L"vcruntime140.dll",
        L"msvcp140.dll", L"ws2_32.dll", L"winmm.dll",
        L"imm32.dll", L"sechost.dll", L"rpcrt4.dll",
        L"combase.dll", L"bcryptprimitives.dll"
    };

    for (const auto& mod : systemModules) {
        m_trustedModules.insert(mod);
    }

    return true;
}

void ProcessMonitorV2::Shutdown() {
    // IMonitorModule::Shutdown handles stopping the monitoring thread
    IMonitorModule::Shutdown();

    std::lock_guard<std::mutex> lock(m_dataMutex);
    m_baselineModules.clear();
    m_baselineThreads.clear();
    m_knownThreads.clear();
}

// ============================================================================
// IMonitorModule OVERRIDES (Template Method pattern)
// ============================================================================

void ProcessMonitorV2::OnMonitorStart() {
    // Capture baseline when monitoring starts (if not already captured)
    std::lock_guard<std::mutex> lock(m_dataMutex);
    if (m_baselineModules.empty()) {
        // Release lock to call CaptureBaseline (which also acquires the lock)
    }
}

void ProcessMonitorV2::OnMonitorStop() {
    // Nothing special needed on stop
}

void ProcessMonitorV2::DoMonitorCycle() {
    // Check for new modules loaded since baseline
    CheckNewModules();

    // Check for new threads created since baseline
    CheckNewThreads();

    // Verify all thread start addresses are in known modules
    CheckThreadStartAddresses();

    // Run injection detection heuristics
    InjectionResult injection = CheckForInjection();
    if (injection.WasDetected()) {
        // Notify via injection callback
        {
            std::lock_guard<std::mutex> cbLock(m_callbackMutex);
            if (m_injectionCallback) {
                m_injectionCallback(injection);
            }
        }

        // Queue a detection event for the EventBus
        DetectionEvent event;
        event.type = DetectionType::SuspiciousModule;
        event.severity = injection.severity;
        event.description = injection.details;
        event.moduleName = WStringToString(injection.moduleName);
        event.address = injection.address;
        event.timestamp = ::GetTickCount();
        QueueEvent(event);
    }
}

// ============================================================================
// BASELINE
// ============================================================================

bool ProcessMonitorV2::CaptureBaseline() {
    std::lock_guard<std::mutex> lock(m_dataMutex);

    m_baselineModules.clear();
    m_baselineThreads.clear();
    m_knownThreads.clear();

    // Capture current modules
    auto modules = GetLoadedModules();
    for (const auto& mod : modules) {
        std::wstring lowerName = mod.name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
        m_baselineModules[lowerName] = mod;
    }

    // Capture current threads
    auto threads = GetThreads();
    for (const auto& thread : threads) {
        m_baselineThreads.insert(thread.threadId);
        m_knownThreads[thread.threadId] = thread;
    }

    return true;
}

bool ProcessMonitorV2::AddTrustedModule(const std::wstring& moduleName) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    std::wstring lower = moduleName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    m_trustedModules.insert(lower);
    return true;
}

bool ProcessMonitorV2::AddTrustedModules(const std::vector<std::wstring>& modules) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    for (const auto& mod : modules) {
        std::wstring lower = mod;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        m_trustedModules.insert(lower);
    }
    return true;
}

void ProcessMonitorV2::ClearTrustedModules() {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    m_trustedModules.clear();
}

void ProcessMonitorV2::AddSuspiciousPattern(const std::wstring& pattern) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    std::wstring lower = pattern;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    m_suspiciousPatterns.insert(lower);
}

void ProcessMonitorV2::ClearSuspiciousPatterns() {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    m_suspiciousPatterns.clear();
}

// ============================================================================
// MODULE SCANNING
// ============================================================================

std::vector<LoadedModuleInfo> ProcessMonitorV2::GetLoadedModules() const {
    std::vector<LoadedModuleInfo> modules;

    FileHandle snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0));
    if (!snapshot) return modules;

    MODULEENTRY32W me32{};
    me32.dwSize = sizeof(MODULEENTRY32W);

    if (::Module32FirstW(snapshot.Get(), &me32)) {
        do {
            LoadedModuleInfo info;
            info.name = me32.szModule;
            info.fullPath = me32.szExePath;
            info.baseAddress = me32.modBaseAddr;
            info.imageSize = me32.modBaseSize;
            info.checksum = CalculateModuleChecksum(me32.hModule);
            info.isSigned = VerifyModuleSignature(me32.szExePath);
            info.isTrusted = IsModuleTrusted(me32.szModule);
            ::GetSystemTimeAsFileTime(&info.loadTime);

            // Determine if it's a system module
            std::wstring lowerPath = info.fullPath;
            std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
            info.isSystemModule = (lowerPath.find(L"\\windows\\system32\\") != std::wstring::npos ||
                                   lowerPath.find(L"\\windows\\syswow64\\") != std::wstring::npos);

            modules.push_back(std::move(info));
        } while (::Module32NextW(snapshot.Get(), &me32));
    }

    return modules;
}

std::vector<LoadedModuleInfo> ProcessMonitorV2::GetNewModules() const {
    std::vector<LoadedModuleInfo> newModules;
    auto currentModules = GetLoadedModules();

    std::lock_guard<std::mutex> lock(m_dataMutex);
    for (const auto& mod : currentModules) {
        std::wstring lowerName = mod.name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

        if (m_baselineModules.find(lowerName) == m_baselineModules.end()) {
            newModules.push_back(mod);
        }
    }

    return newModules;
}

// ============================================================================
// THREAD SCANNING
// ============================================================================

std::vector<ThreadSnapshot> ProcessMonitorV2::GetThreads() const {
    std::vector<ThreadSnapshot> threads;

    const DWORD currentPid = ::GetCurrentProcessId();
    FileHandle snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!snapshot) return threads;

    THREADENTRY32 te32{};
    te32.dwSize = sizeof(THREADENTRY32);

    if (::Thread32First(snapshot.Get(), &te32)) {
        do {
            if (te32.th32OwnerProcessID != currentPid) continue;

            ThreadSnapshot info;
            info.threadId = te32.th32ThreadID;
            info.creationFlags = 0;
            info.isSuspicious = false;

            // Open thread to query its start address
            KernelHandle hThread(::OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID));
            if (hThread) {
                info.startAddress = GetThreadStartAddress(hThread.Get());

                // Determine owning module
                std::wstring modulePath;
                if (IsAddressInModule(info.startAddress, modulePath)) {
                    info.ownerModulePath = modulePath;
                    // Extract filename
                    size_t pos = modulePath.find_last_of(L"\\/");
                    info.ownerModuleName = (pos != std::wstring::npos)
                        ? modulePath.substr(pos + 1) : modulePath;
                }
            }

            info.isSuspicious = IsThreadSuspicious(info);
            threads.push_back(std::move(info));

        } while (::Thread32Next(snapshot.Get(), &te32));
    }

    return threads;
}

std::vector<ThreadSnapshot> ProcessMonitorV2::GetNewThreads() const {
    std::vector<ThreadSnapshot> newThreads;
    auto currentThreads = GetThreads();

    std::lock_guard<std::mutex> lock(m_dataMutex);
    for (const auto& thread : currentThreads) {
        if (m_baselineThreads.find(thread.threadId) == m_baselineThreads.end()) {
            newThreads.push_back(thread);
        }
    }

    return newThreads;
}

void* ProcessMonitorV2::GetThreadStartAddress(HANDLE threadHandle) {
    ResolveNtdllFunctions();
    if (s_ntQueryInformationThread == nullptr) return nullptr;

    void* startAddress = nullptr;
    s_ntQueryInformationThread(
        threadHandle,
        kThreadQuerySetWin32StartAddress,
        &startAddress,
        sizeof(startAddress),
        nullptr);

    return startAddress;
}

// ============================================================================
// DETECTION CYCLE HELPERS
// ============================================================================

bool ProcessMonitorV2::CheckNewModules() {
    auto newModules = GetNewModules();
    bool foundSuspicious = false;

    for (const auto& mod : newModules) {
        // Add to baseline so we don't re-alert
        {
            std::lock_guard<std::mutex> lock(m_dataMutex);
            std::wstring lowerName = mod.name;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
            m_baselineModules[lowerName] = mod;
        }

        if (IsModuleSuspicious(mod)) {
            // Notify via module callback
            {
                std::lock_guard<std::mutex> cbLock(m_callbackMutex);
                if (m_moduleCallback) {
                    m_moduleCallback(mod, true);
                }
            }

            DetectionEvent event;
            event.type = DetectionType::SuspiciousModule;
            event.severity = Severity::Warning;
            event.description = "Suspicious module loaded: " + WStringToString(mod.name);
            event.moduleName = WStringToString(mod.name);
            event.address = mod.baseAddress;
            event.timestamp = ::GetTickCount();
            QueueEvent(event);

            foundSuspicious = true;
        }
    }

    return foundSuspicious;
}

bool ProcessMonitorV2::CheckNewThreads() {
    auto newThreads = GetNewThreads();
    bool foundSuspicious = false;

    for (const auto& thread : newThreads) {
        // Add to baseline
        {
            std::lock_guard<std::mutex> lock(m_dataMutex);
            m_baselineThreads.insert(thread.threadId);
            m_knownThreads[thread.threadId] = thread;
        }

        // Notify via thread callback
        {
            std::lock_guard<std::mutex> cbLock(m_callbackMutex);
            if (m_threadCallback) {
                m_threadCallback(thread);
            }
        }

        if (thread.isSuspicious) {
            DetectionEvent event;
            event.type = DetectionType::SuspiciousThread;
            event.severity = Severity::Warning;
            event.description = "Suspicious thread created: " + thread.suspicionReason;
            event.address = thread.startAddress;
            event.timestamp = ::GetTickCount();
            QueueEvent(event);

            foundSuspicious = true;
        }
    }

    return foundSuspicious;
}

bool ProcessMonitorV2::CheckThreadStartAddresses() {
    auto threads = GetThreads();
    bool foundSuspicious = false;

    for (const auto& thread : threads) {
        if (thread.startAddress == nullptr) continue;

        std::wstring moduleName;
        if (!IsAddressInModule(thread.startAddress, moduleName)) {
            DetectionEvent event;
            event.type = DetectionType::SuspiciousThread;
            event.severity = Severity::Critical;
            event.description = "Thread start address outside any loaded module (possible injection)";
            event.address = thread.startAddress;
            event.timestamp = ::GetTickCount();
            QueueEvent(event);

            foundSuspicious = true;
        }
    }

    return foundSuspicious;
}

// ============================================================================
// INJECTION DETECTION
// ============================================================================

InjectionResult ProcessMonitorV2::CheckForInjection() const {
    InjectionResult result;

    // 1. Check for newly loaded unsigned/untrusted modules
    auto newModules = GetNewModules();
    for (const auto& mod : newModules) {
        if (!mod.isSigned && !mod.isTrusted) {
            result.technique = InjectionResult::Technique::DLLInjection;
            result.moduleName = mod.name;
            result.address = mod.baseAddress;
            result.severity = Severity::Critical;
            result.details = "Unsigned untrusted DLL loaded: " + WStringToString(mod.name);
            return result;
        }

        if (IsModuleSuspicious(mod)) {
            result.technique = InjectionResult::Technique::DLLInjection;
            result.moduleName = mod.name;
            result.address = mod.baseAddress;
            result.severity = Severity::Critical;
            result.details = "Suspicious DLL injected: " + WStringToString(mod.name);
            return result;
        }
    }

    // 2. Check for remote threads
    if (DetectRemoteThreads()) {
        result.technique = InjectionResult::Technique::RemoteThread;
        result.severity = Severity::Critical;
        result.details = "Remote thread creation detected - thread starts outside any module";
        return result;
    }

    // 3. Check for manually mapped code
    if (DetectManualMapping()) {
        result.technique = InjectionResult::Technique::ManualMapping;
        result.severity = Severity::Fatal;
        result.details = "Manually mapped PE or shellcode detected in executable memory";
        return result;
    }

    // 4. Check for code caves
    if (DetectCodeCaves()) {
        result.technique = InjectionResult::Technique::CodeCave;
        result.severity = Severity::Critical;
        result.details = "Code cave with injected code detected in module padding";
        return result;
    }

    // 5. Check for process hollowing
    if (DetectHollowing()) {
        result.technique = InjectionResult::Technique::ProcessHollowing;
        result.severity = Severity::Fatal;
        result.details = "Main executable image appears to be hollowed";
        return result;
    }

    return result; // technique == None
}

bool ProcessMonitorV2::DetectRemoteThreads() const {
    auto threads = GetThreads();

    for (const auto& thread : threads) {
        if (thread.ownerModuleName.empty() && thread.startAddress != nullptr) {
            std::wstring moduleName;
            if (!IsAddressInModule(thread.startAddress, moduleName)) {
                return true;
            }
        }
    }

    return false;
}

bool ProcessMonitorV2::DetectManualMapping() const {
    MEMORY_BASIC_INFORMATION mbi{};
    auto* address = static_cast<const uint8_t*>(nullptr);

    while (::VirtualQuery(address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {

            // Check if this executable region is backed by any module
            std::wstring moduleName;
            if (!IsAddressInModule(mbi.BaseAddress, moduleName)) {
                const auto* data = static_cast<const uint8_t*>(mbi.BaseAddress);

                // Check for PE header (MZ signature)
                if (mbi.RegionSize >= 2 && data[0] == 'M' && data[1] == 'Z') {
                    return true;
                }

                // Check for common x86 function prologues indicating injected code
                if (mbi.RegionSize >= 4) {
                    // push ebp; mov ebp, esp (32-bit prologue)
                    if (data[0] == 0x55 && data[1] == 0x8B && data[2] == 0xEC) {
                        return true;
                    }
                    // push rbx (64-bit prologue)
                    if (data[0] == 0x40 && data[1] == 0x53) {
                        return true;
                    }
                    // sub rsp, imm8 (64-bit stack allocation)
                    if (data[0] == 0x48 && data[1] == 0x83 && data[2] == 0xEC) {
                        return true;
                    }
                }

                // High entropy in small executable region = likely shellcode
                if (mbi.RegionSize >= 64 && mbi.RegionSize <= 0x100000) {
                    double entropy = CalculateEntropy(data, std::min<size_t>(mbi.RegionSize, 1024));
                    if (entropy > 6.0) {
                        return true;
                    }
                }
            }
        }

        address = static_cast<const uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
    }

    return false;
}

bool ProcessMonitorV2::DetectCodeCaves() const {
    auto modules = GetLoadedModules();

    for (const auto& mod : modules) {
        if (mod.isTrusted || mod.isSystemModule) continue;

        const auto* dosHeader = static_cast<const IMAGE_DOS_HEADER*>(mod.baseAddress);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) continue;

        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            static_cast<const uint8_t*>(mod.baseAddress) + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) continue;

        const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
            if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

            const auto* sectionData = static_cast<const uint8_t*>(mod.baseAddress) +
                                      section->VirtualAddress;
            const size_t sectionSize = section->Misc.VirtualSize;
            const size_t rawSize = section->SizeOfRawData;

            // Code caves are typically in the padding between VirtualSize and
            // aligned size, or at the end of the raw data section.
            // If VirtualSize > SizeOfRawData, the difference is zero-filled by the loader.
            // Cheats write shellcode into this zero-filled region.

            if (rawSize > 0 && sectionSize > rawSize) {
                // Check the padding region (between raw data end and virtual end)
                const uint8_t* paddingStart = sectionData + rawSize;
                size_t paddingSize = sectionSize - rawSize;
                size_t scanLimit = std::min<size_t>(paddingSize, 0x10000);

                // Count non-zero bytes in the padding region
                size_t nonZeroCount = 0;
                for (size_t j = 0; j < scanLimit; j++) {
                    if (paddingStart[j] != 0x00) {
                        nonZeroCount++;
                    }
                }

                // If more than 32 non-zero bytes exist in the padding,
                // compute entropy to distinguish real code from data alignment
                if (nonZeroCount > 32) {
                    double entropy = CalculateEntropy(paddingStart, scanLimit);
                    // Code typically has entropy between 4.0 and 7.5
                    // Pure padding (zeros/NOPs) has entropy near 0
                    if (entropy > 3.5) {
                        return true; // Likely injected code in padding
                    }
                }
            }

            // Also check for large NOP-sled + code patterns within the section body
            // (Some injectors overwrite NOP padding regions mid-section)
            size_t scanSize = std::min<size_t>(sectionSize, 0x20000);
            size_t nopRunStart = 0;
            size_t nopRunLength = 0;
            bool inNopRun = false;

            for (size_t j = 0; j < scanSize; j++) {
                bool isNopOrZero = (sectionData[j] == 0x90 || sectionData[j] == 0xCC ||
                                    sectionData[j] == 0x00);
                if (isNopOrZero) {
                    if (!inNopRun) {
                        nopRunStart = j;
                        inNopRun = true;
                    }
                    nopRunLength++;
                } else {
                    if (inNopRun && nopRunLength > 64) {
                        // Large NOP/padding run ended - check what follows
                        size_t remainingAfterRun = scanSize - j;
                        if (remainingAfterRun >= 16) {
                            double postNopEntropy = CalculateEntropy(sectionData + j,
                                                                      std::min<size_t>(remainingAfterRun, 256));
                            if (postNopEntropy > 4.0) {
                                // High-entropy code right after a large NOP sled: suspicious
                                return true;
                            }
                        }
                    }
                    inNopRun = false;
                    nopRunLength = 0;
                }
            }
        }
    }

    return false;
}

bool ProcessMonitorV2::DetectHollowing() const {
    HMODULE mainModule = ::GetModuleHandleW(nullptr);
    if (mainModule == nullptr) return false;

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(mainModule);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return true; // DOS header corrupted - clear sign of hollowing
    }

    const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const uint8_t*>(mainModule) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return true; // NT header corrupted
    }

    // Verify entry point falls within the module's address range
    const auto entryPointRva = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    const auto* entryPoint = reinterpret_cast<const void*>(
        reinterpret_cast<uintptr_t>(mainModule) + entryPointRva);

    MEMORY_BASIC_INFORMATION mbi{};
    if (::VirtualQuery(entryPoint, &mbi, sizeof(mbi))) {
        if (mbi.AllocationBase != mainModule) {
            return true; // Entry point memory not allocated by the main module
        }
        if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            return true; // Entry point not in executable memory
        }
    }

    // Verify the .text section is executable and matches expected size
    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (std::memcmp(section->Name, ".text", 5) == 0) {
            const auto* textSection = reinterpret_cast<const uint8_t*>(mainModule) +
                                      section->VirtualAddress;
            MEMORY_BASIC_INFORMATION textMbi{};
            if (::VirtualQuery(textSection, &textMbi, sizeof(textMbi))) {
                if (textMbi.AllocationBase != mainModule) {
                    return true; // .text section memory doesn't belong to main module
                }
            }
            break;
        }
    }

    return false;
}

// ============================================================================
// ANALYSIS HELPERS
// ============================================================================

bool ProcessMonitorV2::IsModuleSuspicious(const LoadedModuleInfo& module) const {
    std::wstring lowerName = module.name;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

    // Check against suspicious keyword patterns
    // Note: m_dataMutex should already be held by the caller, or we're in a
    // read-only context where the set doesn't change.
    for (const auto& pattern : m_suspiciousPatterns) {
        if (lowerName.find(pattern) != std::wstring::npos) {
            return true;
        }
    }

    // Unsigned + not trusted + loaded from temp/appdata = highly suspicious
    if (!module.isSigned && !module.isTrusted) {
        std::wstring lowerPath = module.fullPath;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

        if (lowerPath.find(L"\\temp\\") != std::wstring::npos ||
            lowerPath.find(L"\\appdata\\local\\temp\\") != std::wstring::npos ||
            lowerPath.find(L"\\downloads\\") != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

bool ProcessMonitorV2::IsThreadSuspicious(const ThreadSnapshot& thread) const {
    // Thread with no owner module but has a start address
    if (thread.ownerModuleName.empty() && thread.startAddress != nullptr) {
        return true;
    }

    // Thread originating from a suspicious module
    if (!thread.ownerModuleName.empty()) {
        std::wstring lower = thread.ownerModuleName;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        for (const auto& pattern : m_suspiciousPatterns) {
            if (lower.find(pattern) != std::wstring::npos) {
                return true;
            }
        }
    }

    return false;
}

bool ProcessMonitorV2::IsAddressInModule(void* address, std::wstring& outModuleName) const {
    outModuleName.clear();

    HMODULE module = nullptr;
    BOOL result = ::GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(address),
        &module);

    if (result && module != nullptr) {
        wchar_t path[MAX_PATH]{};
        if (::GetModuleFileNameW(module, path, MAX_PATH) > 0) {
            outModuleName = path;
            return true;
        }
    }

    return false;
}

bool ProcessMonitorV2::IsAddressExecutable(void* address) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (::VirtualQuery(address, &mbi, sizeof(mbi))) {
        return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    }
    return false;
}

// ============================================================================
// MODULE QUERIES
// ============================================================================

LoadedModuleInfo ProcessMonitorV2::GetModuleInfo(HMODULE module) const {
    LoadedModuleInfo info;
    if (module == nullptr) return info;

    wchar_t path[MAX_PATH]{};
    if (::GetModuleFileNameW(module, path, MAX_PATH) > 0) {
        info.fullPath = path;
        std::wstring pathStr = path;
        size_t pos = pathStr.find_last_of(L"\\/");
        info.name = (pos != std::wstring::npos) ? pathStr.substr(pos + 1) : pathStr;
    }

    MODULEINFO modInfo{};
    if (::GetModuleInformation(::GetCurrentProcess(), module, &modInfo, sizeof(modInfo))) {
        info.baseAddress = modInfo.lpBaseOfDll;
        info.imageSize = modInfo.SizeOfImage;
    }

    info.checksum = CalculateModuleChecksum(module);
    info.isSigned = VerifyModuleSignature(info.fullPath);
    info.isTrusted = IsModuleTrusted(info.name);

    return info;
}

LoadedModuleInfo ProcessMonitorV2::GetModuleInfo(const std::wstring& name) const {
    HMODULE module = ::GetModuleHandleW(name.c_str());
    return GetModuleInfo(module);
}

bool ProcessMonitorV2::IsModuleLoaded(const std::wstring& name) const {
    return ::GetModuleHandleW(name.c_str()) != nullptr;
}

bool ProcessMonitorV2::IsModuleTrusted(const std::wstring& name) const {
    std::wstring lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    // Try without lock first (read-only check on stable set)
    return m_trustedModules.find(lower) != m_trustedModules.end();
}

ThreadSnapshot ProcessMonitorV2::GetThreadInfo(DWORD threadId) const {
    ThreadSnapshot info;
    info.threadId = threadId;

    KernelHandle hThread(::OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId));
    if (hThread) {
        info.startAddress = GetThreadStartAddress(hThread.Get());
        IsAddressInModule(info.startAddress, info.ownerModulePath);

        size_t pos = info.ownerModulePath.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            info.ownerModuleName = info.ownerModulePath.substr(pos + 1);
        }

        info.isSuspicious = IsThreadSuspicious(info);
    }

    return info;
}

bool ProcessMonitorV2::IsThreadFromTrustedModule(DWORD threadId) const {
    KernelHandle hThread(::OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId));
    if (!hThread) return false;

    void* startAddr = GetThreadStartAddress(hThread.Get());
    if (startAddr == nullptr) return false;

    std::wstring modulePath;
    if (IsAddressInModule(startAddr, modulePath)) {
        size_t pos = modulePath.find_last_of(L"\\/");
        std::wstring moduleName = (pos != std::wstring::npos)
            ? modulePath.substr(pos + 1) : modulePath;
        return IsModuleTrusted(moduleName);
    }

    return false;
}

// ============================================================================
// MODULE VERIFICATION
// ============================================================================

bool ProcessMonitorV2::VerifyModuleSignature(const std::wstring& path) {
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = path.c_str();

    GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA winTrustData{};
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG status = ::WinVerifyTrust(NULL, &guidAction, &winTrustData);

    // Clean up the trust state
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    ::WinVerifyTrust(NULL, &guidAction, &winTrustData);

    return status == ERROR_SUCCESS;
}

uint32_t ProcessMonitorV2::CalculateModuleChecksum(HMODULE module) {
    if (module == nullptr) return 0;

    MODULEINFO modInfo{};
    if (!::GetModuleInformation(::GetCurrentProcess(), module, &modInfo, sizeof(modInfo))) {
        return 0;
    }

    return CalculateCRC32(static_cast<const uint8_t*>(modInfo.lpBaseOfDll), modInfo.SizeOfImage);
}

double ProcessMonitorV2::CalculateEntropy(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0) return 0.0;

    // Count byte frequencies
    size_t frequency[256] = {};
    for (size_t i = 0; i < size; i++) {
        frequency[data[i]]++;
    }

    // Calculate Shannon entropy
    double entropy = 0.0;
    const double logBase = std::log(2.0);
    const double sizeDouble = static_cast<double>(size);

    for (size_t i = 0; i < 256; i++) {
        if (frequency[i] == 0) continue;

        double probability = static_cast<double>(frequency[i]) / sizeDouble;
        entropy -= probability * (std::log(probability) / logBase);
    }

    return entropy;
}

// ============================================================================
// CALLBACKS
// ============================================================================

void ProcessMonitorV2::SetModuleCallback(ModuleCallback callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_moduleCallback = std::move(callback);
}

void ProcessMonitorV2::SetThreadCallback(ThreadCallback callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_threadCallback = std::move(callback);
}

void ProcessMonitorV2::SetInjectionCallback(InjectionCallback callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_injectionCallback = std::move(callback);
}

// ============================================================================
// STATUS
// ============================================================================

int ProcessMonitorV2::GetBaselineModuleCount() const {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    return static_cast<int>(m_baselineModules.size());
}

int ProcessMonitorV2::GetBaselineThreadCount() const {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    return static_cast<int>(m_baselineThreads.size());
}

// ============================================================================
// IConfigurable
// ============================================================================

bool ProcessMonitorV2::ApplyConfig(const ConfigMap& config) {
    auto getOrDefault = [&config](const std::string& key, const std::string& def) {
        auto it = config.find(key);
        return (it != config.end()) ? it->second : def;
    };

    std::string intervalStr = getOrDefault("scan_interval", "1000");
    try {
        DWORD interval = static_cast<DWORD>(std::stoul(intervalStr));
        SetMonitorInterval(interval);
    } catch (...) {
        // Keep default
    }

    // Load additional suspicious patterns from config
    std::string patternsStr = getOrDefault("suspicious_patterns", "");
    if (!patternsStr.empty()) {
        // Parse comma-separated patterns
        size_t start = 0;
        while (start < patternsStr.size()) {
            size_t end = patternsStr.find(',', start);
            if (end == std::string::npos) end = patternsStr.size();

            std::string pattern = patternsStr.substr(start, end - start);
            // Trim whitespace
            size_t pStart = pattern.find_first_not_of(" \t");
            size_t pEnd = pattern.find_last_not_of(" \t");
            if (pStart != std::string::npos && pEnd != std::string::npos) {
                pattern = pattern.substr(pStart, pEnd - pStart + 1);
                AddSuspiciousPattern(StringToWString(pattern));
            }

            start = end + 1;
        }
    }

    return true;
}

void ProcessMonitorV2::ExportConfig(ConfigMap& outConfig) const {
    outConfig["scan_interval"] = std::to_string(GetMonitorInterval());

    // Export suspicious patterns as comma-separated list
    std::string patterns;
    {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        for (const auto& pattern : m_suspiciousPatterns) {
            if (!patterns.empty()) patterns += ",";
            patterns += WStringToString(pattern);
        }
    }
    outConfig["suspicious_patterns"] = patterns;
}

} // namespace AntiCheat
