/**
 * AntiCheatCore - Hook Detection Implementation
 * Detects inline hooks, IAT hooks, and API modifications
 */

#include "stdafx.h"
#include "../include/internal/HookDetector.h"
#include <Softpub.h>
#include <WinTrust.h>

#pragma comment(lib, "Wintrust.lib")

namespace AntiCheat {

// Common hook instruction opcodes
static const uint8_t JMP_REL8 = 0xEB;
static const uint8_t JMP_REL32 = 0xE9;
static const uint8_t JMP_ABS_FF = 0xFF;
static const uint8_t CALL_REL32 = 0xE8;
static const uint8_t MOV_EAX = 0xB8;
static const uint8_t PUSH_RET = 0x68;
static const uint8_t NOP = 0x90;

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

HookDetector::HookDetector() {
}

HookDetector::~HookDetector() {
    Shutdown();
}

// ============================================================================
// INITIALIZATION
// ============================================================================

bool HookDetector::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Add default critical APIs to monitor
    AddCriticalAPI("ntdll.dll", "NtQueryInformationProcess");
    AddCriticalAPI("ntdll.dll", "NtSetInformationThread");
    AddCriticalAPI("ntdll.dll", "NtReadVirtualMemory");
    AddCriticalAPI("ntdll.dll", "NtWriteVirtualMemory");
    AddCriticalAPI("ntdll.dll", "NtProtectVirtualMemory");
    AddCriticalAPI("kernel32.dll", "ReadProcessMemory");
    AddCriticalAPI("kernel32.dll", "WriteProcessMemory");
    AddCriticalAPI("kernel32.dll", "VirtualProtect");
    AddCriticalAPI("kernel32.dll", "IsDebuggerPresent");
    AddCriticalAPI("kernel32.dll", "CheckRemoteDebuggerPresent");
    AddCriticalAPI("user32.dll", "GetAsyncKeyState");
    AddCriticalAPI("user32.dll", "GetKeyState");
    AddCriticalAPI("user32.dll", "SetWindowsHookExW");

    return true;
}

void HookDetector::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_criticalAPIs.clear();
    m_trustedModules.clear();
    m_originalPrologues.clear();
}

void HookDetector::SetDetectionCallback(DetectionCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_callback = callback;
}

// ============================================================================
// API REGISTRATION
// ============================================================================

void HookDetector::AddCriticalAPI(const std::string& moduleName, const std::string& functionName) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string key = moduleName + "!" + functionName;
    m_criticalAPIs.push_back(key);
}

void HookDetector::AddCriticalAPIs(const std::vector<std::pair<std::string, std::string>>& apis) {
    for (const auto& api : apis) {
        AddCriticalAPI(api.first, api.second);
    }
}

void HookDetector::ClearCriticalAPIs() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_criticalAPIs.clear();
}

void HookDetector::AddTrustedModule(const std::wstring& moduleName) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_trustedModules.push_back(moduleName);
}

void HookDetector::ClearTrustedModules() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_trustedModules.clear();
}

// ============================================================================
// HOOK DETECTION
// ============================================================================

bool HookDetector::IsJmpInstruction(const uint8_t* bytes) {
    if (!bytes) return false;

    // JMP rel8
    if (bytes[0] == JMP_REL8) return true;

    // JMP rel32
    if (bytes[0] == JMP_REL32) return true;

    // JMP [addr] or JMP reg
    if (bytes[0] == JMP_ABS_FF) {
        uint8_t modrm = bytes[1];
        uint8_t reg = (modrm >> 3) & 0x07;
        if (reg == 4 || reg == 5) return true; // JMP indirect
    }

    return false;
}

bool HookDetector::IsCallInstruction(const uint8_t* bytes) {
    if (!bytes) return false;

    // CALL rel32
    if (bytes[0] == CALL_REL32) return true;

    // CALL [addr] or CALL reg
    if (bytes[0] == JMP_ABS_FF) {
        uint8_t modrm = bytes[1];
        uint8_t reg = (modrm >> 3) & 0x07;
        if (reg == 2 || reg == 3) return true;
    }

    return false;
}

bool HookDetector::IsHookInstruction(const uint8_t* bytes) {
    if (!bytes) return false;

    // Direct jumps
    if (IsJmpInstruction(bytes)) return true;

    // PUSH addr; RET pattern
    if (bytes[0] == PUSH_RET) return true;

    // MOV EAX, addr; JMP EAX pattern
    if (bytes[0] == MOV_EAX && bytes[5] == JMP_ABS_FF) return true;

    // Hot-patching: MOV EDI, EDI preceded by 5 NOPs
    // Windows APIs have this at the start

    return false;
}

HookDetector::HookInfo HookDetector::CheckInlineHook(HMODULE module, const char* functionName) {
    HookInfo info = {};
    info.type = HookType::None;

    void* funcAddr = GetProcAddress(module, functionName);
    if (!funcAddr) {
        m_lastError = "Function not found: " + std::string(functionName);
        return info;
    }

    info.originalAddress = funcAddr;
    info.functionName = functionName;

    // Get module name
    wchar_t modulePath[MAX_PATH];
    if (GetModuleFileNameW(module, modulePath, MAX_PATH)) {
        info.moduleName = WStringToString(modulePath);
    }

    // Read first 16 bytes of function
    uint8_t bytes[16];
    SIZE_T bytesRead;
    if (!ReadProcessMemory(GetCurrentProcess(), funcAddr, bytes, sizeof(bytes), &bytesRead)) {
        return info;
    }

    info.currentBytes.assign(bytes, bytes + bytesRead);

    // Check for hook patterns
    if (IsHookInstruction(bytes)) {
        info.type = HookType::InlineHook;

        // Try to determine where it hooks to
        if (bytes[0] == JMP_REL32) {
            int32_t offset = *reinterpret_cast<int32_t*>(&bytes[1]);
            info.hookedAddress = reinterpret_cast<void*>(
                reinterpret_cast<uintptr_t>(funcAddr) + 5 + offset);
        } else if (bytes[0] == JMP_REL8) {
            int8_t offset = static_cast<int8_t>(bytes[1]);
            info.hookedAddress = reinterpret_cast<void*>(
                reinterpret_cast<uintptr_t>(funcAddr) + 2 + offset);
        }

        // Identify target module
        info.targetModule = WStringToString(GetModuleFromAddress(info.hookedAddress));
    }

    // Compare with stored prologue if available
    std::string key = info.moduleName + "!" + functionName;
    auto it = m_originalPrologues.find(key);
    if (it != m_originalPrologues.end()) {
        if (info.currentBytes != it->second) {
            info.type = HookType::InlineHook;
            info.originalBytes = it->second;
        }
    }

    return info;
}

HookDetector::HookInfo HookDetector::CheckIATHook(HMODULE targetModule, HMODULE sourceModule,
                                                  const char* functionName) {
    HookInfo info = {};
    info.type = HookType::None;
    info.functionName = functionName;

    void* expectedAddr = GetProcAddress(sourceModule, functionName);
    if (!expectedAddr) return info;

    info.originalAddress = expectedAddr;

    // Walk IAT to find the imported function
    bool found = WalkIAT(targetModule, [&](const char* dllName, const char* funcName, void** iatEntry) {
        if (funcName && strcmp(funcName, functionName) == 0) {
            void* currentAddr = *iatEntry;
            if (currentAddr != expectedAddr) {
                info.type = HookType::IATHook;
                info.hookedAddress = currentAddr;
                info.targetModule = WStringToString(GetModuleFromAddress(currentAddr));
            }
            return false; // Stop walking
        }
        return true; // Continue
    });

    return info;
}

HookDetector::HookInfo HookDetector::CheckFunction(const char* moduleName, const char* functionName) {
    HMODULE module = GetModuleHandleA(moduleName);
    if (!module) {
        module = LoadLibraryA(moduleName);
    }

    if (!module) {
        HookInfo info = {};
        m_lastError = "Module not found: " + std::string(moduleName);
        return info;
    }

    return CheckInlineHook(module, functionName);
}

// ============================================================================
// IAT WALKING
// ============================================================================

bool HookDetector::WalkIAT(HMODULE module, std::function<bool(const char*, const char*, void**)> callback) {
    if (!module || !callback) return false;

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(module) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

    DWORD importDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importDirRVA == 0) return false;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        reinterpret_cast<uint8_t*>(module) + importDirRVA);

    while (importDesc->Name != 0) {
        const char* dllName = reinterpret_cast<const char*>(
            reinterpret_cast<uint8_t*>(module) + importDesc->Name);

        PIMAGE_THUNK_DATA origThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
            reinterpret_cast<uint8_t*>(module) + importDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA iatThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
            reinterpret_cast<uint8_t*>(module) + importDesc->FirstThunk);

        while (origThunk->u1.AddressOfData != 0) {
            const char* funcName = nullptr;

            if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                    reinterpret_cast<uint8_t*>(module) + origThunk->u1.AddressOfData);
                funcName = reinterpret_cast<const char*>(importByName->Name);
            }

            if (!callback(dllName, funcName, reinterpret_cast<void**>(&iatThunk->u1.Function))) {
                return true;
            }

            origThunk++;
            iatThunk++;
        }

        importDesc++;
    }

    return true;
}

// ============================================================================
// SCANNING
// ============================================================================

HookDetector::ScanResult HookDetector::ScanAllHooks() {
    ScanResult result = {};
    result.hasCriticalHooks = false;
    result.totalHooksFound = 0;

    // Scan critical APIs
    ScanResult criticalResult = ScanCriticalAPIs();
    result.detectedHooks.insert(result.detectedHooks.end(),
                                 criticalResult.detectedHooks.begin(),
                                 criticalResult.detectedHooks.end());

    // Scan suspicious modules
    result.suspiciousModules = GetSuspiciousModules();

    result.totalHooksFound = static_cast<int>(result.detectedHooks.size());
    result.hasCriticalHooks = !result.detectedHooks.empty();

    return result;
}

HookDetector::ScanResult HookDetector::ScanCriticalAPIs() {
    ScanResult result = {};

    std::lock_guard<std::mutex> lock(m_mutex);

    for (const std::string& apiKey : m_criticalAPIs) {
        size_t pos = apiKey.find('!');
        if (pos == std::string::npos) continue;

        std::string moduleName = apiKey.substr(0, pos);
        std::string funcName = apiKey.substr(pos + 1);

        HookInfo info = CheckFunction(moduleName.c_str(), funcName.c_str());
        if (info.type != HookType::None) {
            result.detectedHooks.push_back(info);

            // Report via callback
            if (m_callback) {
                DetectionEvent event;
                event.type = DetectionType::HookDetected;
                event.severity = Severity::Critical;
                event.description = "Hook detected: " + moduleName + "!" + funcName;
                event.timestamp = GetTickCount();
                m_callback(event);
            }
        }
    }

    result.totalHooksFound = static_cast<int>(result.detectedHooks.size());
    result.hasCriticalHooks = result.totalHooksFound > 0;

    return result;
}

HookDetector::ScanResult HookDetector::ScanModuleHooks(HMODULE module) {
    ScanResult result = {};

    // Get module info
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), module, &modInfo, sizeof(modInfo))) {
        return result;
    }

    // Scan exports for hooks
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return result;

    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(module) + dosHeader->e_lfanew);

    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) return result;

    PIMAGE_EXPORT_DIRECTORY exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        reinterpret_cast<uint8_t*>(module) + exportDirRVA);

    DWORD* names = reinterpret_cast<DWORD*>(
        reinterpret_cast<uint8_t*>(module) + exportDir->AddressOfNames);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* funcName = reinterpret_cast<const char*>(
            reinterpret_cast<uint8_t*>(module) + names[i]);

        HookInfo info = CheckInlineHook(module, funcName);
        if (info.type != HookType::None) {
            result.detectedHooks.push_back(info);
        }
    }

    result.totalHooksFound = static_cast<int>(result.detectedHooks.size());
    return result;
}

// ============================================================================
// MODULE ANALYSIS
// ============================================================================

std::vector<HookDetector::ModuleInfo> HookDetector::GetLoadedModules() {
    std::vector<ModuleInfo> modules;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
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
            info.isSystem = IsSystemModule(me32.szExePath);
            info.isSigned = IsSignedModule(me32.szExePath);
            info.checksum = 0;

            modules.push_back(info);
        } while (Module32NextW(snapshot, &me32));
    }

    CloseHandle(snapshot);
    return modules;
}

std::vector<HookDetector::ModuleInfo> HookDetector::GetSuspiciousModules() {
    std::vector<ModuleInfo> suspicious;
    auto modules = GetLoadedModules();

    for (const ModuleInfo& mod : modules) {
        // Check for unsigned non-system modules
        if (!mod.isSystem && !mod.isSigned) {
            suspicious.push_back(mod);
            continue;
        }

        // Check for modules with suspicious names
        std::wstring lowerName = mod.name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

        if (lowerName.find(L"inject") != std::wstring::npos ||
            lowerName.find(L"hook") != std::wstring::npos ||
            lowerName.find(L"cheat") != std::wstring::npos ||
            lowerName.find(L"hack") != std::wstring::npos) {
            suspicious.push_back(mod);
        }
    }

    return suspicious;
}

bool HookDetector::IsSystemModule(const std::wstring& path) {
    std::wstring lowerPath = path;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

    // Check for Windows system directories
    if (lowerPath.find(L"\\windows\\system32\\") != std::wstring::npos ||
        lowerPath.find(L"\\windows\\syswow64\\") != std::wstring::npos) {
        return true;
    }

    return false;
}

bool HookDetector::IsSignedModule(const std::wstring& path) {
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

std::wstring HookDetector::GetModuleFromAddress(void* address) {
    HMODULE module = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                           reinterpret_cast<LPCWSTR>(address), &module)) {
        wchar_t path[MAX_PATH];
        if (GetModuleFileNameW(module, path, MAX_PATH)) {
            return path;
        }
    }
    return L"Unknown";
}

// ============================================================================
// PROLOGUE STORAGE
// ============================================================================

bool HookDetector::StoreFunctionPrologue(const char* moduleName, const char* functionName) {
    HMODULE module = GetModuleHandleA(moduleName);
    if (!module) return false;

    void* funcAddr = GetProcAddress(module, functionName);
    if (!funcAddr) return false;

    ByteVector prologue(16);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(GetCurrentProcess(), funcAddr, prologue.data(), 16, &bytesRead)) {
        return false;
    }

    std::string key = std::string(moduleName) + "!" + functionName;

    std::lock_guard<std::mutex> lock(m_mutex);
    m_originalPrologues[key] = prologue;

    return true;
}

bool HookDetector::StoreCriticalPrologues() {
    bool success = true;

    std::lock_guard<std::mutex> lock(m_mutex);
    for (const std::string& apiKey : m_criticalAPIs) {
        size_t pos = apiKey.find('!');
        if (pos == std::string::npos) continue;

        std::string moduleName = apiKey.substr(0, pos);
        std::string funcName = apiKey.substr(pos + 1);

        m_mutex.unlock();
        if (!StoreFunctionPrologue(moduleName.c_str(), funcName.c_str())) {
            success = false;
        }
        m_mutex.lock();
    }

    return success;
}

bool HookDetector::VerifyStoredPrologues() {
    std::lock_guard<std::mutex> lock(m_mutex);

    for (const auto& pair : m_originalPrologues) {
        size_t pos = pair.first.find('!');
        if (pos == std::string::npos) continue;

        std::string moduleName = pair.first.substr(0, pos);
        std::string funcName = pair.first.substr(pos + 1);

        HMODULE module = GetModuleHandleA(moduleName.c_str());
        if (!module) continue;

        void* funcAddr = GetProcAddress(module, funcName.c_str());
        if (!funcAddr) continue;

        ByteVector current(16);
        SIZE_T bytesRead;
        if (ReadProcessMemory(GetCurrentProcess(), funcAddr, current.data(), 16, &bytesRead)) {
            if (current != pair.second) {
                return false; // Prologue changed - hook detected
            }
        }
    }

    return true;
}

// ============================================================================
// ANTI-DEBUGGING
// ============================================================================

bool HookDetector::IsDebuggerPresent() {
    return ::IsDebuggerPresent() != FALSE;
}

bool HookDetector::IsRemoteDebuggerPresent() {
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
    return debuggerPresent != FALSE;
}

bool HookDetector::CheckDebugRegisters() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            return true; // Hardware breakpoints set
        }
    }

    return false;
}

bool HookDetector::CheckDebugFlags() {
    // Check NtGlobalFlag using inline assembly or direct PEB access
#ifdef _M_IX86
    // 32-bit: PEB is at fs:[0x30], NtGlobalFlag at PEB+0x68
    DWORD ntGlobalFlag = 0;
    __asm {
        mov eax, fs:[0x30]      // Get PEB
        mov eax, [eax + 0x68]   // Get NtGlobalFlag
        mov ntGlobalFlag, eax
    }
    // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
    if (ntGlobalFlag & 0x70) {
        return true;
    }
#else
    // 64-bit: Use NtQueryInformationProcess instead
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static pNtQueryInformationProcess NtQueryInfoProcess = reinterpret_cast<pNtQueryInformationProcess>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));

    if (NtQueryInfoProcess) {
        DWORD debugFlags = 0;
        // ProcessDebugFlags = 0x1F
        if (NtQueryInfoProcess(GetCurrentProcess(), 0x1F, &debugFlags, sizeof(debugFlags), nullptr) >= 0) {
            if (debugFlags == 0) {
                return true; // Being debugged
            }
        }
    }
#endif
    return false;
}

bool HookDetector::VerifyModuleIntegrity(HMODULE module) {
    // Basic integrity check - verify PE headers
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(module) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

    return true;
}

bool HookDetector::VerifyModuleSignature(const std::wstring& path) {
    return IsSignedModule(path);
}

} // namespace AntiCheat
