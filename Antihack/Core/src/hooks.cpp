/**
 * Hook Detection Module
 * Detects various hooking techniques used by cheats
 */

#include "../include/anticheat_core.h"
#include <Windows.h>
#include <Psapi.h>
#include <vector>
#include <string>

#pragma comment(lib, "psapi.lib")

static char g_hookError[512] = "";

// Hook types
enum HookType {
    HOOK_NONE = 0,
    HOOK_INLINE_JMP,      // JMP instruction at function start
    HOOK_INLINE_PUSH_RET, // PUSH addr + RET
    HOOK_IAT,             // Import Address Table hook
    HOOK_EAT,             // Export Address Table hook
    HOOK_VEH,             // Vectored Exception Handler
    HOOK_HOTPATCH         // Hotpatch (MOV EDI, EDI)
};

struct HookInfo {
    HookType type;
    void* address;
    void* targetAddress;
    char moduleName[MAX_PATH];
    char functionName[128];
};

static std::vector<HookInfo> g_detectedHooks;

// Check if address is within a loaded module
static bool IsAddressInModule(void* address, HMODULE* outModule = nullptr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0) {
        return false;
    }

    if (mbi.Type != MEM_IMAGE) {
        return false;
    }

    if (outModule) {
        *outModule = (HMODULE)mbi.AllocationBase;
    }

    return true;
}

// Get module name from address
static bool GetModuleNameFromAddress(void* address, char* buffer, int bufferSize) {
    HMODULE hModule = NULL;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)address, &hModule)) {
        return false;
    }

    return GetModuleFileNameA(hModule, buffer, bufferSize) > 0;
}

// Check for inline hook (JMP/CALL at function start)
static HookType DetectInlineHook(void* functionAddress) {
    if (!functionAddress) return HOOK_NONE;

    __try {
        BYTE* code = (BYTE*)functionAddress;

        // Check for JMP rel32 (E9 xx xx xx xx)
        if (code[0] == 0xE9) {
            return HOOK_INLINE_JMP;
        }

        // Check for JMP [addr] (FF 25 xx xx xx xx)
        if (code[0] == 0xFF && code[1] == 0x25) {
            return HOOK_INLINE_JMP;
        }

        // Check for PUSH addr + RET (68 xx xx xx xx C3)
        if (code[0] == 0x68 && code[5] == 0xC3) {
            return HOOK_INLINE_PUSH_RET;
        }

        // Check for MOV EAX, addr + JMP EAX (B8 xx xx xx xx FF E0)
        if (code[0] == 0xB8 && code[5] == 0xFF && code[6] == 0xE0) {
            return HOOK_INLINE_JMP;
        }

        // Check for hotpatch (MOV EDI, EDI = 8B FF) with JMP before
        if (code[0] == 0x8B && code[1] == 0xFF) {
            // Check 5 bytes before for a JMP
            BYTE* preCode = code - 5;
            if (preCode[0] == 0xE9) {
                return HOOK_HOTPATCH;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return HOOK_NONE;
    }

    return HOOK_NONE;
}

// Get jump target from inline hook
static void* GetHookTarget(void* functionAddress, HookType hookType) {
    if (!functionAddress) return nullptr;

    __try {
        BYTE* code = (BYTE*)functionAddress;

        switch (hookType) {
            case HOOK_INLINE_JMP:
                if (code[0] == 0xE9) {
                    // JMP rel32
                    int32_t offset = *(int32_t*)(code + 1);
                    return code + 5 + offset;
                }
                if (code[0] == 0xFF && code[1] == 0x25) {
                    // JMP [addr]
                    void** pTarget = *(void***)(code + 2);
                    return *pTarget;
                }
                break;

            case HOOK_INLINE_PUSH_RET:
                // PUSH addr
                return *(void**)(code + 1);

            case HOOK_HOTPATCH:
                // JMP is 5 bytes before
                {
                    int32_t offset = *(int32_t*)(code - 4);
                    return code - 5 + 5 + offset;
                }

            default:
                break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }

    return nullptr;
}

// Check IAT for hooks
static bool CheckIATHook(HMODULE hModule, const char* functionName, void* expectedAddr) {
    if (!hModule || !functionName) return false;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

    DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) return false;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importRVA);

    while (importDesc->Name != 0) {
        PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);

        while (originalThunk->u1.AddressOfData != 0) {
            if (!(originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + originalThunk->u1.AddressOfData);

                if (_stricmp((char*)importByName->Name, functionName) == 0) {
                    void* currentAddr = (void*)firstThunk->u1.Function;
                    return currentAddr != expectedAddr;
                }
            }

            originalThunk++;
            firstThunk++;
        }

        importDesc++;
    }

    return false;
}

// ============================================================================
// EXPORTED FUNCTIONS
// ============================================================================

AC_API bool AC_CALL AC_HookDetectionInit(void) {
    g_detectedHooks.clear();
    g_hookError[0] = '\0';
    return true;
}

AC_API bool AC_CALL AC_DetectInlineHook(const char* moduleName, const char* functionName,
                                         char* hookDetails, int bufferSize) {
    if (!moduleName || !functionName) {
        strcpy_s(g_hookError, "Invalid parameters");
        return false;
    }

    HMODULE hModule = GetModuleHandleA(moduleName);
    if (!hModule) {
        strcpy_s(g_hookError, "Module not found");
        return false;
    }

    void* funcAddr = GetProcAddress(hModule, functionName);
    if (!funcAddr) {
        strcpy_s(g_hookError, "Function not found");
        return false;
    }

    HookType hookType = DetectInlineHook(funcAddr);
    if (hookType != HOOK_NONE) {
        void* target = GetHookTarget(funcAddr, hookType);

        HookInfo info = {};
        info.type = hookType;
        info.address = funcAddr;
        info.targetAddress = target;
        strncpy_s(info.moduleName, moduleName, _TRUNCATE);
        strncpy_s(info.functionName, functionName, _TRUNCATE);
        g_detectedHooks.push_back(info);

        if (hookDetails && bufferSize > 0) {
            char targetModule[MAX_PATH] = "Unknown";
            GetModuleNameFromAddress(target, targetModule, sizeof(targetModule));

            snprintf(hookDetails, bufferSize,
                     "Inline hook detected: %s!%s -> 0x%p (%s)",
                     moduleName, functionName, target, targetModule);
        }

        return true;
    }

    return false;
}

AC_API bool AC_CALL AC_DetectIATHook(const char* targetModule, const char* importModule,
                                      const char* functionName, char* hookDetails, int bufferSize) {
    if (!targetModule || !importModule || !functionName) {
        strcpy_s(g_hookError, "Invalid parameters");
        return false;
    }

    HMODULE hTarget = GetModuleHandleA(targetModule);
    HMODULE hImport = GetModuleHandleA(importModule);

    if (!hTarget || !hImport) {
        strcpy_s(g_hookError, "Module not found");
        return false;
    }

    void* expectedAddr = GetProcAddress(hImport, functionName);
    if (!expectedAddr) {
        strcpy_s(g_hookError, "Function not found");
        return false;
    }

    if (CheckIATHook(hTarget, functionName, expectedAddr)) {
        if (hookDetails && bufferSize > 0) {
            snprintf(hookDetails, bufferSize,
                     "IAT hook detected: %s imports %s!%s with modified address",
                     targetModule, importModule, functionName);
        }

        HookInfo info = {};
        info.type = HOOK_IAT;
        info.address = expectedAddr;
        strncpy_s(info.moduleName, targetModule, _TRUNCATE);
        strncpy_s(info.functionName, functionName, _TRUNCATE);
        g_detectedHooks.push_back(info);

        return true;
    }

    return false;
}

// Scan common Windows APIs for hooks
AC_API int AC_CALL AC_ScanCommonHooks(char* report, int reportSize) {
    int hookCount = 0;

    // Critical APIs to check
    static const struct {
        const char* module;
        const char* function;
    } criticalAPIs[] = {
        {"kernel32.dll", "LoadLibraryA"},
        {"kernel32.dll", "LoadLibraryW"},
        {"kernel32.dll", "LoadLibraryExA"},
        {"kernel32.dll", "LoadLibraryExW"},
        {"kernel32.dll", "GetProcAddress"},
        {"kernel32.dll", "VirtualAlloc"},
        {"kernel32.dll", "VirtualAllocEx"},
        {"kernel32.dll", "VirtualProtect"},
        {"kernel32.dll", "VirtualProtectEx"},
        {"kernel32.dll", "WriteProcessMemory"},
        {"kernel32.dll", "ReadProcessMemory"},
        {"kernel32.dll", "CreateThread"},
        {"kernel32.dll", "CreateRemoteThread"},
        {"ntdll.dll", "NtQueryInformationProcess"},
        {"ntdll.dll", "NtSetInformationThread"},
        {"ntdll.dll", "NtOpenProcess"},
        {"ntdll.dll", "NtReadVirtualMemory"},
        {"ntdll.dll", "NtWriteVirtualMemory"},
        {"user32.dll", "GetAsyncKeyState"},
        {"user32.dll", "GetKeyState"},
        {"user32.dll", "SendInput"},
        {nullptr, nullptr}
    };

    std::string reportStr;

    for (int i = 0; criticalAPIs[i].module != nullptr; i++) {
        char details[512];
        if (AC_DetectInlineHook(criticalAPIs[i].module, criticalAPIs[i].function,
                                 details, sizeof(details))) {
            hookCount++;
            reportStr += details;
            reportStr += "\n";
        }
    }

    if (report && reportSize > 0 && !reportStr.empty()) {
        strncpy_s(report, reportSize, reportStr.c_str(), _TRUNCATE);
    }

    return hookCount;
}

AC_API int AC_CALL AC_GetDetectedHookCount(void) {
    return static_cast<int>(g_detectedHooks.size());
}

AC_API void AC_CALL AC_ClearDetectedHooks(void) {
    g_detectedHooks.clear();
}

AC_API const char* AC_CALL AC_GetHookError(void) {
    return g_hookError;
}

// Check for VEH (Vectored Exception Handler) abuse
AC_API bool AC_CALL AC_DetectVEHHooks(void) {
    // VEH can be used to intercept exceptions for hooking
    // We check by looking at the VEH chain via NtQueryInformationProcess
    // This is a simplified detection

    typedef LONG(NTAPI* pNtQueryInformationProcess)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) return false;

    // Check if the function is hooked
    char details[256];
    return AC_DetectInlineHook("ntdll.dll", "NtQueryInformationProcess", details, sizeof(details));
}

// Detect hardware breakpoints (used by some debuggers/cheats)
AC_API bool AC_CALL AC_DetectHardwareBreakpoints(void) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx)) {
        return false;
    }

    // Check DR0-DR3 for breakpoint addresses
    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
        return true;
    }

    // Check DR7 for enabled breakpoints
    if (ctx.Dr7 & 0xFF) {
        return true;
    }

    return false;
}
