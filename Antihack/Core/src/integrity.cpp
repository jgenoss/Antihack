/**
 * AntiCheatCore - Memory Integrity Module
 * Verifies code integrity and detects injected DLLs
 */

#include "../include/anticheat_core.h"
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <algorithm>

// CRC32 lookup table
static uint32_t g_CRC32Table[256];
static bool g_CRC32Initialized = false;

// Known legitimate DLLs (system DLLs)
static const wchar_t* g_TrustedDlls[] = {
    L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll",
    L"user32.dll", L"gdi32.dll", L"advapi32.dll",
    L"shell32.dll", L"ole32.dll", L"oleaut32.dll",
    L"msvcrt.dll", L"ucrtbase.dll", L"vcruntime",
    L"msvcp", L"combase.dll", L"rpcrt4.dll",
    L"sechost.dll", L"bcrypt.dll", L"crypt32.dll",
    L"ws2_32.dll", L"winhttp.dll", L"wininet.dll",
    L"clr.dll", L"clrjit.dll", L"mscorlib",
    nullptr
};

// Suspicious DLL patterns
static const wchar_t* g_SuspiciousDllPatterns[] = {
    L"inject", L"hack", L"cheat", L"hook",
    L"trainer", L"mod", L"bypass", L"loader",
    nullptr
};

// Initialize CRC32 table
static void InitCRC32Table() {
    if (g_CRC32Initialized) return;

    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        g_CRC32Table[i] = crc;
    }
    g_CRC32Initialized = true;
}

extern "C" {

AC_API uint32_t AC_CALL AC_HashMemory(void* address, size_t size) {
    if (!address || size == 0) {
        return 0;
    }

    InitCRC32Table();

    uint32_t crc = 0xFFFFFFFF;
    uint8_t* data = (uint8_t*)address;

    for (size_t i = 0; i < size; i++) {
        crc = g_CRC32Table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }

    return ~crc;
}

AC_API bool AC_CALL AC_VerifyModuleIntegrity(const char* module_name, uint32_t expected_hash) {
    if (!module_name) {
        return false;
    }

    // Convert to wide string
    wchar_t wModuleName[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, module_name, -1, wModuleName, MAX_PATH);

    HMODULE hModule = GetModuleHandleW(wModuleName);
    if (!hModule) {
        return false;
    }

    // Get module info
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        return false;
    }

    // Calculate hash of the module's code section
    // Note: In production, you'd parse PE headers to find .text section
    uint32_t actualHash = AC_HashMemory(modInfo.lpBaseOfDll, modInfo.SizeOfImage);

    return actualHash == expected_hash;
}

// Helper: Check if DLL name contains suspicious pattern
static bool IsSuspiciousDllName(const wchar_t* dllName) {
    std::wstring name(dllName);
    std::transform(name.begin(), name.end(), name.begin(), ::towlower);

    for (int i = 0; g_SuspiciousDllPatterns[i] != nullptr; i++) {
        if (name.find(g_SuspiciousDllPatterns[i]) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

// Helper: Check if DLL is in trusted list
static bool IsTrustedDll(const wchar_t* dllName) {
    std::wstring name(dllName);
    std::transform(name.begin(), name.end(), name.begin(), ::towlower);

    // Check system directory
    wchar_t systemDir[MAX_PATH];
    GetSystemDirectoryW(systemDir, MAX_PATH);
    std::wstring sysDir(systemDir);
    std::transform(sysDir.begin(), sysDir.end(), sysDir.begin(), ::towlower);

    // Check Windows directory
    wchar_t winDir[MAX_PATH];
    GetWindowsDirectoryW(winDir, MAX_PATH);
    std::wstring windowsDir(winDir);
    std::transform(windowsDir.begin(), windowsDir.end(), windowsDir.begin(), ::towlower);

    // If in system directories, likely trusted
    if (name.find(sysDir) != std::wstring::npos ||
        name.find(windowsDir) != std::wstring::npos) {
        return true;
    }

    // Check against known trusted DLLs
    for (int i = 0; g_TrustedDlls[i] != nullptr; i++) {
        if (name.find(g_TrustedDlls[i]) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

AC_API bool AC_CALL AC_ScanForInjectedDlls(char* injected_dll, int buffer_size) {
    if (!injected_dll || buffer_size < 1) {
        return false;
    }

    injected_dll[0] = '\0';

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (!EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        return false;
    }

    int moduleCount = cbNeeded / sizeof(HMODULE);

    for (int i = 0; i < moduleCount; i++) {
        wchar_t modulePath[MAX_PATH];
        if (GetModuleFileNameExW(GetCurrentProcess(), hMods[i], modulePath, MAX_PATH)) {

            // Skip trusted DLLs
            if (IsTrustedDll(modulePath)) {
                continue;
            }

            // Check for suspicious names
            if (IsSuspiciousDllName(modulePath)) {
                WideCharToMultiByte(CP_UTF8, 0, modulePath, -1,
                    injected_dll, buffer_size, nullptr, nullptr);
                return true;
            }

            // Check if DLL was loaded from temp directory (suspicious)
            wchar_t tempPath[MAX_PATH];
            GetTempPathW(MAX_PATH, tempPath);
            std::wstring path(modulePath);
            std::wstring temp(tempPath);
            std::transform(path.begin(), path.end(), path.begin(), ::towlower);
            std::transform(temp.begin(), temp.end(), temp.begin(), ::towlower);

            if (path.find(temp) != std::wstring::npos) {
                WideCharToMultiByte(CP_UTF8, 0, modulePath, -1,
                    injected_dll, buffer_size, nullptr, nullptr);
                return true;
            }
        }
    }

    return false;
}

// Check if a specific API function is hooked
AC_API bool AC_CALL AC_IsApiHooked(const char* module_name, const char* function_name) {
    if (!module_name || !function_name) {
        return false;
    }

    HMODULE hModule = GetModuleHandleA(module_name);
    if (!hModule) {
        return false;
    }

    void* funcAddr = GetProcAddress(hModule, function_name);
    if (!funcAddr) {
        return false;
    }

    // Check first bytes for common hook patterns
    uint8_t* bytes = (uint8_t*)funcAddr;

    // JMP rel32 (E9 xx xx xx xx)
    if (bytes[0] == 0xE9) {
        return true;
    }

    // JMP [rip+disp32] for 64-bit (FF 25 xx xx xx xx)
    if (bytes[0] == 0xFF && bytes[1] == 0x25) {
        return true;
    }

    // MOV RAX, addr; JMP RAX (48 B8 xx xx xx xx xx xx xx xx FF E0)
    if (bytes[0] == 0x48 && bytes[1] == 0xB8) {
        return true;
    }

    // PUSH addr; RET (68 xx xx xx xx C3)
    if (bytes[0] == 0x68 && bytes[5] == 0xC3) {
        return true;
    }

    return false;
}

} // extern "C"
