/**
 * AntiCheatCore - Process Detection Module
 * Scans for blacklisted processes and suspicious activity
 */

#include "../include/anticheat_core.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>

// Internal blacklist storage
static std::vector<std::string> g_Blacklist;
static char g_LastError[256] = {0};

// Debugger process names
static const char* g_DebuggerProcesses[] = {
    "ollydbg", "x64dbg", "x32dbg", "windbg", "idaq", "idaq64",
    "ida", "ida64", "radare2", "dnspy", "cheatengine",
    "processhacker", "procexp", "procexp64", "procmon",
    "wireshark", "fiddler", "httpdebugger", nullptr
};

// Helper: Convert string to lowercase
static std::string ToLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return result;
}

// Helper: Get process name without extension
static std::string GetProcessBaseName(const std::string& name) {
    std::string result = name;
    size_t pos = result.rfind('.');
    if (pos != std::string::npos) {
        result = result.substr(0, pos);
    }
    return ToLower(result);
}

extern "C" {

AC_API bool AC_CALL AC_ScanProcesses(char* detected_name, int buffer_size) {
    if (!detected_name || buffer_size < 1) {
        strcpy_s(g_LastError, "Invalid buffer");
        return false;
    }

    detected_name[0] = '\0';

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        strcpy_s(g_LastError, "Failed to create process snapshot");
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    bool found = false;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            // Convert wide string to narrow
            char processName[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1,
                processName, MAX_PATH, nullptr, nullptr);

            std::string baseName = GetProcessBaseName(processName);

            // Check against blacklist
            for (const auto& blacklisted : g_Blacklist) {
                if (baseName == ToLower(blacklisted)) {
                    strncpy_s(detected_name, buffer_size, processName, _TRUNCATE);
                    found = true;
                    break;
                }
            }

            if (found) break;

        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return found;
}

AC_API bool AC_CALL AC_AddToBlacklist(const char* process_name) {
    if (!process_name || strlen(process_name) == 0) {
        strcpy_s(g_LastError, "Invalid process name");
        return false;
    }

    std::string name = ToLower(process_name);

    // Check if already in list
    for (const auto& existing : g_Blacklist) {
        if (ToLower(existing) == name) {
            return true; // Already exists
        }
    }

    g_Blacklist.push_back(process_name);
    return true;
}

AC_API void AC_CALL AC_ClearBlacklist(void) {
    g_Blacklist.clear();
}

AC_API int AC_CALL AC_GetBlacklistCount(void) {
    return static_cast<int>(g_Blacklist.size());
}

AC_API bool AC_CALL AC_DetectDebuggerProcess(char* debugger_name, int buffer_size) {
    if (!debugger_name || buffer_size < 1) {
        return false;
    }

    debugger_name[0] = '\0';

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    bool found = false;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            char processName[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1,
                processName, MAX_PATH, nullptr, nullptr);

            std::string baseName = GetProcessBaseName(processName);

            for (int i = 0; g_DebuggerProcesses[i] != nullptr; i++) {
                if (baseName == g_DebuggerProcesses[i]) {
                    strncpy_s(debugger_name, buffer_size, processName, _TRUNCATE);
                    found = true;
                    break;
                }
            }

            if (found) break;

        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return found;
}

} // extern "C"
