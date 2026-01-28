/**
 * AntiCheatCore - Main Module
 * Core initialization and HWID generation
 */

#define ANTICHEATCORE_EXPORTS
#include "../include/anticheat_core.h"
#include <windows.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <sddl.h>
#include <string>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "iphlpapi.lib")

#define AC_VERSION "1.0.0"

static bool g_Initialized = false;
static char g_LastError[256] = {0};
static AC_DetectionCallback g_DetectionCallback = nullptr;

// Forward declarations from other modules
extern "C" bool AC_CALL AC_ScanProcesses(char* detected_name, int buffer_size);
extern "C" uint32_t AC_CALL AC_DetectDebugger(void);

// Helper: Generate MD5-like hash string from data
static std::string HashToString(uint8_t* data, size_t len) {
    std::stringstream ss;
    for (size_t i = 0; i < len && i < 16; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    }
    return ss.str();
}

// Get CPU ID
static std::string GetCPUID() {
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    ss << std::setw(8) << cpuInfo[1];
    ss << std::setw(8) << cpuInfo[3];
    ss << std::setw(8) << cpuInfo[2];

    return ss.str();
}

// Get Volume Serial Number
static std::string GetVolumeSerial() {
    DWORD serialNumber = 0;
    if (GetVolumeInformationW(L"C:\\", nullptr, 0, &serialNumber,
                              nullptr, nullptr, nullptr, 0)) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0') << std::setw(8) << serialNumber;
        return ss.str();
    }
    return "00000000";
}

// Get MAC Address
static std::string GetMACAddress() {
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufLen = sizeof(adapterInfo);

    if (GetAdaptersInfo(adapterInfo, &bufLen) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO adapter = adapterInfo;
        while (adapter) {
            // Skip virtual adapters
            if (adapter->Type == MIB_IF_TYPE_ETHERNET ||
                adapter->Type == IF_TYPE_IEEE80211) {
                std::stringstream ss;
                for (UINT i = 0; i < adapter->AddressLength; i++) {
                    if (i > 0) ss << ":";
                    ss << std::hex << std::setfill('0') << std::setw(2)
                       << (int)adapter->Address[i];
                }
                return ss.str();
            }
            adapter = adapter->Next;
        }
    }
    return "00:00:00:00:00:00";
}

// Get Machine GUID from registry
static std::string GetMachineGUID() {
    HKEY hKey;
    char guid[64] = {0};
    DWORD size = sizeof(guid);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Cryptography",
        0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {

        RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr,
            (LPBYTE)guid, &size);
        RegCloseKey(hKey);
    }

    return std::string(guid);
}

extern "C" {

AC_API bool AC_CALL AC_Initialize(void) {
    if (g_Initialized) {
        return true;
    }

    // Initialize any required resources
    g_Initialized = true;
    strcpy_s(g_LastError, "OK");

    return true;
}

AC_API void AC_CALL AC_Shutdown(void) {
    if (!g_Initialized) {
        return;
    }

    // Cleanup resources
    g_DetectionCallback = nullptr;
    g_Initialized = false;
}

AC_API const char* AC_CALL AC_GetVersion(void) {
    return AC_VERSION;
}

AC_API bool AC_CALL AC_GenerateHWID(char* hwid_buffer, int buffer_size) {
    if (!hwid_buffer || buffer_size < 64) {
        strcpy_s(g_LastError, "Buffer too small");
        return false;
    }

    try {
        // Combine multiple hardware identifiers
        std::string cpuid = GetCPUID();
        std::string volumeSerial = GetVolumeSerial();
        std::string macAddress = GetMACAddress();
        std::string machineGuid = GetMachineGUID();

        // Create combined string
        std::string combined = cpuid + volumeSerial + macAddress + machineGuid;

        // Simple hash (in production, use proper crypto hash)
        uint32_t hash = 0;
        for (char c : combined) {
            hash = hash * 31 + c;
        }

        // Format HWID
        std::stringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0');
        ss << std::setw(8) << hash;
        ss << "-" << cpuid.substr(0, 8);
        ss << "-" << volumeSerial;
        ss << "-" << std::setw(8) << (hash ^ 0xDEADBEEF);

        std::string hwid = ss.str();
        strncpy_s(hwid_buffer, buffer_size, hwid.c_str(), _TRUNCATE);

        return true;
    }
    catch (...) {
        strcpy_s(g_LastError, "HWID generation failed");
        return false;
    }
}

AC_API bool AC_CALL AC_InstallHooks(void) {
    // Placeholder - implement actual API hooking here
    // In production, use Microsoft Detours or similar library
    return true;
}

AC_API void AC_CALL AC_RemoveHooks(void) {
    // Placeholder - remove hooks here
}

AC_API void AC_CALL AC_SetDetectionCallback(AC_DetectionCallback callback) {
    g_DetectionCallback = callback;
}

AC_API const char* AC_CALL AC_GetLastError(void) {
    return g_LastError;
}

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            break;
        case DLL_PROCESS_DETACH:
            AC_Shutdown();
            break;
    }
    return TRUE;
}

} // extern "C"
