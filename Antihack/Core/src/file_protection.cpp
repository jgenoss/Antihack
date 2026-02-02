/**
 * File Protection Module
 * Protects game files from tampering and unauthorized access
 */

#include "../include/anticheat_core.h"
#include <Windows.h>
#include <vector>
#include <string>
#include <map>
#include <fstream>

// File integrity record
struct FileRecord {
    std::wstring path;
    uint32_t hash;
    DWORD size;
    FILETIME lastModified;
};

static std::map<std::wstring, FileRecord> g_protectedFiles;
static char g_fileProtectionError[512] = "";
static bool g_monitoringActive = false;
static HANDLE g_monitorThread = NULL;
static volatile bool g_stopMonitoring = false;

// Calculate file hash
static uint32_t CalculateFileHash(const wchar_t* filePath) {
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return 0;
    }

    // Limit to 10MB for performance
    DWORD readSize = min(fileSize, 10 * 1024 * 1024);
    std::vector<BYTE> buffer(readSize);
    DWORD bytesRead = 0;

    if (!ReadFile(hFile, buffer.data(), readSize, &bytesRead, NULL)) {
        CloseHandle(hFile);
        return 0;
    }

    CloseHandle(hFile);

    // CRC32 calculation
    uint32_t crc = 0xFFFFFFFF;
    for (DWORD i = 0; i < bytesRead; i++) {
        crc ^= buffer[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }

    return ~crc;
}

// Get file info
static bool GetFileInfo(const wchar_t* filePath, DWORD* size, FILETIME* modTime) {
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (!GetFileAttributesExW(filePath, GetFileExInfoStandard, &fileInfo)) {
        return false;
    }

    if (size) *size = fileInfo.nFileSizeLow;
    if (modTime) *modTime = fileInfo.ftLastWriteTime;
    return true;
}

// File monitoring thread
static DWORD WINAPI FileMonitorThread(LPVOID param) {
    while (!g_stopMonitoring) {
        for (auto& pair : g_protectedFiles) {
            FileRecord& record = pair.second;

            DWORD currentSize = 0;
            FILETIME currentModTime = { 0 };

            if (GetFileInfo(record.path.c_str(), &currentSize, &currentModTime)) {
                // Check if file was modified
                if (currentSize != record.size ||
                    CompareFileTime(&currentModTime, &record.lastModified) != 0) {

                    // Recalculate hash
                    uint32_t newHash = CalculateFileHash(record.path.c_str());
                    if (newHash != record.hash) {
                        // File was tampered!
                        char narrowPath[MAX_PATH];
                        WideCharToMultiByte(CP_UTF8, 0, record.path.c_str(), -1,
                                          narrowPath, MAX_PATH, NULL, NULL);

                        // Report via IPC if available
                        AC_IpcReportDetection("FILE_TAMPERED", narrowPath);
                    }
                }
            }
        }

        Sleep(5000); // Check every 5 seconds
    }
    return 0;
}

// ============================================================================
// EXPORTED FUNCTIONS
// ============================================================================

AC_API bool AC_CALL AC_FileProtectionInit(void) {
    g_protectedFiles.clear();
    g_fileProtectionError[0] = '\0';
    g_stopMonitoring = false;
    return true;
}

AC_API void AC_CALL AC_FileProtectionShutdown(void) {
    g_stopMonitoring = true;
    if (g_monitorThread) {
        WaitForSingleObject(g_monitorThread, 3000);
        CloseHandle(g_monitorThread);
        g_monitorThread = NULL;
    }
    g_protectedFiles.clear();
    g_monitoringActive = false;
}

AC_API bool AC_CALL AC_ProtectFile(const wchar_t* filePath) {
    if (!filePath) {
        strcpy_s(g_fileProtectionError, "Invalid file path");
        return false;
    }

    // Check if file exists
    DWORD attrs = GetFileAttributesW(filePath);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        strcpy_s(g_fileProtectionError, "File not found");
        return false;
    }

    FileRecord record;
    record.path = filePath;
    record.hash = CalculateFileHash(filePath);

    if (record.hash == 0) {
        strcpy_s(g_fileProtectionError, "Failed to calculate file hash");
        return false;
    }

    if (!GetFileInfo(filePath, &record.size, &record.lastModified)) {
        strcpy_s(g_fileProtectionError, "Failed to get file info");
        return false;
    }

    g_protectedFiles[filePath] = record;
    return true;
}

AC_API bool AC_CALL AC_ProtectFileA(const char* filePath) {
    if (!filePath) return false;

    wchar_t widePath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, filePath, -1, widePath, MAX_PATH);
    return AC_ProtectFile(widePath);
}

AC_API bool AC_CALL AC_UnprotectFile(const wchar_t* filePath) {
    auto it = g_protectedFiles.find(filePath);
    if (it != g_protectedFiles.end()) {
        g_protectedFiles.erase(it);
        return true;
    }
    return false;
}

AC_API bool AC_CALL AC_VerifyFileIntegrity(const wchar_t* filePath) {
    auto it = g_protectedFiles.find(filePath);
    if (it == g_protectedFiles.end()) {
        strcpy_s(g_fileProtectionError, "File not in protection list");
        return false;
    }

    uint32_t currentHash = CalculateFileHash(filePath);
    if (currentHash != it->second.hash) {
        strcpy_s(g_fileProtectionError, "File integrity check failed - hash mismatch");
        return false;
    }

    return true;
}

AC_API bool AC_CALL AC_VerifyAllFiles(char* failedFile, int bufferSize) {
    for (const auto& pair : g_protectedFiles) {
        uint32_t currentHash = CalculateFileHash(pair.first.c_str());
        if (currentHash != pair.second.hash) {
            if (failedFile && bufferSize > 0) {
                WideCharToMultiByte(CP_UTF8, 0, pair.first.c_str(), -1,
                                  failedFile, bufferSize, NULL, NULL);
            }
            return false;
        }
    }
    return true;
}

AC_API bool AC_CALL AC_StartFileMonitoring(void) {
    if (g_monitoringActive) {
        return true; // Already running
    }

    g_stopMonitoring = false;
    g_monitorThread = CreateThread(NULL, 0, FileMonitorThread, NULL, 0, NULL);

    if (g_monitorThread == NULL) {
        strcpy_s(g_fileProtectionError, "Failed to start monitor thread");
        return false;
    }

    g_monitoringActive = true;
    return true;
}

AC_API void AC_CALL AC_StopFileMonitoring(void) {
    g_stopMonitoring = true;
    if (g_monitorThread) {
        WaitForSingleObject(g_monitorThread, 3000);
        CloseHandle(g_monitorThread);
        g_monitorThread = NULL;
    }
    g_monitoringActive = false;
}

AC_API int AC_CALL AC_GetProtectedFileCount(void) {
    return static_cast<int>(g_protectedFiles.size());
}

AC_API uint32_t AC_CALL AC_GetFileHash(const wchar_t* filePath) {
    return CalculateFileHash(filePath);
}

AC_API uint32_t AC_CALL AC_GetFileHashA(const char* filePath) {
    if (!filePath) return 0;

    wchar_t widePath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, filePath, -1, widePath, MAX_PATH);
    return CalculateFileHash(widePath);
}

AC_API const char* AC_CALL AC_GetFileProtectionError(void) {
    return g_fileProtectionError;
}

// Protect directory recursively
AC_API int AC_CALL AC_ProtectDirectory(const wchar_t* dirPath, const wchar_t* pattern) {
    if (!dirPath) return 0;

    std::wstring searchPath = dirPath;
    searchPath += L"\\";
    searchPath += (pattern ? pattern : L"*.*");

    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return 0;
    }

    int count = 0;
    do {
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::wstring fullPath = dirPath;
            fullPath += L"\\";
            fullPath += findData.cFileName;

            if (AC_ProtectFile(fullPath.c_str())) {
                count++;
            }
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
    return count;
}
