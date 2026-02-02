/**
 * AntiCheatCore - File Protection Module
 * Protects game files from tampering
 */

#pragma once

#ifndef AC_FILE_PROTECTION_H
#define AC_FILE_PROTECTION_H

#include "common.h"
#include <fstream>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

namespace AntiCheat {

class FileProtection {
public:
    struct FileInfo {
        std::wstring path;
        std::wstring relativePath;
        uint32_t expectedCrc;
        DWORD fileSize;
        FILETIME lastModified;
        bool isRequired;
        bool isVerified;
    };

private:
    std::vector<FileInfo> m_protectedFiles;
    std::wstring m_basePath;
    std::mutex m_mutex;
    std::atomic<bool> m_monitorRunning{false};
    HANDLE m_monitorThread = nullptr;
    DetectionCallback m_callback;
    std::string m_lastError;

    static DWORD WINAPI MonitorThreadProc(LPVOID param);
    void MonitorLoop();
    ByteVector ReadFileBytes(const std::wstring& path);
    std::wstring GetFullPath(const std::wstring& relativePath);

public:
    FileProtection();
    ~FileProtection();

    // Initialization
    bool Initialize();
    void Shutdown();
    void SetBasePath(const std::wstring& path);
    void SetDetectionCallback(DetectionCallback callback);

    // File protection
    bool AddProtectedFile(const std::wstring& relativePath, uint32_t expectedCrc, bool isRequired = true);
    bool AddProtectedFile(const std::wstring& relativePath, bool isRequired = true);
    bool RemoveProtectedFile(const std::wstring& relativePath);
    void ClearProtectedFiles();

    // Verification
    bool VerifyFile(const std::wstring& relativePath);
    bool VerifyAllFiles(std::wstring* failedFile = nullptr);
    uint32_t CalculateFileCRC(const std::wstring& path);

    // Configuration
    bool LoadConfiguration(const std::wstring& configPath);
    bool SaveConfiguration(const std::wstring& configPath);

    // Monitoring
    bool StartMonitoring();
    void StopMonitoring();
    bool IsMonitoring() const { return m_monitorRunning; }

    // Directory protection
    int ProtectDirectory(const std::wstring& dirPath, const std::wstring& pattern = L"*.*");

    // Getters
    int GetProtectedFileCount() const { return static_cast<int>(m_protectedFiles.size()); }
    const std::string& GetLastError() const { return m_lastError; }
    const std::wstring& GetBasePath() const { return m_basePath; }
};

} // namespace AntiCheat

#endif // AC_FILE_PROTECTION_H
