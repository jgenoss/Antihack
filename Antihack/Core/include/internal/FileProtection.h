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
        uint32_t expectedCRC;
        uint64_t expectedSize;
        FILETIME lastModified;
        bool isRequired;
        bool verified;
        uint64_t lastCheckTime;
    };

    struct VerificationResult {
        std::wstring path;
        bool passed;
        uint32_t expectedCRC;
        uint32_t currentCRC;
        uint64_t expectedSize;
        uint64_t currentSize;
        std::string errorMessage;
    };

    using ViolationCallback = std::function<void(const VerificationResult&)>;

private:
    std::map<std::wstring, FileInfo> m_protectedFiles;
    std::wstring m_basePath;
    std::mutex m_mutex;
    std::atomic<bool> m_monitoring{false};
    HANDLE m_monitorThread;
    DWORD m_monitorInterval;
    DetectionCallback m_callback;
    ViolationCallback m_violationCallback;
    std::string m_lastError;
    bool m_initialized;

    static DWORD WINAPI MonitorThreadProc(LPVOID param);
    void MonitorLoop();
    std::wstring GetFullPath(const std::wstring& relativePath);

public:
    FileProtection();
    ~FileProtection();

    // Initialization
    bool Initialize();
    void Shutdown();
    void SetBasePath(const std::wstring& path);
    void SetDetectionCallback(DetectionCallback callback);
    void SetViolationCallback(ViolationCallback callback) { m_violationCallback = callback; }

    // File protection
    bool AddProtectedFile(const std::wstring& path, bool calculateHash = true);
    bool AddProtectedFile(const std::wstring& path, uint32_t expectedCRC, uint64_t expectedSize = 0);
    bool RemoveProtectedFile(const std::wstring& path);
    void ClearProtectedFiles();

    // Verification
    bool VerifyFile(const std::wstring& path, VerificationResult& result);
    bool VerifyAllFiles(std::vector<VerificationResult>& results);
    uint32_t CalculateFileCRC(const std::wstring& path);

    // Configuration
    bool LoadConfig(const std::wstring& configPath);
    bool SaveConfig(const std::wstring& configPath);

    // Monitoring
    bool StartMonitoring(DWORD intervalMs = 5000);
    void StopMonitoring();
    bool IsMonitoring() const { return m_monitoring; }

    // Directory protection
    int ProtectDirectory(const std::wstring& dirPath, const std::wstring& pattern = L"*.*", bool recursive = false);

    // Getters
    FileInfo GetFileInfo(const std::wstring& path);
    std::vector<std::wstring> GetProtectedFiles();
    int GetProtectedFileCount() const { return static_cast<int>(m_protectedFiles.size()); }
    const std::string& GetLastError() const { return m_lastError; }
    const std::wstring& GetBasePath() const { return m_basePath; }
    bool IsInitialized() const { return m_initialized; }
};

} // namespace AntiCheat

#endif // AC_FILE_PROTECTION_H
