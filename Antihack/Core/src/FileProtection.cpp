/**
 * AntiCheatCore - File Protection Implementation
 * CRC32 integrity verification with monitoring
 */

#include "stdafx.h"
#include "../include/internal/FileProtection.h"
#include <fstream>
#include <sstream>

namespace AntiCheat {

// CRC32 lookup table
static uint32_t s_CRC32Table[256];
static bool s_CRC32Initialized = false;

static void InitCRC32Table() {
    if (s_CRC32Initialized) return;

    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        s_CRC32Table[i] = crc;
    }
    s_CRC32Initialized = true;
}

static uint32_t CalculateCRC32(const void* data, size_t size) {
    InitCRC32Table();
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < size; i++) {
        crc = s_CRC32Table[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }

    return crc ^ 0xFFFFFFFF;
}

FileProtection::FileProtection()
    : m_monitorThread(NULL)
    , m_monitorInterval(5000)
    , m_initialized(false) {
    // Get base path from current module
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    PathRemoveFileSpecW(exePath);
    m_basePath = exePath;
}

FileProtection::~FileProtection() {
    Shutdown();
}

bool FileProtection::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_lastError.clear();
    m_initialized = true;
    return true;
}

void FileProtection::Shutdown() {
    StopMonitoring();
    std::lock_guard<std::mutex> lock(m_mutex);
    m_protectedFiles.clear();
    m_initialized = false;
}

void FileProtection::SetBasePath(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_basePath = path;
}

void FileProtection::SetDetectionCallback(DetectionCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_callback = callback;
}

std::wstring FileProtection::GetFullPath(const std::wstring& relativePath) {
    wchar_t fullPath[MAX_PATH];
    if (!PathCombineW(fullPath, m_basePath.c_str(), relativePath.c_str())) {
        return relativePath;
    }
    return std::wstring(fullPath);
}

bool FileProtection::AddProtectedFile(const std::wstring& path, bool calculateHash) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::wstring fullPath = GetFullPath(path);

    // Check if file exists
    WIN32_FILE_ATTRIBUTE_DATA fileData;
    if (!GetFileAttributesExW(fullPath.c_str(), GetFileExInfoStandard, &fileData)) {
        m_lastError = "File not found";
        return false;
    }

    FileInfo info;
    info.path = fullPath;
    info.relativePath = path;
    info.expectedSize = ((uint64_t)fileData.nFileSizeHigh << 32) | fileData.nFileSizeLow;
    info.lastModified = fileData.ftLastWriteTime;
    info.isRequired = true;
    info.verified = false;
    info.lastCheckTime = 0;

    if (calculateHash) {
        info.expectedCRC = CalculateFileCRC(fullPath);
    } else {
        info.expectedCRC = 0;
    }

    m_protectedFiles[fullPath] = info;
    return true;
}

bool FileProtection::AddProtectedFile(const std::wstring& path, uint32_t expectedCRC, uint64_t expectedSize) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::wstring fullPath = GetFullPath(path);

    FileInfo info;
    info.path = fullPath;
    info.relativePath = path;
    info.expectedCRC = expectedCRC;
    info.expectedSize = expectedSize;
    info.isRequired = true;
    info.verified = false;
    info.lastCheckTime = 0;
    ZeroMemory(&info.lastModified, sizeof(FILETIME));

    m_protectedFiles[fullPath] = info;
    return true;
}

bool FileProtection::RemoveProtectedFile(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::wstring fullPath = GetFullPath(path);
    auto it = m_protectedFiles.find(fullPath);
    if (it != m_protectedFiles.end()) {
        m_protectedFiles.erase(it);
        return true;
    }
    return false;
}

void FileProtection::ClearProtectedFiles() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_protectedFiles.clear();
}

bool FileProtection::VerifyFile(const std::wstring& path, VerificationResult& result) {
    std::wstring fullPath = GetFullPath(path);

    result.path = fullPath;
    result.passed = false;
    result.errorMessage.clear();

    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_protectedFiles.find(fullPath);
    if (it == m_protectedFiles.end()) {
        result.errorMessage = "File not in protected list";
        return false;
    }

    FileInfo& info = it->second;
    result.expectedCRC = info.expectedCRC;
    result.expectedSize = info.expectedSize;

    // Get current file info
    WIN32_FILE_ATTRIBUTE_DATA fileData;
    if (!GetFileAttributesExW(fullPath.c_str(), GetFileExInfoStandard, &fileData)) {
        result.errorMessage = "Cannot access file";
        result.currentCRC = 0;
        result.currentSize = 0;
        return false;
    }

    result.currentSize = ((uint64_t)fileData.nFileSizeHigh << 32) | fileData.nFileSizeLow;

    // Check size if expected
    if (info.expectedSize > 0 && result.currentSize != info.expectedSize) {
        result.errorMessage = "File size mismatch";
        info.verified = false;

        if (m_callback) {
            DetectionEvent event;
            event.type = DetectionType::FileModified;
            event.severity = info.isRequired ? Severity::Critical : Severity::Warning;
            event.description = "File size changed: " + std::string(fullPath.begin(), fullPath.end());
            event.moduleName = "";
            event.address = nullptr;
            event.timestamp = GetTickCount();
            m_callback(event);
        }

        if (m_violationCallback) {
            m_violationCallback(result);
        }

        return false;
    }

    // Calculate current CRC
    result.currentCRC = CalculateFileCRC(fullPath);

    if (result.currentCRC != info.expectedCRC) {
        result.errorMessage = "CRC mismatch";
        info.verified = false;

        if (m_callback) {
            DetectionEvent event;
            event.type = DetectionType::FileModified;
            event.severity = info.isRequired ? Severity::Critical : Severity::Warning;
            event.description = "File CRC mismatch: " + std::string(fullPath.begin(), fullPath.end());
            event.moduleName = "";
            event.address = nullptr;
            event.timestamp = GetTickCount();
            m_callback(event);
        }

        if (m_violationCallback) {
            m_violationCallback(result);
        }

        return false;
    }

    info.verified = true;
    info.lastCheckTime = GetTickCount64();
    result.passed = true;
    return true;
}

bool FileProtection::VerifyAllFiles(std::vector<VerificationResult>& results) {
    results.clear();
    bool allPassed = true;

    std::vector<std::wstring> paths;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& pair : m_protectedFiles) {
            paths.push_back(pair.first);
        }
    }

    for (const auto& path : paths) {
        VerificationResult result;
        if (!VerifyFile(path, result)) {
            allPassed = false;
        }
        results.push_back(result);
    }

    return allPassed;
}

uint32_t FileProtection::CalculateFileCRC(const std::wstring& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return 0;
    }

    size_t fileSize = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(fileSize);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
        return 0;
    }

    return CalculateCRC32(buffer.data(), buffer.size());
}

bool FileProtection::LoadConfig(const std::wstring& configPath) {
    std::wifstream config(configPath);
    if (!config.is_open()) {
        m_lastError = "Cannot open configuration file";
        return false;
    }

    std::wstring line;
    while (std::getline(config, line)) {
        if (line.empty() || line[0] == L'#') continue;

        std::wistringstream iss(line);
        std::wstring relativePath;
        std::wstring crcHex;
        std::wstring sizeStr;

        if (std::getline(iss, relativePath, L',') &&
            std::getline(iss, crcHex, L',') &&
            std::getline(iss, sizeStr)) {

            uint32_t crc = 0;
            uint64_t size = 0;

            std::wstringstream ss;
            ss << std::hex << crcHex;
            ss >> crc;

            std::wstringstream ss2;
            ss2 << sizeStr;
            ss2 >> size;

            AddProtectedFile(relativePath, crc, size);
        }
    }

    return true;
}

bool FileProtection::SaveConfig(const std::wstring& configPath) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::wofstream outFile(configPath);
    if (!outFile.is_open()) {
        m_lastError = "Cannot create configuration file";
        return false;
    }

    outFile << L"# AntiCheat File Protection Configuration\n";
    outFile << L"# Format: relative_path,crc32_hex,size\n\n";

    for (const auto& pair : m_protectedFiles) {
        const FileInfo& info = pair.second;
        outFile << info.relativePath << L","
                << std::hex << std::uppercase << info.expectedCRC << L","
                << std::dec << info.expectedSize << std::endl;
    }

    return true;
}

DWORD WINAPI FileProtection::MonitorThreadProc(LPVOID param) {
    FileProtection* self = static_cast<FileProtection*>(param);
    self->MonitorLoop();
    return 0;
}

void FileProtection::MonitorLoop() {
    while (m_monitoring) {
        std::vector<VerificationResult> results;
        VerifyAllFiles(results);
        Sleep(m_monitorInterval);
    }
}

bool FileProtection::StartMonitoring(DWORD intervalMs) {
    if (m_monitoring) return true;

    m_monitorInterval = intervalMs;
    m_monitoring = true;

    m_monitorThread = CreateThread(NULL, 0, MonitorThreadProc, this, 0, NULL);
    if (!m_monitorThread) {
        m_monitoring = false;
        m_lastError = "Failed to create monitor thread";
        return false;
    }

    return true;
}

void FileProtection::StopMonitoring() {
    if (!m_monitoring) return;

    m_monitoring = false;

    if (m_monitorThread) {
        WaitForSingleObject(m_monitorThread, 5000);
        CloseHandle(m_monitorThread);
        m_monitorThread = NULL;
    }
}

int FileProtection::ProtectDirectory(const std::wstring& dirPath, const std::wstring& pattern, bool recursive) {
    std::wstring fullDir = GetFullPath(dirPath);
    std::wstring searchPath = fullDir + L"\\" + pattern;

    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return 0;
    }

    int count = 0;
    do {
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) {
            continue;
        }

        std::wstring relativePath = dirPath + L"\\" + findData.cFileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (recursive) {
                count += ProtectDirectory(relativePath, pattern, true);
            }
        } else {
            if (AddProtectedFile(relativePath, true)) {
                count++;
            }
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
    return count;
}

FileProtection::FileInfo FileProtection::GetFileInfo(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::wstring fullPath = GetFullPath(path);
    auto it = m_protectedFiles.find(fullPath);
    if (it != m_protectedFiles.end()) {
        return it->second;
    }

    return FileInfo();
}

std::vector<std::wstring> FileProtection::GetProtectedFiles() {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::vector<std::wstring> files;
    for (const auto& pair : m_protectedFiles) {
        files.push_back(pair.second.relativePath);
    }
    return files;
}

} // namespace AntiCheat
