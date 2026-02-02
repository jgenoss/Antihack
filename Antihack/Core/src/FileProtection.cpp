/**
 * AntiCheatCore - File Protection Implementation
 * CRC32 integrity verification with monitoring
 */

#include "../include/internal/FileProtection.h"
#include <fstream>
#include <sstream>

namespace AntiCheat {

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

FileProtection::FileProtection()
    : m_monitorRunning(false), m_monitorThread(nullptr) {
    // Get base path from current module
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    PathRemoveFileSpecW(exePath);
    m_basePath = exePath;
}

FileProtection::~FileProtection() {
    Shutdown();
}

// ============================================================================
// INITIALIZATION
// ============================================================================

bool FileProtection::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_lastError.clear();
    return true;
}

void FileProtection::Shutdown() {
    StopMonitoring();
    std::lock_guard<std::mutex> lock(m_mutex);
    m_protectedFiles.clear();
}

void FileProtection::SetBasePath(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_basePath = path;
}

void FileProtection::SetDetectionCallback(DetectionCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_callback = callback;
}

// ============================================================================
// FILE PROTECTION
// ============================================================================

bool FileProtection::AddProtectedFile(const std::wstring& relativePath, uint32_t expectedCrc, bool isRequired) {
    std::lock_guard<std::mutex> lock(m_mutex);

    try {
        std::wstring fullPath = GetFullPath(relativePath);

        FileInfo info;
        info.path = fullPath;
        info.relativePath = relativePath;
        info.expectedCrc = expectedCrc;
        info.isRequired = isRequired;
        info.isVerified = false;

        // Get file attributes
        WIN32_FILE_ATTRIBUTE_DATA fileData;
        if (GetFileAttributesExW(fullPath.c_str(), GetFileExInfoStandard, &fileData)) {
            info.fileSize = fileData.nFileSizeLow;
            info.lastModified = fileData.ftLastWriteTime;
        }

        m_protectedFiles.push_back(info);
        return true;
    }
    catch (const std::exception& e) {
        m_lastError = e.what();
        return false;
    }
}

bool FileProtection::AddProtectedFile(const std::wstring& relativePath, bool isRequired) {
    try {
        std::wstring fullPath = GetFullPath(relativePath);
        auto fileData = ReadFileBytes(fullPath);
        uint32_t crc = CalculateCRC32(fileData);
        return AddProtectedFile(relativePath, crc, isRequired);
    }
    catch (const std::exception& e) {
        m_lastError = e.what();
        return false;
    }
}

bool FileProtection::RemoveProtectedFile(const std::wstring& relativePath) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::wstring fullPath = GetFullPath(relativePath);
    for (auto it = m_protectedFiles.begin(); it != m_protectedFiles.end(); ++it) {
        if (it->path == fullPath || it->relativePath == relativePath) {
            m_protectedFiles.erase(it);
            return true;
        }
    }
    return false;
}

void FileProtection::ClearProtectedFiles() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_protectedFiles.clear();
}

// ============================================================================
// VERIFICATION
// ============================================================================

bool FileProtection::VerifyFile(const std::wstring& relativePath) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::wstring fullPath = GetFullPath(relativePath);
    for (auto& file : m_protectedFiles) {
        if (file.path == fullPath || file.relativePath == relativePath) {
            try {
                auto data = ReadFileBytes(file.path);
                uint32_t currentCrc = CalculateCRC32(data);

                if (currentCrc != file.expectedCrc) {
                    file.isVerified = false;

                    if (m_callback) {
                        DetectionEvent event;
                        event.type = DetectionType::FileModified;
                        event.severity = file.isRequired ? Severity::Critical : Severity::Warning;
                        event.name = "File Modified";
                        event.details = WStringToString(file.path);
                        m_callback(event);
                    }
                    return false;
                }

                file.isVerified = true;
                return true;
            }
            catch (const std::exception&) {
                file.isVerified = false;
                return false;
            }
        }
    }

    m_lastError = "File not in protected list";
    return false;
}

bool FileProtection::VerifyAllFiles(std::wstring* failedFile) {
    std::lock_guard<std::mutex> lock(m_mutex);

    for (auto& file : m_protectedFiles) {
        try {
            auto data = ReadFileBytes(file.path);
            uint32_t currentCrc = CalculateCRC32(data);

            if (currentCrc != file.expectedCrc) {
                file.isVerified = false;

                if (m_callback) {
                    DetectionEvent event;
                    event.type = DetectionType::FileModified;
                    event.severity = file.isRequired ? Severity::Critical : Severity::Warning;
                    event.name = "File Modified";
                    event.details = WStringToString(file.path);
                    m_callback(event);
                }

                if (file.isRequired) {
                    if (failedFile) *failedFile = file.path;
                    return false;
                }
            }
            else {
                file.isVerified = true;
            }
        }
        catch (const std::exception&) {
            file.isVerified = false;
            if (file.isRequired) {
                if (failedFile) *failedFile = file.path;
                return false;
            }
        }
    }

    return true;
}

uint32_t FileProtection::CalculateFileCRC(const std::wstring& path) {
    try {
        auto data = ReadFileBytes(path);
        return CalculateCRC32(data);
    }
    catch (...) {
        return 0;
    }
}

// ============================================================================
// CONFIGURATION
// ============================================================================

bool FileProtection::LoadConfiguration(const std::wstring& configPath) {
    std::wifstream config(configPath);
    if (!config.is_open()) {
        m_lastError = "Cannot open configuration file";
        return false;
    }

    std::wstring line;
    while (std::getline(config, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == L'#') continue;

        std::wistringstream iss(line);
        std::wstring relativePath;
        std::wstring crcHex;
        std::wstring required;

        if (std::getline(iss, relativePath, L',') &&
            std::getline(iss, crcHex, L',') &&
            std::getline(iss, required)) {

            uint32_t crc;
            std::wstringstream ss;
            ss << std::hex << crcHex;
            ss >> crc;

            bool isRequired = (required == L"true" || required == L"1");
            AddProtectedFile(relativePath, crc, isRequired);
        }
    }

    return true;
}

bool FileProtection::SaveConfiguration(const std::wstring& configPath) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::wofstream outFile(configPath);
    if (!outFile.is_open()) {
        m_lastError = "Cannot create configuration file";
        return false;
    }

    outFile << L"# AntiCheat File Protection Configuration\n";
    outFile << L"# Format: relative_path,crc32,required\n\n";

    for (const auto& file : m_protectedFiles) {
        outFile << file.relativePath << L","
                << std::hex << std::uppercase << file.expectedCrc << L","
                << (file.isRequired ? L"true" : L"false") << std::endl;
    }

    return true;
}

// ============================================================================
// MONITORING
// ============================================================================

DWORD WINAPI FileProtection::MonitorThreadProc(LPVOID param) {
    FileProtection* self = static_cast<FileProtection*>(param);
    self->MonitorLoop();
    return 0;
}

void FileProtection::MonitorLoop() {
    while (m_monitorRunning) {
        VerifyAllFiles();
        Sleep(5000);  // Check every 5 seconds
    }
}

bool FileProtection::StartMonitoring() {
    if (m_monitorRunning) return true;

    m_monitorRunning = true;
    m_monitorThread = CreateThread(nullptr, 0, MonitorThreadProc, this, 0, nullptr);

    if (!m_monitorThread) {
        m_monitorRunning = false;
        m_lastError = "Failed to create monitor thread";
        return false;
    }

    return true;
}

void FileProtection::StopMonitoring() {
    if (!m_monitorRunning) return;

    m_monitorRunning = false;

    if (m_monitorThread) {
        WaitForSingleObject(m_monitorThread, 5000);
        CloseHandle(m_monitorThread);
        m_monitorThread = nullptr;
    }
}

// ============================================================================
// DIRECTORY PROTECTION
// ============================================================================

int FileProtection::ProtectDirectory(const std::wstring& dirPath, const std::wstring& pattern) {
    std::wstring fullDir = GetFullPath(dirPath);
    std::wstring searchPath = fullDir + L"\\" + pattern;

    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return 0;
    }

    int count = 0;
    do {
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::wstring relativePath = dirPath + L"\\" + findData.cFileName;
            if (AddProtectedFile(relativePath, true)) {
                count++;
            }
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
    return count;
}

// ============================================================================
// PRIVATE METHODS
// ============================================================================

ByteVector FileProtection::ReadFileBytes(const std::wstring& path) {
    ByteVector buffer;
    std::ifstream file(path, std::ios::binary);

    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file");
    }

    file.seekg(0, std::ios::end);
    size_t fileSize = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    buffer.resize(fileSize);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

    return buffer;
}

std::wstring FileProtection::GetFullPath(const std::wstring& relativePath) {
    wchar_t fullPath[MAX_PATH];
    if (!PathCombineW(fullPath, m_basePath.c_str(), relativePath.c_str())) {
        return relativePath;  // Return as-is if combination fails
    }
    return std::wstring(fullPath);
}

} // namespace AntiCheat
