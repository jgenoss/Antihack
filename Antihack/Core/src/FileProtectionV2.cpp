/**
 * AntiCheatCore - Refactored File Protection (V2) Implementation
 *
 * Full implementation with proper namespace, IMonitorModule integration,
 * and CRC32 from common.h (no duplicate table).
 */

#include "../include/internal/FileProtectionV2.hpp"
#include <shlwapi.h>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "shlwapi.lib")

namespace AntiCheat {

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

FileProtectionV2::FileProtectionV2()
    : IMonitorModule("FileProtection", 10000) { // Scan every 10 seconds
    // Determine default base path from the executable location
    wchar_t exePath[MAX_PATH]{};
    if (::GetModuleFileNameW(nullptr, exePath, MAX_PATH) > 0) {
        if (::PathRemoveFileSpecW(exePath)) {
            m_basePath = exePath;
        }
    }
}

FileProtectionV2::~FileProtectionV2() {
    Shutdown();
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool FileProtectionV2::Initialize() {
    if (!IMonitorModule::Initialize()) {
        return false;
    }

    // Verify base path is valid
    if (m_basePath.empty()) {
        m_lastError = "Base path is not set";
        return false;
    }

    DWORD attrs = ::GetFileAttributesW(m_basePath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        m_lastError = "Base path does not exist or is not a directory";
        return false;
    }

    return true;
}

void FileProtectionV2::Shutdown() {
    IMonitorModule::Shutdown();

    std::lock_guard<std::mutex> lock(m_dataMutex);
    m_protectedFiles.clear();
}

// ============================================================================
// PATH CONFIGURATION
// ============================================================================

void FileProtectionV2::SetBasePath(const std::wstring& basePath) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    m_basePath = basePath;

    // Re-resolve all existing protected file paths
    for (auto& entry : m_protectedFiles) {
        entry.fullPath = ResolvePath(entry.relativePath);
    }
}

// ============================================================================
// FILE REGISTRATION
// ============================================================================

void FileProtectionV2::AddProtectedFile(const std::wstring& relativePath,
                                         uint32_t expectedCrc,
                                         bool isRequired) {
    std::lock_guard<std::mutex> lock(m_dataMutex);

    ProtectedFileEntry entry;
    entry.relativePath = relativePath;
    entry.fullPath = ResolvePath(relativePath);
    entry.expectedCrc = expectedCrc;
    entry.isRequired = isRequired;

    m_protectedFiles.push_back(std::move(entry));
}

bool FileProtectionV2::AddProtectedFileAuto(const std::wstring& relativePath,
                                              bool isRequired) {
    std::wstring fullPath = ResolvePath(relativePath);

    uint32_t crc = 0;
    if (!ComputeFileCrc(fullPath, crc)) {
        m_lastError = "Failed to read file for CRC calculation: " + WStringToString(fullPath);
        return false;
    }

    AddProtectedFile(relativePath, crc, isRequired);
    return true;
}

void FileProtectionV2::RemoveProtectedFile(const std::wstring& relativePath) {
    std::lock_guard<std::mutex> lock(m_dataMutex);

    std::wstring lowerTarget = relativePath;
    std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::towlower);

    m_protectedFiles.erase(
        std::remove_if(m_protectedFiles.begin(), m_protectedFiles.end(),
                        [&lowerTarget](const ProtectedFileEntry& entry) {
                            std::wstring lower = entry.relativePath;
                            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                            return lower == lowerTarget;
                        }),
        m_protectedFiles.end());
}

void FileProtectionV2::ClearProtectedFiles() {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    m_protectedFiles.clear();
}

int FileProtectionV2::GetProtectedFileCount() const {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    return static_cast<int>(m_protectedFiles.size());
}

// ============================================================================
// CONFIGURATION FILE
// ============================================================================

bool FileProtectionV2::LoadConfiguration(const std::wstring& configPath) {
    std::wifstream config(configPath);
    if (!config.is_open()) {
        m_lastError = "Failed to open configuration file";
        return false;
    }

    std::wstring line;
    int lineNum = 0;

    while (std::getline(config, line)) {
        lineNum++;

        // Skip empty lines and comments
        if (line.empty() || line[0] == L'#' || line[0] == L';') continue;

        // Parse: relative_path,crc32_hex,required
        std::wistringstream iss(line);
        std::wstring relativePath;
        std::wstring crcHexStr;
        std::wstring requiredStr;

        if (!std::getline(iss, relativePath, L',') ||
            !std::getline(iss, crcHexStr, L',') ||
            !std::getline(iss, requiredStr)) {
            m_lastError = "Malformed line " + std::to_string(lineNum);
            continue; // Skip malformed lines
        }

        // Trim whitespace
        auto trimW = [](std::wstring& s) {
            size_t start = s.find_first_not_of(L" \t");
            size_t end = s.find_last_not_of(L" \t");
            if (start != std::wstring::npos && end != std::wstring::npos) {
                s = s.substr(start, end - start + 1);
            }
        };

        trimW(relativePath);
        trimW(crcHexStr);
        trimW(requiredStr);

        // Parse CRC32 hex
        uint32_t crc = 0;
        std::wstringstream crcStream;
        crcStream << std::hex << crcHexStr;
        crcStream >> crc;

        // Parse required flag
        bool isRequired = (requiredStr == L"true" || requiredStr == L"1" || requiredStr == L"yes");

        AddProtectedFile(relativePath, crc, isRequired);
    }

    return true;
}

bool FileProtectionV2::GenerateConfiguration(const std::wstring& outputPath) const {
    std::wofstream outFile(outputPath);
    if (!outFile.is_open()) {
        return false;
    }

    outFile << L"# AntiCheatCore File Protection Configuration\n";
    outFile << L"# Format: relative_path,CRC32_hex,required\n\n";

    std::lock_guard<std::mutex> lock(m_dataMutex);

    for (const auto& entry : m_protectedFiles) {
        outFile << entry.relativePath << L","
                << std::hex << std::uppercase << entry.expectedCrc << L","
                << (entry.isRequired ? L"true" : L"false") << L"\n";
    }

    outFile.flush();
    return outFile.good();
}

// ============================================================================
// VERIFICATION
// ============================================================================

bool FileProtectionV2::VerifyAllFiles(std::vector<VerificationResult>& outResults) const {
    std::lock_guard<std::mutex> lock(m_dataMutex);

    bool allPassed = true;

    for (const auto& entry : m_protectedFiles) {
        VerificationResult result;
        result.path = entry.fullPath;
        result.expectedCrc = entry.expectedCrc;
        result.isRequired = entry.isRequired;

        // Check if file exists
        DWORD attrs = ::GetFileAttributesW(entry.fullPath.c_str());
        result.fileExists = (attrs != INVALID_FILE_ATTRIBUTES);

        if (!result.fileExists) {
            result.isValid = false;
            result.errorMessage = "File not found";
            if (entry.isRequired) {
                allPassed = false;
            }
            outResults.push_back(std::move(result));
            continue;
        }

        // Compute current CRC
        if (ComputeFileCrc(entry.fullPath, result.actualCrc)) {
            result.isValid = (result.actualCrc == entry.expectedCrc);
            if (!result.isValid) {
                result.errorMessage = "CRC mismatch: expected " +
                    std::to_string(entry.expectedCrc) + ", got " +
                    std::to_string(result.actualCrc);
                if (entry.isRequired) {
                    allPassed = false;
                }
            }
        } else {
            result.isValid = false;
            result.errorMessage = "Failed to read file for CRC computation";
            if (entry.isRequired) {
                allPassed = false;
            }
        }

        outResults.push_back(std::move(result));
    }

    return allPassed;
}

FileProtectionV2::VerificationResult FileProtectionV2::VerifyFile(
    const std::wstring& relativePath) const {

    VerificationResult result;
    std::wstring fullPath = ResolvePath(relativePath);
    result.path = fullPath;

    // Find the entry
    {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        bool found = false;

        std::wstring lowerTarget = relativePath;
        std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::towlower);

        for (const auto& entry : m_protectedFiles) {
            std::wstring lower = entry.relativePath;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
            if (lower == lowerTarget) {
                result.expectedCrc = entry.expectedCrc;
                result.isRequired = entry.isRequired;
                found = true;
                break;
            }
        }

        if (!found) {
            result.errorMessage = "File not in protection list";
            return result;
        }
    }

    // Check existence
    DWORD attrs = ::GetFileAttributesW(fullPath.c_str());
    result.fileExists = (attrs != INVALID_FILE_ATTRIBUTES);

    if (!result.fileExists) {
        result.errorMessage = "File not found";
        return result;
    }

    // Compute CRC
    if (ComputeFileCrc(fullPath, result.actualCrc)) {
        result.isValid = (result.actualCrc == result.expectedCrc);
        if (!result.isValid) {
            result.errorMessage = "CRC mismatch";
        }
    } else {
        result.errorMessage = "Failed to read file";
    }

    return result;
}

bool FileProtectionV2::VerifyIntegrity() const {
    std::vector<VerificationResult> results;
    return VerifyAllFiles(results);
}

// ============================================================================
// CALLBACKS
// ============================================================================

void FileProtectionV2::SetViolationCallback(ViolationCallback callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_violationCallback = std::move(callback);
}

// ============================================================================
// IMonitorModule OVERRIDES
// ============================================================================

void FileProtectionV2::OnMonitorStart() {
    // Nothing special needed on start
}

void FileProtectionV2::DoMonitorCycle() {
    std::vector<VerificationResult> results;
    VerifyAllFiles(results);

    for (const auto& result : results) {
        if (!result.isValid) {
            // Notify via violation callback
            {
                std::lock_guard<std::mutex> cbLock(m_callbackMutex);
                if (m_violationCallback) {
                    m_violationCallback(result);
                }
            }

            // Queue detection event for the EventBus
            DetectionEvent event;
            event.type = DetectionType::FileModified;
            event.severity = result.isRequired ? Severity::Critical : Severity::Warning;
            event.description = "File integrity violation: " + WStringToString(result.path) +
                                " (" + result.errorMessage + ")";
            event.timestamp = ::GetTickCount();
            QueueEvent(event);
        }
    }
}

// ============================================================================
// IConfigurable
// ============================================================================

bool FileProtectionV2::ApplyConfig(const ConfigMap& config) {
    auto getOrDefault = [&config](const std::string& key, const std::string& def) {
        auto it = config.find(key);
        return (it != config.end()) ? it->second : def;
    };

    std::string intervalStr = getOrDefault("scan_interval", "10000");
    try {
        SetMonitorInterval(static_cast<DWORD>(std::stoul(intervalStr)));
    } catch (...) {}

    std::string basePath = getOrDefault("base_path", "");
    if (!basePath.empty()) {
        SetBasePath(StringToWString(basePath));
    }

    // Load protected files config if specified
    std::string configFile = getOrDefault("config_file", "");
    if (!configFile.empty()) {
        LoadConfiguration(StringToWString(configFile));
    }

    return true;
}

void FileProtectionV2::ExportConfig(ConfigMap& outConfig) const {
    outConfig["scan_interval"] = std::to_string(GetMonitorInterval());
    outConfig["base_path"] = WStringToString(m_basePath);
    outConfig["protected_file_count"] = std::to_string(GetProtectedFileCount());
}

// ============================================================================
// UTILITY
// ============================================================================

std::wstring FileProtectionV2::ResolvePath(const std::wstring& relativePath) const {
    if (m_basePath.empty()) {
        return relativePath; // Return as-is if no base path
    }

    wchar_t fullPath[MAX_PATH]{};
    if (::PathCombineW(fullPath, m_basePath.c_str(), relativePath.c_str())) {
        return fullPath;
    }

    // Fallback: simple concatenation
    std::wstring result = m_basePath;
    if (!result.empty() && result.back() != L'\\' && result.back() != L'/') {
        result += L'\\';
    }
    result += relativePath;
    return result;
}

ByteVector FileProtectionV2::ReadFileBytes(const std::wstring& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return {};
    }

    std::streamsize fileSize = file.tellg();
    if (fileSize <= 0) {
        return {};
    }

    file.seekg(0, std::ios::beg);

    ByteVector buffer(static_cast<size_t>(fileSize));
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

    if (!file) {
        return {};
    }

    return buffer;
}

bool FileProtectionV2::ComputeFileCrc(const std::wstring& path, uint32_t& outCrc) {
    ByteVector data = ReadFileBytes(path);
    if (data.empty()) {
        return false;
    }

    outCrc = CalculateCRC32(data);
    return true;
}

} // namespace AntiCheat
