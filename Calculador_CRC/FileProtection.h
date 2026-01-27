#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>

class FileProtection {
private:
    static const uint32_t CRC32_TABLE[256];
    struct FileInfo {
        std::wstring path;
        uint32_t expectedCrc;
        bool isRequired;
    };

    std::vector<FileInfo> protectedFiles;
    wchar_t basePath[MAX_PATH];

public:
    std::wstring baseGamePath;
    FileProtection();
    void SetBasePath(const std::wstring& path);
    bool LoadConfiguration(const std::wstring& configPath);
    void AddProtectedFile(const std::wstring& relativePath, uint32_t expectedCrc, bool isRequired = true);
    void AddProtectedFile(const std::wstring& relativePath, bool isRequired = true);
    bool VerifyIntegrity();
    void GenerateConfiguration(const std::wstring& outputPath);
    void TerminateWithError(const std::wstring& filePath);

    // Métodos que necesitamos hacer públicos
    uint32_t CalculateCRC32(const std::vector<uint8_t>& data);
    std::vector<uint8_t> ReadFileBytes(const std::wstring& path);
    std::wstring GetFullPath(const std::wstring& relativePath);
};