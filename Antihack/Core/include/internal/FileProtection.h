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
    std::wstring baseGamePath;
    wchar_t basePath[MAX_PATH];

    uint32_t CalculateCRC32(const std::vector<uint8_t>& data);
    std::vector<uint8_t> ReadFileBytes(const std::wstring& path);
    void TerminateWithError(const std::wstring& filePath);
    std::wstring GetFullPath(const std::wstring& relativePath);

public:
    void CloseProcessAfterTimeouts(int timeoutMs);
    void ShowMessageAndExits(const char* message, const char* title, int timeoutMs);
    FileProtection();
    void SetBasePath(const std::wstring& path);
    bool LoadConfiguration(const std::wstring& configPath);
    void AddProtectedFile(const std::wstring& relativePath, uint32_t expectedCrc, bool isRequired = true);
    void AddProtectedFile(const std::wstring& relativePath, bool isRequired = true);
    bool VerifyIntegrity();
    void GenerateConfiguration(const std::wstring& outputPath);
    uint32_t CalculateCRC32(const uint8_t* data, size_t size);
};
