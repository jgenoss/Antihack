#pragma once
#include <Windows.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <random>
#include <fstream>

#pragma comment(lib, "Crypt32.lib")

class EncryptionLib {
private:
    std::vector<uint8_t> key;
    HCRYPTPROV hProvider;
    HCRYPTKEY hKey;
    
    void InitializeProvider();
    void ImportKey();

public:

    std::string GetLastErrorAsString();

    EncryptionLib();
    ~EncryptionLib();

    std::vector<uint8_t> GenerateKey();
    void SetKey(const std::vector<uint8_t>& newKey);
    void SaveKeyToFile(const std::wstring& keyPath);
    void LoadKeyFromFile(const std::wstring& keyPath);
    std::vector<uint8_t> EncryptData(const std::vector<uint8_t>& data);
    std::vector<uint8_t> DecryptData(const std::vector<uint8_t>& encrypted);
    void EncryptFile(const std::wstring& inputPath, const std::wstring& outputPath);
    void DecryptFile(const std::wstring& inputPath, const std::wstring& outputPath);
};
