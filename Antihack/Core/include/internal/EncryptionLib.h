/**
 * AntiCheatCore - Encryption Library Module
 * AES-256 encryption using Windows CryptoAPI
 */

#pragma once

#ifndef AC_ENCRYPTION_LIB_H
#define AC_ENCRYPTION_LIB_H

#include "common.h"
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

namespace AntiCheat {

class EncryptionLib {
public:
    static const size_t KEY_SIZE = 32;  // AES-256
    static const size_t IV_SIZE = 16;

private:
    ByteVector m_key;
    HCRYPTPROV m_hProvider;
    HCRYPTKEY m_hKey;
    bool m_initialized;
    std::string m_lastError;
    std::mutex m_mutex;

    bool InitializeProvider();
    bool ImportKey();
    void Cleanup();

public:
    EncryptionLib();
    ~EncryptionLib();

    // Key management
    bool GenerateKey();
    bool SetKey(const ByteVector& key);
    bool SetKey(const uint8_t* key, size_t length);
    ByteVector GetKey() const;
    bool SaveKeyToFile(const std::wstring& path);
    bool LoadKeyFromFile(const std::wstring& path);

    // Data encryption/decryption
    ByteVector Encrypt(const ByteVector& data);
    ByteVector Decrypt(const ByteVector& encrypted);
    bool Encrypt(const uint8_t* input, size_t inputLen, uint8_t* output, size_t* outputLen);
    bool Decrypt(const uint8_t* input, size_t inputLen, uint8_t* output, size_t* outputLen);

    // File encryption/decryption
    bool EncryptFile(const std::wstring& inputPath, const std::wstring& outputPath);
    bool DecryptFile(const std::wstring& inputPath, const std::wstring& outputPath);

    // String helpers
    std::string EncryptString(const std::string& plaintext);
    std::string DecryptString(const std::string& encrypted);

    // RC4 streaming (faster, less secure)
    static void RC4Encrypt(uint8_t* data, size_t length, const uint8_t* key, size_t keyLen);
    static void RC4Decrypt(uint8_t* data, size_t length, const uint8_t* key, size_t keyLen);

    // XOR obfuscation (very fast, for basic obfuscation)
    static void XorEncrypt(uint8_t* data, size_t length, const uint8_t* key, size_t keyLen);
    static void XorDecrypt(uint8_t* data, size_t length, const uint8_t* key, size_t keyLen);

    // Random generation
    static bool GenerateRandomBytes(uint8_t* buffer, size_t length);

    // Hashing
    static uint32_t HashCRC32(const uint8_t* data, size_t length);
    static ByteVector HashSHA256(const uint8_t* data, size_t length);

    // Getters
    bool IsInitialized() const { return m_initialized; }
    const std::string& GetLastError() const { return m_lastError; }
};

} // namespace AntiCheat

#endif // AC_ENCRYPTION_LIB_H
