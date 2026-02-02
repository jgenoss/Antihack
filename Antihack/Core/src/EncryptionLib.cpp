/**
 * AntiCheatCore - Encryption Library Implementation
 * AES-256 with Windows CryptoAPI, plus RC4 and XOR utilities
 */

#include "../include/internal/EncryptionLib.h"
#include <fstream>
#include <sstream>
#include <random>
#include <cstring>

#pragma pack(push, 1)
struct AESKeyBlob {
    BLOBHEADER hdr;
    DWORD dwKeySize;
    BYTE rgbKeyData[32];
};
#pragma pack(pop)

namespace AntiCheat {

// ============================================================================
// RC4 STATE
// ============================================================================

struct RC4State {
    uint8_t S[256];
    int i, j;

    void Init(const uint8_t* key, size_t keyLen) {
        for (int n = 0; n < 256; n++) {
            S[n] = static_cast<uint8_t>(n);
        }

        int jj = 0;
        for (int n = 0; n < 256; n++) {
            jj = (jj + S[n] + key[n % keyLen]) % 256;
            std::swap(S[n], S[jj]);
        }

        i = 0;
        j = 0;
    }

    void Process(uint8_t* data, size_t length) {
        for (size_t n = 0; n < length; n++) {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            std::swap(S[i], S[j]);
            uint8_t k = S[(S[i] + S[j]) % 256];
            data[n] ^= k;
        }
    }
};

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

EncryptionLib::EncryptionLib()
    : m_hProvider(0), m_hKey(0), m_initialized(false) {
    InitializeProvider();
}

EncryptionLib::~EncryptionLib() {
    Cleanup();
}

// ============================================================================
// INITIALIZATION
// ============================================================================

bool EncryptionLib::InitializeProvider() {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_hProvider) return true;

    if (!CryptAcquireContextW(&m_hProvider, NULL, MS_ENH_RSA_AES_PROV,
                               PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        m_lastError = "Failed to initialize crypto provider";
        return false;
    }

    m_initialized = true;
    return true;
}

bool EncryptionLib::ImportKey() {
    if (m_key.size() != KEY_SIZE) {
        m_lastError = "Key must be 32 bytes (256 bits)";
        return false;
    }

    if (m_hKey) {
        CryptDestroyKey(m_hKey);
        m_hKey = 0;
    }

    AESKeyBlob keyBlob = {};
    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_AES_256;
    keyBlob.dwKeySize = KEY_SIZE;
    memcpy(keyBlob.rgbKeyData, m_key.data(), KEY_SIZE);

    if (!CryptImportKey(m_hProvider, reinterpret_cast<BYTE*>(&keyBlob),
                        sizeof(AESKeyBlob), 0, 0, &m_hKey)) {
        m_lastError = "Failed to import key";
        return false;
    }

    return true;
}

void EncryptionLib::Cleanup() {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_hKey) {
        CryptDestroyKey(m_hKey);
        m_hKey = 0;
    }
    if (m_hProvider) {
        CryptReleaseContext(m_hProvider, 0);
        m_hProvider = 0;
    }

    SecureZeroMemory(m_key.data(), m_key.size());
    m_key.clear();
    m_initialized = false;
}

// ============================================================================
// KEY MANAGEMENT
// ============================================================================

bool EncryptionLib::GenerateKey() {
    std::lock_guard<std::mutex> lock(m_mutex);

    m_key.resize(KEY_SIZE);

    if (!GenerateRandomBytes(m_key.data(), KEY_SIZE)) {
        m_lastError = "Failed to generate random key";
        return false;
    }

    return ImportKey();
}

bool EncryptionLib::SetKey(const ByteVector& key) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (key.size() != KEY_SIZE) {
        m_lastError = "Key must be 32 bytes (256 bits)";
        return false;
    }

    m_key = key;
    return ImportKey();
}

bool EncryptionLib::SetKey(const uint8_t* key, size_t length) {
    if (!key || length != KEY_SIZE) {
        m_lastError = "Invalid key parameters";
        return false;
    }

    ByteVector keyVec(key, key + length);
    return SetKey(keyVec);
}

ByteVector EncryptionLib::GetKey() const {
    return m_key;
}

bool EncryptionLib::SaveKeyToFile(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_key.empty()) {
        m_lastError = "No key to save";
        return false;
    }

    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        m_lastError = "Cannot create key file";
        return false;
    }

    file.write(reinterpret_cast<const char*>(m_key.data()), m_key.size());
    return file.good();
}

bool EncryptionLib::LoadKeyFromFile(const std::wstring& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        m_lastError = "Cannot open key file";
        return false;
    }

    ByteVector key(KEY_SIZE);
    file.read(reinterpret_cast<char*>(key.data()), KEY_SIZE);

    if (!file.good()) {
        m_lastError = "Failed to read key file";
        return false;
    }

    return SetKey(key);
}

// ============================================================================
// DATA ENCRYPTION
// ============================================================================

ByteVector EncryptionLib::Encrypt(const ByteVector& data) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_hKey) {
        m_lastError = "Key not initialized";
        return ByteVector();
    }

    if (data.empty()) {
        m_lastError = "Empty input data";
        return ByteVector();
    }

    // Calculate required buffer size
    DWORD encryptedSize = static_cast<DWORD>(data.size());
    if (!CryptEncrypt(m_hKey, 0, TRUE, 0, nullptr, &encryptedSize, 0)) {
        m_lastError = "Failed to calculate encrypted size";
        return ByteVector();
    }

    // Create buffer and encrypt
    ByteVector encrypted(encryptedSize);
    memcpy(encrypted.data(), data.data(), data.size());

    DWORD dataSize = static_cast<DWORD>(data.size());
    if (!CryptEncrypt(m_hKey, 0, TRUE, 0, encrypted.data(), &dataSize, encryptedSize)) {
        m_lastError = "Encryption failed";
        return ByteVector();
    }

    encrypted.resize(dataSize);
    return encrypted;
}

ByteVector EncryptionLib::Decrypt(const ByteVector& encrypted) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_hKey) {
        m_lastError = "Key not initialized";
        return ByteVector();
    }

    ByteVector decrypted = encrypted;
    DWORD size = static_cast<DWORD>(encrypted.size());

    if (!CryptDecrypt(m_hKey, 0, TRUE, 0, decrypted.data(), &size)) {
        m_lastError = "Decryption failed";
        return ByteVector();
    }

    decrypted.resize(size);
    return decrypted;
}

bool EncryptionLib::Encrypt(const uint8_t* input, size_t inputLen,
                            uint8_t* output, size_t* outputLen) {
    if (!input || !output || !outputLen || inputLen == 0) {
        m_lastError = "Invalid parameters";
        return false;
    }

    ByteVector data(input, input + inputLen);
    ByteVector encrypted = Encrypt(data);

    if (encrypted.empty()) return false;

    if (*outputLen < encrypted.size()) {
        *outputLen = encrypted.size();
        m_lastError = "Output buffer too small";
        return false;
    }

    memcpy(output, encrypted.data(), encrypted.size());
    *outputLen = encrypted.size();
    return true;
}

bool EncryptionLib::Decrypt(const uint8_t* input, size_t inputLen,
                            uint8_t* output, size_t* outputLen) {
    if (!input || !output || !outputLen || inputLen == 0) {
        m_lastError = "Invalid parameters";
        return false;
    }

    ByteVector encrypted(input, input + inputLen);
    ByteVector decrypted = Decrypt(encrypted);

    if (decrypted.empty()) return false;

    if (*outputLen < decrypted.size()) {
        *outputLen = decrypted.size();
        m_lastError = "Output buffer too small";
        return false;
    }

    memcpy(output, decrypted.data(), decrypted.size());
    *outputLen = decrypted.size();
    return true;
}

// ============================================================================
// FILE ENCRYPTION
// ============================================================================

bool EncryptionLib::EncryptFile(const std::wstring& inputPath, const std::wstring& outputPath) {
    std::ifstream inFile(inputPath, std::ios::binary);
    if (!inFile.is_open()) {
        m_lastError = "Cannot open input file";
        return false;
    }

    inFile.seekg(0, std::ios::end);
    size_t fileSize = static_cast<size_t>(inFile.tellg());
    inFile.seekg(0, std::ios::beg);

    if (fileSize == 0) {
        m_lastError = "Input file is empty";
        return false;
    }

    ByteVector data(fileSize);
    inFile.read(reinterpret_cast<char*>(data.data()), fileSize);
    inFile.close();

    ByteVector encrypted = Encrypt(data);
    if (encrypted.empty()) return false;

    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile.is_open()) {
        m_lastError = "Cannot create output file";
        return false;
    }

    outFile.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
    return outFile.good();
}

bool EncryptionLib::DecryptFile(const std::wstring& inputPath, const std::wstring& outputPath) {
    std::ifstream inFile(inputPath, std::ios::binary);
    if (!inFile.is_open()) {
        m_lastError = "Cannot open encrypted file";
        return false;
    }

    ByteVector encrypted((std::istreambuf_iterator<char>(inFile)),
                          std::istreambuf_iterator<char>());

    ByteVector decrypted = Decrypt(encrypted);
    if (decrypted.empty()) return false;

    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile.is_open()) {
        m_lastError = "Cannot create output file";
        return false;
    }

    outFile.write(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
    return outFile.good();
}

// ============================================================================
// STRING HELPERS
// ============================================================================

std::string EncryptionLib::EncryptString(const std::string& plaintext) {
    ByteVector data(plaintext.begin(), plaintext.end());
    ByteVector encrypted = Encrypt(data);
    return std::string(encrypted.begin(), encrypted.end());
}

std::string EncryptionLib::DecryptString(const std::string& encrypted) {
    ByteVector data(encrypted.begin(), encrypted.end());
    ByteVector decrypted = Decrypt(data);
    return std::string(decrypted.begin(), decrypted.end());
}

// ============================================================================
// STATIC METHODS - RC4
// ============================================================================

void EncryptionLib::RC4Encrypt(uint8_t* data, size_t length,
                                const uint8_t* key, size_t keyLen) {
    if (!data || length == 0 || !key || keyLen == 0) return;

    RC4State state;
    state.Init(key, keyLen);
    state.Process(data, length);
}

void EncryptionLib::RC4Decrypt(uint8_t* data, size_t length,
                                const uint8_t* key, size_t keyLen) {
    // RC4 is symmetric
    RC4Encrypt(data, length, key, keyLen);
}

// ============================================================================
// STATIC METHODS - XOR
// ============================================================================

void EncryptionLib::XorEncrypt(uint8_t* data, size_t length,
                                const uint8_t* key, size_t keyLen) {
    if (!data || length == 0 || !key || keyLen == 0) return;

    for (size_t i = 0; i < length; i++) {
        data[i] ^= key[i % keyLen];
    }
}

void EncryptionLib::XorDecrypt(uint8_t* data, size_t length,
                                const uint8_t* key, size_t keyLen) {
    // XOR is symmetric
    XorEncrypt(data, length, key, keyLen);
}

// ============================================================================
// STATIC METHODS - RANDOM
// ============================================================================

bool EncryptionLib::GenerateRandomBytes(uint8_t* buffer, size_t length) {
    if (!buffer || length == 0) return false;

    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return false;
    }

    BOOL result = CryptGenRandom(hProv, static_cast<DWORD>(length), buffer);
    CryptReleaseContext(hProv, 0);

    return result != FALSE;
}

// ============================================================================
// STATIC METHODS - HASHING
// ============================================================================

uint32_t EncryptionLib::HashCRC32(const uint8_t* data, size_t length) {
    return CalculateCRC32(data, length);
}

ByteVector EncryptionLib::HashSHA256(const uint8_t* data, size_t length) {
    ByteVector hash;

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return hash;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return hash;
    }

    if (CryptHashData(hHash, data, static_cast<DWORD>(length), 0)) {
        DWORD hashSize = 32;
        hash.resize(hashSize);
        CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashSize, 0);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return hash;
}

} // namespace AntiCheat
