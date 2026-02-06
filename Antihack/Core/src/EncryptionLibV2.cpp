/**
 * AntiCheatCore - Refactored Encryption Library (V2) Implementation
 *
 * Full implementation with RAII CryptoAPI management and
 * cryptographically secure key generation.
 */

#include "../include/internal/EncryptionLibV2.hpp"
#include <fstream>
#include <cstring>

namespace AntiCheat {

// ============================================================================
// KEY BLOB STRUCTURE (for CryptoAPI import)
// ============================================================================

#pragma pack(push, 1)
struct AesKeyBlob {
    BLOBHEADER header;
    DWORD      keySize;
    BYTE       keyData[EncryptionLibV2::KEY_SIZE_BYTES];
};
#pragma pack(pop)

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

EncryptionLibV2::EncryptionLibV2()
    : m_providerHandle(0)
    , m_keyHandle(0) {
}

EncryptionLibV2::~EncryptionLibV2() {
    Shutdown();
}

// ============================================================================
// MOVE SEMANTICS
// ============================================================================

EncryptionLibV2::EncryptionLibV2(EncryptionLibV2&& other) noexcept
    : m_providerHandle(other.m_providerHandle)
    , m_keyHandle(other.m_keyHandle)
    , m_keyData(std::move(other.m_keyData))
    , m_lastError(std::move(other.m_lastError)) {
    other.m_providerHandle = 0;
    other.m_keyHandle = 0;
}

EncryptionLibV2& EncryptionLibV2::operator=(EncryptionLibV2&& other) noexcept {
    if (this != &other) {
        Shutdown();
        m_providerHandle = other.m_providerHandle;
        m_keyHandle = other.m_keyHandle;
        m_keyData = std::move(other.m_keyData);
        m_lastError = std::move(other.m_lastError);
        other.m_providerHandle = 0;
        other.m_keyHandle = 0;
    }
    return *this;
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool EncryptionLibV2::Initialize() {
    if (m_providerHandle != 0) {
        return true; // Already initialized
    }

    if (!::CryptAcquireContextW(&m_providerHandle, nullptr,
                                 MS_ENH_RSA_AES_PROV_W,
                                 PROV_RSA_AES,
                                 CRYPT_VERIFYCONTEXT)) {
        m_lastError = "Failed to acquire crypto provider: " +
                      FormatWinError(::GetLastError());
        m_providerHandle = 0;
        return false;
    }

    return true;
}

void EncryptionLibV2::Shutdown() {
    DestroyKey();
    DestroyProvider();

    // Securely clear key data from memory
    if (!m_keyData.empty()) {
        ::SecureZeroMemory(m_keyData.data(), m_keyData.size());
        m_keyData.clear();
    }
}

// ============================================================================
// KEY MANAGEMENT
// ============================================================================

bool EncryptionLibV2::GenerateKey(ByteVector& outKey) const {
    if (m_providerHandle == 0) {
        return false;
    }

    outKey.resize(KEY_SIZE_BYTES);

    // Use CryptGenRandom for cryptographically secure random bytes
    if (!::CryptGenRandom(m_providerHandle, KEY_SIZE_BYTES, outKey.data())) {
        outKey.clear();
        return false;
    }

    return true;
}

bool EncryptionLibV2::SetKey(const ByteVector& keyData) {
    if (keyData.size() != KEY_SIZE_BYTES) {
        m_lastError = "Key must be exactly " + std::to_string(KEY_SIZE_BYTES) +
                      " bytes, got " + std::to_string(keyData.size());
        return false;
    }

    if (m_providerHandle == 0) {
        m_lastError = "Provider not initialized. Call Initialize() first.";
        return false;
    }

    // Destroy existing key before importing new one
    DestroyKey();

    m_keyData = keyData;
    return ImportKey();
}

bool EncryptionLibV2::SaveKeyToFile(const std::wstring& keyFilePath) const {
    if (m_keyData.empty()) {
        m_lastError = "No key loaded";
        return false;
    }

    return WriteFile(keyFilePath, m_keyData);
}

bool EncryptionLibV2::LoadKeyFromFile(const std::wstring& keyFilePath) {
    ByteVector keyData = ReadFile(keyFilePath);
    if (keyData.size() != KEY_SIZE_BYTES) {
        m_lastError = "Key file has invalid size: " + std::to_string(keyData.size()) +
                      " bytes (expected " + std::to_string(KEY_SIZE_BYTES) + ")";
        return false;
    }

    return SetKey(keyData);
}

ByteVector EncryptionLibV2::GetKeyData() const {
    return m_keyData;
}

// ============================================================================
// ENCRYPTION / DECRYPTION
// ============================================================================

bool EncryptionLibV2::Encrypt(const ByteVector& plaintext, ByteVector& outEncrypted) const {
    if (m_keyHandle == 0) {
        return false;
    }

    if (plaintext.empty()) {
        return false;
    }

    // First pass: determine the required buffer size
    DWORD encryptedSize = static_cast<DWORD>(plaintext.size());
    if (!::CryptEncrypt(m_keyHandle, 0, TRUE, 0, nullptr, &encryptedSize, 0)) {
        return false;
    }

    // Allocate buffer and copy plaintext
    outEncrypted.resize(encryptedSize);
    std::memcpy(outEncrypted.data(), plaintext.data(), plaintext.size());

    // Second pass: perform the actual encryption
    DWORD dataSize = static_cast<DWORD>(plaintext.size());
    if (!::CryptEncrypt(m_keyHandle, 0, TRUE, 0,
                         outEncrypted.data(), &dataSize, encryptedSize)) {
        outEncrypted.clear();
        return false;
    }

    outEncrypted.resize(dataSize);
    return true;
}

bool EncryptionLibV2::Decrypt(const ByteVector& encrypted, ByteVector& outDecrypted) const {
    if (m_keyHandle == 0) {
        return false;
    }

    if (encrypted.empty()) {
        return false;
    }

    outDecrypted = encrypted; // CryptDecrypt works in-place
    DWORD dataSize = static_cast<DWORD>(encrypted.size());

    if (!::CryptDecrypt(m_keyHandle, 0, TRUE, 0, outDecrypted.data(), &dataSize)) {
        outDecrypted.clear();
        return false;
    }

    outDecrypted.resize(dataSize);
    return true;
}

bool EncryptionLibV2::EncryptFile(const std::wstring& inputPath,
                                    const std::wstring& outputPath) const {
    ByteVector plaintext = ReadFile(inputPath);
    if (plaintext.empty()) {
        m_lastError = "Failed to read input file or file is empty";
        return false;
    }

    ByteVector encrypted;
    if (!Encrypt(plaintext, encrypted)) {
        m_lastError = "Encryption failed";
        return false;
    }

    if (!WriteFile(outputPath, encrypted)) {
        m_lastError = "Failed to write encrypted output";
        return false;
    }

    return true;
}

bool EncryptionLibV2::DecryptFile(const std::wstring& inputPath,
                                    const std::wstring& outputPath) const {
    ByteVector encrypted = ReadFile(inputPath);
    if (encrypted.empty()) {
        m_lastError = "Failed to read encrypted file or file is empty";
        return false;
    }

    ByteVector decrypted;
    if (!Decrypt(encrypted, decrypted)) {
        m_lastError = "Decryption failed";
        return false;
    }

    if (!WriteFile(outputPath, decrypted)) {
        m_lastError = "Failed to write decrypted output";
        return false;
    }

    return true;
}

// ============================================================================
// INTERNAL METHODS
// ============================================================================

bool EncryptionLibV2::ImportKey() {
    if (m_providerHandle == 0 || m_keyData.size() != KEY_SIZE_BYTES) {
        m_lastError = "Cannot import key: provider not initialized or invalid key size";
        return false;
    }

    AesKeyBlob blob{};
    blob.header.bType = PLAINTEXTKEYBLOB;
    blob.header.bVersion = CUR_BLOB_VERSION;
    blob.header.reserved = 0;
    blob.header.aiKeyAlg = CALG_AES_256;
    blob.keySize = KEY_SIZE_BYTES;
    std::memcpy(blob.keyData, m_keyData.data(), KEY_SIZE_BYTES);

    if (!::CryptImportKey(m_providerHandle,
                           reinterpret_cast<const BYTE*>(&blob),
                           sizeof(AesKeyBlob),
                           0, 0, &m_keyHandle)) {
        m_lastError = "CryptImportKey failed: " + FormatWinError(::GetLastError());
        m_keyHandle = 0;

        // Securely clear the blob
        ::SecureZeroMemory(&blob, sizeof(blob));
        return false;
    }

    // Securely clear the blob (key material was copied into CryptoAPI)
    ::SecureZeroMemory(&blob, sizeof(blob));
    return true;
}

void EncryptionLibV2::DestroyKey() noexcept {
    if (m_keyHandle != 0) {
        ::CryptDestroyKey(m_keyHandle);
        m_keyHandle = 0;
    }
}

void EncryptionLibV2::DestroyProvider() noexcept {
    if (m_providerHandle != 0) {
        ::CryptReleaseContext(m_providerHandle, 0);
        m_providerHandle = 0;
    }
}

ByteVector EncryptionLibV2::ReadFile(const std::wstring& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return {};
    }

    std::streamsize size = file.tellg();
    if (size <= 0) {
        return {};
    }

    file.seekg(0, std::ios::beg);

    ByteVector buffer(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(buffer.data()), size);

    if (!file) {
        return {};
    }

    return buffer;
}

bool EncryptionLibV2::WriteFile(const std::wstring& path, const ByteVector& data) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        return false;
    }

    file.write(reinterpret_cast<const char*>(data.data()),
               static_cast<std::streamsize>(data.size()));

    return file.good();
}

std::string EncryptionLibV2::FormatWinError(DWORD errorCode) {
    if (errorCode == 0) {
        return "No error";
    }

    LPSTR messageBuffer = nullptr;
    DWORD size = ::FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&messageBuffer),
        0, nullptr);

    if (size == 0 || messageBuffer == nullptr) {
        return "Unknown error (" + std::to_string(errorCode) + ")";
    }

    std::string message(messageBuffer, size);
    ::LocalFree(messageBuffer);

    // Remove trailing newline
    while (!message.empty() && (message.back() == '\n' || message.back() == '\r')) {
        message.pop_back();
    }

    return message;
}

} // namespace AntiCheat
