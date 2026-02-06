/**
 * AntiCheatCore - Refactored Encryption Library (V2)
 *
 * Provides AES-256 encryption/decryption using Windows CryptoAPI.
 *
 * Improvements over V1 (EncryptionLib.h):
 *   - Properly in AntiCheat namespace
 *   - RAII for CryptoAPI handles (HCRYPTPROV, HCRYPTKEY)
 *   - Initialize()/Shutdown() lifecycle matching other modules
 *   - Uses CryptGenRandom for key generation (cryptographically secure)
 *   - Error handling via return codes (not exceptions in low-level code)
 *   - Const-correctness
 *   - Non-copyable, movable
 *
 * Follows: RAII, Single Responsibility, Dependency Inversion
 */

#pragma once

#ifndef AC_ENCRYPTION_LIB_V2_HPP
#define AC_ENCRYPTION_LIB_V2_HPP

#include "common.h"
#include <wincrypt.h>

#pragma comment(lib, "Crypt32.lib")

namespace AntiCheat {

/**
 * RAII wrapper for Windows CryptoAPI provider and key handles.
 * Provides AES-256 symmetric encryption.
 */
class EncryptionLibV2 final {
public:
    static constexpr size_t KEY_SIZE_BYTES = 32; ///< AES-256 = 32 bytes

    EncryptionLibV2();
    ~EncryptionLibV2();

    // Non-copyable
    EncryptionLibV2(const EncryptionLibV2&) = delete;
    EncryptionLibV2& operator=(const EncryptionLibV2&) = delete;

    // Movable
    EncryptionLibV2(EncryptionLibV2&& other) noexcept;
    EncryptionLibV2& operator=(EncryptionLibV2&& other) noexcept;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    /**
     * Acquires the CryptoAPI provider context.
     * Must be called before any cryptographic operations.
     *
     * @return true if the provider was acquired successfully.
     */
    bool Initialize();

    /**
     * Releases all cryptographic handles.
     */
    void Shutdown();

    /** Returns true if the provider is initialized. */
    [[nodiscard]] bool IsInitialized() const noexcept { return m_providerHandle != 0; }

    /** Returns true if a key is loaded and ready for encryption. */
    [[nodiscard]] bool IsKeyLoaded() const noexcept { return m_keyHandle != 0; }

    // ========================================================================
    // KEY MANAGEMENT
    // ========================================================================

    /**
     * Generates a cryptographically secure random AES-256 key.
     * Uses CryptGenRandom (CSPRNG) instead of std::mt19937.
     *
     * @param outKey  Receives the 32-byte key.
     * @return true if the key was generated successfully.
     */
    bool GenerateKey(ByteVector& outKey) const;

    /**
     * Sets the encryption key. Destroys any previously loaded key.
     *
     * @param keyData  Must be exactly 32 bytes (AES-256).
     * @return true if the key was imported successfully.
     */
    bool SetKey(const ByteVector& keyData);

    /**
     * Saves the current key to a file.
     *
     * @param keyFilePath  Path for the key file.
     * @return true if saved successfully.
     */
    bool SaveKeyToFile(const std::wstring& keyFilePath) const;

    /**
     * Loads a key from a file and activates it.
     *
     * @param keyFilePath  Path to the key file.
     * @return true if loaded and imported successfully.
     */
    bool LoadKeyFromFile(const std::wstring& keyFilePath);

    /** Returns a copy of the current key bytes (empty if no key loaded). */
    [[nodiscard]] ByteVector GetKeyData() const;

    // ========================================================================
    // ENCRYPTION / DECRYPTION
    // ========================================================================

    /**
     * Encrypts data using the loaded AES-256 key.
     *
     * @param plaintext    Data to encrypt.
     * @param outEncrypted Receives the encrypted data.
     * @return true if encryption succeeded.
     */
    bool Encrypt(const ByteVector& plaintext, ByteVector& outEncrypted) const;

    /**
     * Decrypts data using the loaded AES-256 key.
     *
     * @param encrypted    Data to decrypt.
     * @param outDecrypted Receives the decrypted data.
     * @return true if decryption succeeded.
     */
    bool Decrypt(const ByteVector& encrypted, ByteVector& outDecrypted) const;

    /**
     * Encrypts a file and writes the result to another file.
     *
     * @param inputPath   Source file to encrypt.
     * @param outputPath  Destination for encrypted data.
     * @return true if the operation succeeded.
     */
    bool EncryptFile(const std::wstring& inputPath,
                     const std::wstring& outputPath) const;

    /**
     * Decrypts a file and writes the result to another file.
     *
     * @param inputPath   Source file to decrypt.
     * @param outputPath  Destination for decrypted data.
     * @return true if the operation succeeded.
     */
    bool DecryptFile(const std::wstring& inputPath,
                     const std::wstring& outputPath) const;

    // ========================================================================
    // STATUS
    // ========================================================================

    /** Returns the last error message. */
    [[nodiscard]] const std::string& GetLastError() const noexcept { return m_lastError; }

private:
    HCRYPTPROV  m_providerHandle;   ///< CryptoAPI provider (RAII-managed)
    HCRYPTKEY   m_keyHandle;        ///< CryptoAPI key handle (RAII-managed)
    ByteVector  m_keyData;          ///< Copy of the raw key bytes
    std::string m_lastError;

    /**
     * Imports the raw key bytes into the CryptoAPI context.
     *
     * @return true if the key was imported successfully.
     */
    bool ImportKey();

    /**
     * Destroys the current CryptoAPI key handle (if any).
     */
    void DestroyKey() noexcept;

    /**
     * Destroys the CryptoAPI provider handle (if any).
     */
    void DestroyProvider() noexcept;

    /**
     * Reads a file into a byte vector.
     */
    [[nodiscard]] static ByteVector ReadFile(const std::wstring& path);

    /**
     * Writes a byte vector to a file.
     */
    [[nodiscard]] static bool WriteFile(const std::wstring& path, const ByteVector& data);

    /**
     * Gets the Windows error message for the last error code.
     */
    [[nodiscard]] static std::string FormatWinError(DWORD errorCode);
};

} // namespace AntiCheat

#endif // AC_ENCRYPTION_LIB_V2_HPP
