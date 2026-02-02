/**
 * Encryption Library Module
 * Provides encryption/decryption for secure communication
 */

#include "../include/anticheat_core.h"
#include <Windows.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <cstring>

#pragma comment(lib, "advapi32.lib")

static char g_encryptionError[256] = "";
static BYTE g_sessionKey[32] = { 0 }; // AES-256 key
static bool g_keyInitialized = false;

// XOR encryption (fast, for obfuscation)
static void XorEncrypt(BYTE* data, size_t length, const BYTE* key, size_t keyLen) {
    for (size_t i = 0; i < length; i++) {
        data[i] ^= key[i % keyLen];
    }
}

// RC4 implementation (for streaming)
struct RC4State {
    BYTE S[256];
    int i, j;
};

static void RC4Init(RC4State* state, const BYTE* key, size_t keyLen) {
    for (int i = 0; i < 256; i++) {
        state->S[i] = (BYTE)i;
    }

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + state->S[i] + key[i % keyLen]) % 256;
        BYTE temp = state->S[i];
        state->S[i] = state->S[j];
        state->S[j] = temp;
    }

    state->i = 0;
    state->j = 0;
}

static void RC4Process(RC4State* state, BYTE* data, size_t length) {
    for (size_t n = 0; n < length; n++) {
        state->i = (state->i + 1) % 256;
        state->j = (state->j + state->S[state->i]) % 256;

        BYTE temp = state->S[state->i];
        state->S[state->i] = state->S[state->j];
        state->S[state->j] = temp;

        BYTE k = state->S[(state->S[state->i] + state->S[state->j]) % 256];
        data[n] ^= k;
    }
}

// Generate random bytes using CryptoAPI
static bool GenerateRandomBytes(BYTE* buffer, DWORD length) {
    HCRYPTPROV hProv = 0;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return false;
    }

    BOOL result = CryptGenRandom(hProv, length, buffer);
    CryptReleaseContext(hProv, 0);

    return result != FALSE;
}

// ============================================================================
// EXPORTED FUNCTIONS
// ============================================================================

AC_API bool AC_CALL AC_EncryptionInit(void) {
    g_encryptionError[0] = '\0';
    g_keyInitialized = false;
    memset(g_sessionKey, 0, sizeof(g_sessionKey));
    return true;
}

AC_API bool AC_CALL AC_GenerateSessionKey(void) {
    if (!GenerateRandomBytes(g_sessionKey, sizeof(g_sessionKey))) {
        strcpy_s(g_encryptionError, "Failed to generate random key");
        return false;
    }
    g_keyInitialized = true;
    return true;
}

AC_API bool AC_CALL AC_SetSessionKey(const BYTE* key, int keyLength) {
    if (!key || keyLength <= 0 || keyLength > 32) {
        strcpy_s(g_encryptionError, "Invalid key parameters");
        return false;
    }

    memset(g_sessionKey, 0, sizeof(g_sessionKey));
    memcpy(g_sessionKey, key, keyLength);
    g_keyInitialized = true;
    return true;
}

AC_API bool AC_CALL AC_GetSessionKey(BYTE* keyBuffer, int bufferSize) {
    if (!g_keyInitialized) {
        strcpy_s(g_encryptionError, "Session key not initialized");
        return false;
    }

    if (!keyBuffer || bufferSize < 32) {
        strcpy_s(g_encryptionError, "Buffer too small");
        return false;
    }

    memcpy(keyBuffer, g_sessionKey, 32);
    return true;
}

// XOR encryption (fast, reversible)
AC_API bool AC_CALL AC_XorEncrypt(BYTE* data, int dataLength,
                                   const BYTE* key, int keyLength) {
    if (!data || dataLength <= 0 || !key || keyLength <= 0) {
        strcpy_s(g_encryptionError, "Invalid parameters");
        return false;
    }

    XorEncrypt(data, dataLength, key, keyLength);
    return true;
}

AC_API bool AC_CALL AC_XorDecrypt(BYTE* data, int dataLength,
                                   const BYTE* key, int keyLength) {
    // XOR is symmetric
    return AC_XorEncrypt(data, dataLength, key, keyLength);
}

// RC4 encryption
AC_API bool AC_CALL AC_RC4Encrypt(BYTE* data, int dataLength,
                                   const BYTE* key, int keyLength) {
    if (!data || dataLength <= 0 || !key || keyLength <= 0) {
        strcpy_s(g_encryptionError, "Invalid parameters");
        return false;
    }

    RC4State state;
    RC4Init(&state, key, keyLength);
    RC4Process(&state, data, dataLength);

    // Clear state
    SecureZeroMemory(&state, sizeof(state));
    return true;
}

AC_API bool AC_CALL AC_RC4Decrypt(BYTE* data, int dataLength,
                                   const BYTE* key, int keyLength) {
    // RC4 is symmetric
    return AC_RC4Encrypt(data, dataLength, key, keyLength);
}

// Encrypt with session key
AC_API bool AC_CALL AC_EncryptWithSessionKey(BYTE* data, int dataLength) {
    if (!g_keyInitialized) {
        strcpy_s(g_encryptionError, "Session key not initialized");
        return false;
    }

    return AC_RC4Encrypt(data, dataLength, g_sessionKey, sizeof(g_sessionKey));
}

AC_API bool AC_CALL AC_DecryptWithSessionKey(BYTE* data, int dataLength) {
    if (!g_keyInitialized) {
        strcpy_s(g_encryptionError, "Session key not initialized");
        return false;
    }

    return AC_RC4Decrypt(data, dataLength, g_sessionKey, sizeof(g_sessionKey));
}

// String encryption helpers
AC_API bool AC_CALL AC_EncryptString(const char* input, BYTE* output,
                                      int* outputLength, const BYTE* key, int keyLength) {
    if (!input || !output || !outputLength || !key) {
        strcpy_s(g_encryptionError, "Invalid parameters");
        return false;
    }

    int inputLen = (int)strlen(input) + 1; // Include null terminator
    if (*outputLength < inputLen) {
        *outputLength = inputLen;
        strcpy_s(g_encryptionError, "Output buffer too small");
        return false;
    }

    memcpy(output, input, inputLen);
    *outputLength = inputLen;

    return AC_RC4Encrypt(output, inputLen, key, keyLength);
}

AC_API bool AC_CALL AC_DecryptString(const BYTE* input, int inputLength,
                                      char* output, int outputSize,
                                      const BYTE* key, int keyLength) {
    if (!input || inputLength <= 0 || !output || outputSize < inputLength || !key) {
        strcpy_s(g_encryptionError, "Invalid parameters");
        return false;
    }

    memcpy(output, input, inputLength);
    return AC_RC4Decrypt((BYTE*)output, inputLength, key, keyLength);
}

// Generate random bytes
AC_API bool AC_CALL AC_GenerateRandom(BYTE* buffer, int length) {
    if (!buffer || length <= 0) {
        strcpy_s(g_encryptionError, "Invalid parameters");
        return false;
    }

    return GenerateRandomBytes(buffer, length);
}

// Hash functions
AC_API uint32_t AC_CALL AC_HashData(const BYTE* data, int length) {
    if (!data || length <= 0) return 0;

    // CRC32
    uint32_t crc = 0xFFFFFFFF;
    for (int i = 0; i < length; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

AC_API uint32_t AC_CALL AC_HashString(const char* str) {
    if (!str) return 0;
    return AC_HashData((const BYTE*)str, (int)strlen(str));
}

// Obfuscate/Deobfuscate strings at runtime
AC_API void AC_CALL AC_ObfuscateData(BYTE* data, int length) {
    // Simple obfuscation with fixed key
    static const BYTE obfKey[] = { 0xAC, 0x13, 0x37, 0xBE, 0xEF, 0xCA, 0xFE, 0x42 };
    XorEncrypt(data, length, obfKey, sizeof(obfKey));
}

AC_API void AC_CALL AC_DeobfuscateData(BYTE* data, int length) {
    // Same as obfuscate (XOR is symmetric)
    AC_ObfuscateData(data, length);
}

AC_API const char* AC_CALL AC_GetEncryptionError(void) {
    return g_encryptionError;
}

// Secure zero memory
AC_API void AC_CALL AC_SecureClear(void* buffer, size_t length) {
    if (buffer && length > 0) {
        SecureZeroMemory(buffer, length);
    }
}
