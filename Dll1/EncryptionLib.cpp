#include "pch.h"
#include "EncryptionLib.h"
#include <wincrypt.h>
#include <cstring>
#include <stdexcept>
#include <sstream>


std::string EncryptionLib::GetLastErrorAsString() {
    DWORD error = GetLastError();
    if (error == 0) {
        return "No error";
    }

    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&messageBuffer,
        0,
        NULL
    );

    std::string message(messageBuffer, size);
    LocalFree(messageBuffer);
    return message;
}

#pragma pack(push, 1)
typedef struct {
    BLOBHEADER hdr;
    DWORD dwKeySize;
    BYTE rgbKeyData[32];
} CustomKeyBlob;
#pragma pack(pop)

EncryptionLib::EncryptionLib() : hProvider(0), hKey(0) {
    InitializeProvider();
}

EncryptionLib::~EncryptionLib() {
    if (hKey) {
        CryptDestroyKey(hKey);
    }
    if (hProvider) {
        CryptReleaseContext(hProvider, 0);
    }
}

void EncryptionLib::InitializeProvider() {
    if (!CryptAcquireContext(&hProvider, NULL, MS_ENH_RSA_AES_PROV,
        PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        throw std::runtime_error("Error al inicializar el proveedor de encriptacion");
    }
}


void EncryptionLib::ImportKey() {
    // Crear y configurar el blob de la clave
    CustomKeyBlob keyBlob = {};
    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_AES_256;
    keyBlob.dwKeySize = 32;

    // Copiar la clave al blob
    memcpy(keyBlob.rgbKeyData, key.data(), 32);

    // Importar la clave
    if (!CryptImportKey(hProvider, reinterpret_cast<BYTE*>(&keyBlob),
        sizeof(CustomKeyBlob), 0, 0, &hKey)) {
        throw std::runtime_error("Error al importar la clave");
    }
}

std::vector<uint8_t> EncryptionLib::GenerateKey() {
    std::vector<uint8_t> newKey(32); // AES-256
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (auto& byte : newKey) {
        byte = static_cast<uint8_t>(dis(gen));
    }

    return newKey;
}

void EncryptionLib::SetKey(const std::vector<uint8_t>& newKey) {
    if (newKey.size() != 32) {
        throw std::runtime_error("La clave debe ser de 32 bytes (256 bits)");
    }

    if (hKey) {
        CryptDestroyKey(hKey);
        hKey = 0;
    }

    key = newKey;
    ImportKey();
}

void EncryptionLib::SaveKeyToFile(const std::wstring& keyPath) {
    std::ofstream file(keyPath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("No se puede guardar la clave");
    }
    file.write(reinterpret_cast<const char*>(key.data()), key.size());
}

void EncryptionLib::LoadKeyFromFile(const std::wstring& keyPath) {
    std::ifstream file(keyPath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("No se puede cargar la clave");
    }

    std::vector<uint8_t> newKey(32);
    file.read(reinterpret_cast<char*>(newKey.data()), 32);
    SetKey(newKey);
}

std::vector<uint8_t> EncryptionLib::EncryptData(const std::vector<uint8_t>& data) {
    if (!hKey) {
        throw std::runtime_error("Clave no inicializada");
    }

    if (data.empty()) {
        throw std::runtime_error("Los datos de entrada estan vacios");
    }

    // Calcular el tamaño del buffer necesario
    DWORD encryptedSize = static_cast<DWORD>(data.size());
    if (!CryptEncrypt(hKey, 0, TRUE, 0, nullptr, &encryptedSize, 0)) {
        std::stringstream ss;
        ss << "Error al calcular el tamaño necesario para encriptar: " << GetLastErrorAsString();
        throw std::runtime_error(ss.str());
    }

    // Crear buffer con el tamaño necesario
    std::vector<uint8_t> encrypted(encryptedSize);
    memcpy(encrypted.data(), data.data(), data.size());

    DWORD dataSize = static_cast<DWORD>(data.size());
    if (!CryptEncrypt(hKey, 0, TRUE, 0, encrypted.data(), &dataSize, encryptedSize)) {
        std::stringstream ss;
        ss << "Error durante la encriptacion: " << GetLastErrorAsString();
        throw std::runtime_error(ss.str());
    }

    return encrypted;
}

std::vector<uint8_t> EncryptionLib::DecryptData(const std::vector<uint8_t>& encrypted) {
    if (!hKey) {
        throw std::runtime_error("Clave no inicializada");
    }

    std::vector<uint8_t> decrypted = encrypted;
    DWORD size = static_cast<DWORD>(encrypted.size());

    if (!CryptDecrypt(hKey, 0, TRUE, 0, decrypted.data(), &size)) {
        throw std::runtime_error("Error al desencriptar datos");
    }

    decrypted.resize(size);
    return decrypted;
}

void EncryptionLib::EncryptFile(const std::wstring& inputPath, const std::wstring& outputPath) {
    std::ifstream inFile(inputPath, std::ios::binary);
    if (!inFile.is_open()) {
        throw std::runtime_error("No se puede abrir el archivo de entrada: " + std::string(inputPath.begin(), inputPath.end()));
    }

    // Leer el archivo de entrada
    inFile.seekg(0, std::ios::end);
    size_t fileSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);

    if (fileSize == 0) {
        throw std::runtime_error("El archivo de entrada esta vacio");
    }

    std::vector<uint8_t> data(fileSize);
    inFile.read(reinterpret_cast<char*>(data.data()), fileSize);
    inFile.close();

    if (!inFile) {
        throw std::runtime_error("Error al leer el archivo de entrada");
    }

    // Encriptar los datos
    auto encrypted = EncryptData(data);

    // Guardar los datos encriptados
    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile.is_open()) {
        throw std::runtime_error("No se puede crear el archivo de salida: " + std::string(outputPath.begin(), outputPath.end()));
    }

    outFile.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
    if (!outFile) {
        throw std::runtime_error("Error al escribir el archivo encriptado");
    }
}

void EncryptionLib::DecryptFile(const std::wstring& inputPath, const std::wstring& outputPath) {
    std::ifstream inFile(inputPath, std::ios::binary);
    if (!inFile.is_open()) {
        throw std::runtime_error("No se puede abrir el archivo encriptado");
    }

    std::vector<uint8_t> encrypted(
        (std::istreambuf_iterator<char>(inFile)),
        std::istreambuf_iterator<char>()
    );

    auto decrypted = DecryptData(encrypted);

    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile.is_open()) {
        throw std::runtime_error("No se puede crear el archivo desencriptado");
    }

    outFile.write(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
}