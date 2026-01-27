#include <iostream>
#include <Windows.h>
#include <string>
#include <iomanip>
#include <io.h>
#include <fcntl.h>
#include "FileProtection.h"

// Función auxiliar para convertir string a wstring
std::wstring ConvertToWideString(const std::string& str) {
    if (str.empty()) return std::wstring();

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

std::vector<std::wstring> GetFilesInDirectory(const std::wstring& directory) {
    std::vector<std::wstring> files;
    WIN32_FIND_DATAW findData;

    // Buscar todos los archivos en el directorio
    std::wstring searchPath = directory + L"\\*.*";
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring filename(findData.cFileName);
            // Ignorar . y ..
            if (filename != L"." && filename != L"..") {
                // Ignorar directorios
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    files.push_back(filename);
                }
            }
        } while (FindNextFileW(hFind, &findData));

        FindClose(hFind);
    }

    return files;
}

int main() {
    // Configurar consola para UTF-16
    _setmode(_fileno(stdout), _O_U16TEXT);

    try {
        FileProtection fp;
        std::wcout << L"Calculando CRC32 de archivos en el directorio actual...\n\n";

        // Obtener lista de archivos
        auto files = GetFilesInDirectory(fp.baseGamePath);

        // Calcular CRC para cada archivo
        for (const auto& file : files) {
            try {
                std::wstring fullPath = fp.GetFullPath(file);
                auto fileData = fp.ReadFileBytes(fullPath);
                uint32_t crc = fp.CalculateCRC32(fileData);

                // Mostrar resultado
                std::wcout << std::hex << std::uppercase << std::setfill(L'0') << std::setw(8)
                    << crc << L" - " << file << std::endl;
            }
            catch (const std::exception& e) {
                std::wcout << L"Error al procesar '" << file << L"': "
                    << ConvertToWideString(e.what()) << std::endl;
            }
        }
    }
    catch (const std::exception& e) {
        std::wcerr << L"Error: " << ConvertToWideString(e.what()) << std::endl;
        return 1;
    }

    std::wcout << L"\nPresione Enter para salir...";
    std::wcin.get();
    return 0;
}