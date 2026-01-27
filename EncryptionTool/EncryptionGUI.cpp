// EncryptionGUI.cpp
#include "EncryptionGUI.h"
#include <CommCtrl.h>
#pragma comment(lib, "comctl32.lib")

EncryptionGUI* EncryptionGUI::instance = nullptr;

// Constructor actualizado con lista de inicializacion
EncryptionGUI::EncryptionGUI()
    : hwnd(nullptr)
    , btnGenerateKey(nullptr)
    , btnEncrypt(nullptr)
    , btnDecrypt(nullptr)
    , btnSelectKey(nullptr)
    , txtStatus(nullptr)
    , currentKeyPath(L"") {
    instance = this;
}

EncryptionGUI::~EncryptionGUI() {
    instance = nullptr;
}

bool EncryptionGUI::Initialize(HINSTANCE hInstance) {
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"EncryptionGUIClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);

    if (!RegisterClassEx(&wc)) {
        return false;
    }

    hwnd = CreateWindowEx(
        0,
        L"EncryptionGUIClass",
        L"Herramienta de Encriptacion",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        500, 300,
        nullptr,
        nullptr,
        hInstance,
        nullptr
    );

    if (!hwnd) {
        return false;
    }

    CreateControls();
    return true;
}

void EncryptionGUI::CreateControls() {
    // Crear botones
    btnGenerateKey = CreateWindow(
        L"BUTTON", L"Generar Nueva Clave",
        WS_VISIBLE | WS_CHILD,
        20, 20, 150, 30,
        hwnd, (HMENU)1, nullptr, nullptr
    );

    btnSelectKey = CreateWindow(
        L"BUTTON", L"Seleccionar Clave",
        WS_VISIBLE | WS_CHILD,
        180, 20, 150, 30,
        hwnd, (HMENU)2, nullptr, nullptr
    );

    btnEncrypt = CreateWindow(
        L"BUTTON", L"Encriptar Archivo",
        WS_VISIBLE | WS_CHILD,
        20, 60, 150, 30,
        hwnd, (HMENU)3, nullptr, nullptr
    );

    btnDecrypt = CreateWindow(
        L"BUTTON", L"Desencriptar Archivo",
        WS_VISIBLE | WS_CHILD,
        180, 60, 150, 30,
        hwnd, (HMENU)4, nullptr, nullptr
    );

    // Crear area de estado
    txtStatus = CreateWindow(
        L"EDIT", L"",
        WS_VISIBLE | WS_CHILD | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
        20, 100, 440, 140,
        hwnd, (HMENU)5, nullptr, nullptr
    );
}

void EncryptionGUI::Show(int nCmdShow) {
    ShowWindow(hwnd, nCmdShow);
}

LRESULT CALLBACK EncryptionGUI::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (EncryptionGUI::GetInstance()) {
        return EncryptionGUI::GetInstance()->HandleMessage(hwnd, uMsg, wParam, lParam);
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

std::wstring EncryptionGUI::OpenFileDialog(bool save, const wchar_t* filter) {
    wchar_t filename[MAX_PATH] = {};
    OPENFILENAME ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

    bool result = save ? GetSaveFileName(&ofn) : GetOpenFileName(&ofn);
    return result ? filename : L"";
}

void EncryptionGUI::UpdateStatus(const std::wstring& message) {
    // Usar directamente wstring ya que Windows usa Unicode
    SetWindowTextW(txtStatus, message.c_str());
}

void EncryptionGUI::HandleCommand(WPARAM wParam) {
    switch (LOWORD(wParam)) {
    case 1: // Generar Nueva Clave
        try {
            std::wstring savePath = OpenFileDialog(true, L"Archivos de Clave (*.key)\0*.key\0Todos los archivos\0*.*\0");
            if (!savePath.empty()) {
                auto newKey = encryptor.GenerateKey();
                encryptor.SetKey(newKey);
                encryptor.SaveKeyToFile(savePath);
                currentKeyPath = savePath;
                UpdateStatus(L"Nueva clave generada y guardada en: " + savePath);
            }
        }
        catch (const std::exception& e) {
            // Convertir string a wstring de manera segura
            std::wstring errorMsg;
            try {
                int len = MultiByteToWideChar(CP_UTF8, 0, e.what(), -1, nullptr, 0);
                if (len > 0) {
                    errorMsg.resize(len - 1); // -1 porque no necesitamos el nulo terminador
                    MultiByteToWideChar(CP_UTF8, 0, e.what(), -1, &errorMsg[0], len);
                }
            }
            catch (...) {
                errorMsg = L"Error desconocido";
            }
            UpdateStatus(L"Error al generar la clave: " + errorMsg);
        }
        break;

    case 2: // Seleccionar Clave
        try {
            std::wstring keyPath = OpenFileDialog(false, L"Archivos de Clave (*.key)\0*.key\0Todos los archivos\0*.*\0");
            if (!keyPath.empty()) {
                encryptor.LoadKeyFromFile(keyPath);
                currentKeyPath = keyPath;
                UpdateStatus(L"Clave cargada desde: " + keyPath);
            }
        }
        catch (const std::exception& e) {
            UpdateStatus(L"Error al cargar la clave: " + std::wstring(e.what(), e.what() + strlen(e.what())));
        }
        break;

    case 3: // Encriptar Archivo
        if (currentKeyPath.empty()) {
            UpdateStatus(L"Por favor, seleccione una clave primero.");
            break;
        }
        try {
            std::wstring inputFile = OpenFileDialog(false, L"Todos los archivos\0*.*\0");
            if (!inputFile.empty()) {
                //std::wstring outputFile = OpenFileDialog(true, L"Archivos Encriptados (*.enc)\0*.enc\0Todos los archivos\0*.*\0");
                std::wstring outputFile = OpenFileDialog(true,
                    L"Archivos Encriptados (*.enc)\0*.enc\0"    // Filtro para archivos .enc
                    L"Archivos de datos (*.dat)\0*.dat\0"         // Filtro para archivos .dat
                    L"Archivos de texto (*.txt)\0*.txt\0"         // Filtro para archivos .txt
                    L"Todos los archivos (*.*)\0*.*\0");          // Filtro para todos los archivos
                if (!outputFile.empty()) {
                    encryptor.EncryptFile(inputFile, outputFile);
                    UpdateStatus(L"Archivo encriptado exitosamente: " + outputFile);
                }
            }
        }
        catch (const std::exception& e) {
            UpdateStatus(L"Error al encriptar: " + std::wstring(e.what(), e.what() + strlen(e.what())));
        }
        break;

    case 4: // Desencriptar Archivo
        if (currentKeyPath.empty()) {
            UpdateStatus(L"Por favor, seleccione una clave primero.");
            break;
        }
        try {
            //std::wstring inputFile = OpenFileDialog(false, L"Archivos Encriptados (*.enc)\0*.enc\0Todos los archivos\0*.*\0");
            std::wstring inputFile = OpenFileDialog(false,
                L"Archivos Encriptados (*.enc)\0*.enc\0"    // Filtro para archivos .enc
                L"Archivos de datos (*.dat)\0*.dat\0"         // Filtro para archivos .dat
                L"Archivos de texto (*.txt)\0*.txt\0"         // Filtro para archivos .txt
                L"Todos los archivos (*.*)\0*.*\0");          // Filtro para todos los archivos
            if (!inputFile.empty()) {
                std::wstring outputFile = OpenFileDialog(true, L"Todos los archivos\0*.*\0");
                if (!outputFile.empty()) {
                    encryptor.DecryptFile(inputFile, outputFile);
                    UpdateStatus(L"Archivo desencriptado exitosamente: " + outputFile);
                }
            }
        }
        catch (const std::exception& e) {
            UpdateStatus(L"Error al desencriptar: " + std::wstring(e.what(), e.what() + strlen(e.what())));
        }
        break;
    }
}

LRESULT EncryptionGUI::HandleMessage(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_COMMAND:
        HandleCommand(wParam);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}