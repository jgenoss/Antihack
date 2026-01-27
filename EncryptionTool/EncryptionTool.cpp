
// EncryptionTool.cpp
#include <Windows.h>
#include <CommCtrl.h>
#include "EncryptionGUI.h"

// Forzar el subsistema Windows
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")

// Manifiesto para los controles comunes
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#pragma comment(lib, "comctl32.lib")

// Único punto de entrada - version Unicode
int WINAPI wWinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR lpCmdLine,
    _In_ int nCmdShow)
{
    // Inicializar controles comunes
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icex);

    EncryptionGUI gui;

    if (!gui.Initialize(hInstance)) {
        MessageBoxW(nullptr, L"Error al inicializar la aplicacion", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    gui.Show(nCmdShow);

    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return static_cast<int>(msg.wParam);
}