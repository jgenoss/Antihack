#include "pch.h"
#include "LoadingScreen.h"
#include <CommCtrl.h>
#include <iostream>
#include <memory>
#include <vector> // Añadir esta línea
#include <codecvt>

#pragma comment(lib, "Comctl32.lib")

// Constructor
LoadingScreen loadingScreen;
    // Constructor
LoadingScreen::LoadingScreen() : progress(0), isRunning(false), currentState(ScreenState::Loading),
errorBrush(CreateSolidBrush(RGB(255, 200, 200))),
detectionBrush(CreateSolidBrush(RGB(255, 255, 200))),
loadingImage(nullptr), detectionImage(nullptr), errorImage(nullptr), connectionErrorImage(nullptr) {

    InitializeGDIPlus();
    LoadImages();
    InitializeCommonControls();
    RegisterWindowClass();
    CreateProgressWindow();
}

// Destructor
LoadingScreen::~LoadingScreen() {
    if (isRunning) Hide();
    DeleteObject(errorBrush);
    DeleteObject(detectionBrush);
    CleanupImages();
    Gdiplus::GdiplusShutdown(gdiplusToken);
}

// ** Inicialización modularizada ** 
void LoadingScreen::InitializeGDIPlus() {
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
}

void LoadingScreen::InitializeCommonControls() {
    INITCOMMONCONTROLSEX icex{ sizeof(INITCOMMONCONTROLSEX), ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icex);
}

void LoadingScreen::RegisterWindowClass() {
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_HREDRAW | CS_VREDRAW, WindowProc,
                      0, 0, GetModuleHandle(NULL), NULL, LoadCursor(NULL, IDC_ARROW),
                      (HBRUSH)(COLOR_WINDOW + 1), NULL, L"AntiCheatLoader", NULL };

    RegisterClassEx(&wc);
}
void LoadingScreen::Show() {
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    isRunning = true;
}

void LoadingScreen::Hide() {
    ShowWindow(hwnd, SW_HIDE);
    isRunning = false;
}

void LoadingScreen::SetProgress(int value) {
    progress = value;
    SendMessage(progressBar, PBM_SETPOS, progress, 0);
}

// ** Manejo automático de imágenes con unique_ptr **
void LoadingScreen::LoadImages() {
    struct ImageInfo {
        std::wstring path;
        std::shared_ptr<Gdiplus::Image>& imagePtr;
    };

    std::vector<ImageInfo> imagesToLoad = {
        { L"assets/loading_bg.bmp", loadingImage },
        { L"assets/detection_bg.bmp", detectionImage },
        { L"assets/error_bg.bmp", errorImage },
        { L"assets/connection_error_bg.bmp", connectionErrorImage }
    };

    for (auto& img : imagesToLoad) {
        img.imagePtr = std::make_shared<Gdiplus::Image>(img.path.c_str());
        if (img.imagePtr->GetLastStatus() != Gdiplus::Ok) {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            std::string imgPathStr = converter.to_bytes(img.path);
            std::cerr << "[ERROR] No se pudo cargar la imagen: " << imgPathStr << std::endl;
            img.imagePtr.reset();  // Liberar si falló la carga
        }
    }
}

// Limpieza de imágenes (ahora manejadas con unique_ptr)
void LoadingScreen::CleanupImages() {
    loadingImage.reset();
    detectionImage.reset();
    errorImage.reset();
    connectionErrorImage.reset();
}

// ** Creación de la ventana y la barra de progreso **
void LoadingScreen::CreateProgressWindow() {
    hwnd = CreateWindowEx(WS_EX_TOPMOST, L"AntiCheatLoader", L"Anti-Cheat Loading... by JGenoss",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, WINDOW_WIDTH, WINDOW_HEIGHT,
        NULL, NULL, GetModuleHandle(NULL), this);

    if (!hwnd) {
        std::cerr << "[ERROR] No se pudo crear la ventana. Error: " << GetLastError() << std::endl;
        return;
    }

    progressBar = CreateWindowEx(0, PROGRESS_CLASS, NULL, WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
        12, 175, WINDOW_WIDTH - 40, 12, hwnd, NULL, GetModuleHandle(NULL), NULL);

    SendMessage(progressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    CenterWindow();
}

void LoadingScreen::CenterWindow() {
    RECT rc;
    GetWindowRect(hwnd, &rc);
    int x = (GetSystemMetrics(SM_CXSCREEN) - (rc.right - rc.left)) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - (rc.bottom - rc.top)) / 2;
    SetWindowPos(hwnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

// ** Actualización de estilos de ventana según estado **
void LoadingScreen::UpdateWindowStyle() {
    LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);

    if (currentState == ScreenState::Loading) {
        style &= ~WS_SYSMENU; // Ocultar botón de cierre
        ShowWindow(progressBar, SW_SHOW);
    }
    else {
        style |= WS_SYSMENU;  // Mostrar botón de cierre
        ShowWindow(progressBar, SW_HIDE);
    }

    SetWindowLongPtr(hwnd, GWL_STYLE, style);
    SetWindowPos(hwnd, NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
}

// ** Renderizado de fondo según el estado actual **
void LoadingScreen::DrawBackground(HDC hdc, RECT& rect) {
    Gdiplus::Graphics graphics(hdc);
    Gdiplus::Image* currentImage = nullptr;

    switch (currentState) {
    case ScreenState::Loading: currentImage = loadingImage.get(); break;
    case ScreenState::Detection: currentImage = detectionImage.get(); break;
    case ScreenState::Error: currentImage = errorImage.get(); break;
    case ScreenState::ConnectionError: currentImage = connectionErrorImage.get(); break;
    }

    if (currentImage) {
        graphics.DrawImage(currentImage, Gdiplus::Rect(0, 0, rect.right - rect.left, rect.bottom - rect.top),
            0, 0, currentImage->GetWidth(), currentImage->GetHeight(), Gdiplus::UnitPixel);
    }
}

// ** Métodos para mostrar la ventana con distintos estados **
void LoadingScreen::ShowState(ScreenState state, const std::wstring& message) {
    currentState = state;
    currentMessage = message;
    UpdateWindowStyle();
    Show();
    InvalidateRect(hwnd, NULL, TRUE);
}

void LoadingScreen::ShowLoading(const std::wstring& message) {
    ShowState(ScreenState::Loading, message);
}
void LoadingScreen::ShowDetection(const std::wstring& threat) {
    ShowState(ScreenState::Detection, L"Detección de Amenaza\n\n" + threat); MessageBeep(MB_ICONWARNING);
}
void LoadingScreen::ShowError(const std::wstring& error) {
    ShowState(ScreenState::Error, L"Error\n\n" + error); MessageBeep(MB_ICONERROR);
}
void LoadingScreen::ShowConnectionError(const std::wstring& error) {
    ShowState(ScreenState::ConnectionError, L"Error de Conexión\n\n" + error); MessageBeep(MB_ICONERROR);
}

// ** Procesamiento de eventos de la ventana **
LRESULT CALLBACK LoadingScreen::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    LoadingScreen* screen = reinterpret_cast<LoadingScreen*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));

    switch (uMsg) {
    case WM_CREATE:
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(reinterpret_cast<LPCREATESTRUCT>(lParam)->lpCreateParams));
        return 0;

    case WM_PAINT:
        if (screen) {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT clientRect;
            GetClientRect(hwnd, &clientRect);
            screen->DrawBackground(hdc, clientRect);

            SetTextColor(hdc, RGB(255, 255, 255));
            SetBkMode(hdc, TRANSPARENT);
            RECT textRect = { 20, 145, WINDOW_WIDTH - 20, WINDOW_HEIGHT - 20 };

            DrawTextW(hdc, screen->currentMessage.c_str(), -1, &textRect, DT_CENTER | DT_WORDBREAK);

            EndPaint(hwnd, &ps);
        }
        return 0;

    case WM_CLOSE:
        if (screen && screen->currentState != ScreenState::Loading)
            ShowWindow(hwnd, SW_HIDE);
        
        return 0;

    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}
