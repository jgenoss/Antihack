// EncryptionGUI.h
#pragma once
#include <Windows.h>
#include <string>
#include "EncryptionLib.h"

class EncryptionGUI {
private:
    static EncryptionGUI* instance;
    HWND hwnd;
    HWND btnGenerateKey;
    HWND btnEncrypt;
    HWND btnDecrypt;
    HWND btnSelectKey;
    HWND txtStatus;
    EncryptionLib encryptor;
    std::wstring currentKeyPath;

    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    void CreateControls();
    void HandleCommand(WPARAM wParam);
    std::wstring OpenFileDialog(bool save, const wchar_t* filter);
    void UpdateStatus(const std::wstring& message);

public:
    EncryptionGUI();
    ~EncryptionGUI();
    bool Initialize(HINSTANCE hInstance);
    void Show(int nCmdShow);
    static EncryptionGUI* GetInstance() { return instance; }
};