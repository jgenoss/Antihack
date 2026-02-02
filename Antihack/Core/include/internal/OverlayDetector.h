/**
 * AntiCheatCore - Overlay Detector Module
 * Detects external overlay cheats (ESP, wallhacks via transparent windows)
 */

#pragma once

#ifndef AC_OVERLAY_DETECTOR_H
#define AC_OVERLAY_DETECTOR_H

#include "common.h"
#include <dwmapi.h>

#pragma comment(lib, "dwmapi.lib")

namespace AntiCheat {

class OverlayDetector {
public:
    // Window information
    struct WindowInfo {
        HWND hwnd;
        std::wstring className;
        std::wstring windowTitle;
        std::wstring processName;
        DWORD processId;
        RECT rect;
        BYTE opacity;
        bool isLayered;
        bool isTopmost;
        bool isTransparent;
        bool isClickThrough;
        bool isFullscreen;
        bool isSuspicious;
        std::string suspicionReason;
    };

    // Known overlay programs
    struct OverlaySignature {
        std::wstring processName;
        std::wstring className;
        std::wstring windowTitle;
        bool isCheat;           // true = definite cheat, false = suspicious tool
        Severity severity;
        std::string description;
    };

    // Detection result
    struct DetectionResult {
        bool detected;
        WindowInfo window;
        std::string reason;
        Severity severity;
    };

    using DetectionCallback = std::function<void(const DetectionResult&)>;

private:
    // Target game window
    HWND m_gameWindow;
    RECT m_gameRect;
    std::wstring m_gameClassName;
    std::wstring m_gameTitle;
    DWORD m_gameProcessId;

    // Known signatures
    std::vector<OverlaySignature> m_signatures;
    std::set<std::wstring> m_whitelistedProcesses;
    std::set<std::wstring> m_whitelistedClasses;

    // Detected windows
    std::vector<WindowInfo> m_overlayWindows;

    // Monitoring
    std::atomic<bool> m_monitoring{false};
    HANDLE m_monitorThread;
    DWORD m_monitorInterval;

    // Callbacks
    DetectionCallback m_detectionCallback;
    DetectionCallback m_onOverlayFound;

    // Sync
    std::mutex m_mutex;
    std::string m_lastError;

    // Internal methods
    static DWORD WINAPI MonitorThreadProc(LPVOID param);
    void MonitorLoop();

    static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
    void ProcessWindow(HWND hwnd);

    // Analysis
    bool IsWindowOverGame(HWND hwnd);
    bool IsWindowTransparent(HWND hwnd);
    bool IsWindowLayered(HWND hwnd);
    bool IsWindowClickThrough(HWND hwnd);
    bool IsWindowTopmost(HWND hwnd);
    bool IsWindowFullscreen(HWND hwnd);
    bool MatchesSignature(const WindowInfo& info, const OverlaySignature& sig);

    // Process info
    std::wstring GetProcessNameFromWindow(HWND hwnd);
    DWORD GetProcessIdFromWindow(HWND hwnd);

public:
    OverlayDetector();
    ~OverlayDetector();

    // Initialization
    bool Initialize();
    void Shutdown();

    // Game window setup
    bool SetGameWindow(HWND hwnd);
    bool SetGameWindow(const std::wstring& windowTitle);
    bool SetGameWindowByClass(const std::wstring& className);
    bool SetGameWindowByProcess(DWORD processId);
    HWND GetGameWindow() const { return m_gameWindow; }

    // Signatures
    void AddSignature(const OverlaySignature& sig);
    void AddCheatSignature(const std::wstring& processName, const std::wstring& className,
                           const std::wstring& windowTitle, const std::string& description);
    void AddSuspiciousSignature(const std::wstring& processName, const std::wstring& className);
    void LoadDefaultSignatures();
    void ClearSignatures();

    // Whitelist
    void AddWhitelistedProcess(const std::wstring& processName);
    void AddWhitelistedClass(const std::wstring& className);
    void ClearWhitelist();
    bool IsWhitelisted(const WindowInfo& info);

    // Monitoring
    bool StartMonitoring(DWORD intervalMs = 500);
    void StopMonitoring();
    bool IsMonitoring() const { return m_monitoring; }

    // Manual scanning
    std::vector<WindowInfo> ScanForOverlays();
    std::vector<DetectionResult> DetectCheatOverlays();
    bool HasSuspiciousOverlays();

    // Window analysis
    WindowInfo GetWindowInfo(HWND hwnd);
    bool IsOverlayWindow(HWND hwnd);
    bool IsSuspiciousOverlay(const WindowInfo& info);

    // Direct3D/Graphics hook detection
    bool CheckD3DHooks();
    bool CheckDWMComposition();

    // Callbacks
    void SetDetectionCallback(DetectionCallback callback) { m_detectionCallback = callback; }
    void SetOverlayFoundCallback(DetectionCallback callback) { m_onOverlayFound = callback; }

    // Status
    int GetOverlayCount() const { return static_cast<int>(m_overlayWindows.size()); }
    const std::vector<WindowInfo>& GetDetectedOverlays() const { return m_overlayWindows; }
    const std::string& GetLastError() const { return m_lastError; }
};

} // namespace AntiCheat

#endif // AC_OVERLAY_DETECTOR_H
