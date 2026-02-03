/**
 * AntiCheatCore - Overlay Detector Module
 * Detects external overlay cheats (ESP, wallhacks via transparent windows)
 */

#pragma once

#ifndef AC_OVERLAY_DETECTOR_H
#define AC_OVERLAY_DETECTOR_H

#include "IMonitorModule.h"
#include <dwmapi.h>

#pragma comment(lib, "dwmapi.lib")

namespace AntiCheat {

/**
 * Detects overlay windows that may be used for ESP/wallhacks.
 * Inherits from IMonitorModule for thread-safe monitoring.
 */
class OverlayDetector : public TypedMonitorModule<struct OverlayDetector::DetectionResult> {
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

        WindowInfo()
            : hwnd(NULL)
            , processId(0)
            , opacity(255)
            , isLayered(false)
            , isTopmost(false)
            , isTransparent(false)
            , isClickThrough(false)
            , isFullscreen(false)
            , isSuspicious(false) {
            ZeroMemory(&rect, sizeof(rect));
        }
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

        DetectionResult() : detected(false), severity(Severity::Info) {}
    };

    using OverlayCallback = std::function<void(const DetectionResult&)>;

private:
    // Target game window (protected by m_dataMutex from base class)
    HWND m_gameWindow;
    RECT m_gameRect;
    std::wstring m_gameClassName;
    std::wstring m_gameTitle;
    DWORD m_gameProcessId;

    // Known signatures
    std::vector<OverlaySignature> m_signatures;
    std::set<std::wstring> m_whitelistedProcesses;
    std::set<std::wstring> m_whitelistedClasses;

    // Detected windows (protected by m_dataMutex)
    std::vector<WindowInfo> m_overlayWindows;

    // Additional callback for overlay-specific events
    OverlayCallback m_overlayCallback;

    // EnumWindows context
    struct EnumContext {
        OverlayDetector* detector;
        RECT gameRect;
        std::vector<WindowInfo> windows;
    };

    // Internal methods
    static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
    void ProcessWindow(HWND hwnd, EnumContext& ctx);

    // Analysis (all thread-safe, read-only operations)
    bool IsWindowOverGame(HWND hwnd, const RECT& gameRect);
    bool IsWindowTransparent(HWND hwnd);
    bool IsWindowLayered(HWND hwnd);
    bool IsWindowClickThrough(HWND hwnd);
    bool IsWindowTopmost(HWND hwnd);
    bool IsWindowFullscreen(HWND hwnd);
    bool MatchesSignature(const WindowInfo& info, const OverlaySignature& sig);

    // Process info
    std::wstring GetProcessNameFromWindow(HWND hwnd);
    DWORD GetProcessIdFromWindow(HWND hwnd);

protected:
    /**
     * Override from IMonitorModule - performs one monitoring cycle.
     * Called periodically by the monitoring thread.
     */
    void DoMonitorCycle() override;

public:
    OverlayDetector();
    virtual ~OverlayDetector();

    // Initialization (override from base)
    bool Initialize() override;
    void Shutdown() override;

    // Game window setup (thread-safe)
    bool SetGameWindow(HWND hwnd);
    bool SetGameWindow(const std::wstring& windowTitle);
    bool SetGameWindowByClass(const std::wstring& className);
    bool SetGameWindowByProcess(DWORD processId);

    HWND GetGameWindow() const {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        return m_gameWindow;
    }

    // Signatures (thread-safe)
    void AddSignature(const OverlaySignature& sig);
    void AddCheatSignature(const std::wstring& processName, const std::wstring& className,
                           const std::wstring& windowTitle, const std::string& description);
    void AddSuspiciousSignature(const std::wstring& processName, const std::wstring& className);
    void LoadDefaultSignatures();
    void ClearSignatures();

    // Whitelist (thread-safe)
    void AddWhitelistedProcess(const std::wstring& processName);
    void AddWhitelistedClass(const std::wstring& className);
    void ClearWhitelist();
    bool IsWhitelisted(const WindowInfo& info);

    // Manual scanning (thread-safe)
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

    // Callbacks (thread-safe, invoked outside of locks)
    void SetOverlayFoundCallback(OverlayCallback callback) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_overlayCallback = callback;
    }

    // Status (thread-safe)
    int GetOverlayCount() const {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        return static_cast<int>(m_overlayWindows.size());
    }

    std::vector<WindowInfo> GetDetectedOverlays() const {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        return m_overlayWindows;  // Return copy for thread safety
    }
};

} // namespace AntiCheat

#endif // AC_OVERLAY_DETECTOR_H
