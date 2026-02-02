/**
 * AntiCheatCore - Overlay Detector Implementation
 * Detects external overlay cheats (ESP, wallhacks via transparent windows)
 */

#include "stdafx.h"
#include "../include/internal/OverlayDetector.h"

namespace AntiCheat {

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

OverlayDetector::OverlayDetector()
    : m_gameWindow(nullptr),
      m_gameProcessId(0),
      m_monitorThread(nullptr),
      m_monitorInterval(500) {
    m_gameRect = { 0, 0, 0, 0 };
}

OverlayDetector::~OverlayDetector() {
    Shutdown();
}

// ============================================================================
// INITIALIZATION
// ============================================================================

bool OverlayDetector::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Add default whitelisted system windows
    m_whitelistedClasses.insert(L"Shell_TrayWnd");           // Taskbar
    m_whitelistedClasses.insert(L"Windows.UI.Core.CoreWindow");
    m_whitelistedClasses.insert(L"TaskListThumbnailWnd");
    m_whitelistedClasses.insert(L"NotifyIconOverflowWindow");
    m_whitelistedClasses.insert(L"tooltips_class32");

    // Whitelist common legitimate overlays
    m_whitelistedProcesses.insert(L"explorer.exe");
    m_whitelistedProcesses.insert(L"dwm.exe");
    m_whitelistedProcesses.insert(L"csrss.exe");

    LoadDefaultSignatures();

    return true;
}

void OverlayDetector::Shutdown() {
    StopMonitoring();

    std::lock_guard<std::mutex> lock(m_mutex);
    m_signatures.clear();
    m_overlayWindows.clear();
    m_gameWindow = nullptr;
}

// ============================================================================
// GAME WINDOW SETUP
// ============================================================================

bool OverlayDetector::SetGameWindow(HWND hwnd) {
    if (!IsWindow(hwnd)) {
        m_lastError = "Invalid window handle";
        return false;
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    m_gameWindow = hwnd;
    GetWindowRect(hwnd, &m_gameRect);
    GetWindowThreadProcessId(hwnd, &m_gameProcessId);

    // Get class name
    wchar_t className[256];
    GetClassNameW(hwnd, className, 256);
    m_gameClassName = className;

    // Get window title
    wchar_t title[256];
    GetWindowTextW(hwnd, title, 256);
    m_gameTitle = title;

    return true;
}

bool OverlayDetector::SetGameWindow(const std::wstring& windowTitle) {
    HWND hwnd = FindWindowW(nullptr, windowTitle.c_str());
    if (!hwnd) {
        m_lastError = "Window not found: " + WStringToString(windowTitle);
        return false;
    }
    return SetGameWindow(hwnd);
}

bool OverlayDetector::SetGameWindowByClass(const std::wstring& className) {
    HWND hwnd = FindWindowW(className.c_str(), nullptr);
    if (!hwnd) {
        m_lastError = "Window class not found: " + WStringToString(className);
        return false;
    }
    return SetGameWindow(hwnd);
}

bool OverlayDetector::SetGameWindowByProcess(DWORD processId) {
    struct EnumData {
        DWORD processId;
        HWND result;
    } data = { processId, nullptr };

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        EnumData* data = reinterpret_cast<EnumData*>(lParam);
        DWORD pid;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid == data->processId && IsWindowVisible(hwnd)) {
            HWND owner = GetWindow(hwnd, GW_OWNER);
            if (!owner) {
                data->result = hwnd;
                return FALSE;
            }
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&data));

    if (!data.result) {
        m_lastError = "No window found for process";
        return false;
    }
    return SetGameWindow(data.result);
}

// ============================================================================
// SIGNATURES
// ============================================================================

void OverlayDetector::AddSignature(const OverlaySignature& sig) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_signatures.push_back(sig);
}

void OverlayDetector::AddCheatSignature(const std::wstring& processName,
                                         const std::wstring& className,
                                         const std::wstring& windowTitle,
                                         const std::string& description) {
    OverlaySignature sig;
    sig.processName = processName;
    sig.className = className;
    sig.windowTitle = windowTitle;
    sig.isCheat = true;
    sig.severity = Severity::Critical;
    sig.description = description;
    AddSignature(sig);
}

void OverlayDetector::AddSuspiciousSignature(const std::wstring& processName,
                                              const std::wstring& className) {
    OverlaySignature sig;
    sig.processName = processName;
    sig.className = className;
    sig.isCheat = false;
    sig.severity = Severity::Warning;
    sig.description = "Suspicious overlay tool";
    AddSignature(sig);
}

void OverlayDetector::LoadDefaultSignatures() {
    // Known cheat overlays
    AddCheatSignature(L"", L"CEF-OSC-WIDGET", L"", "Cheat overlay framework");
    AddCheatSignature(L"", L"overlay", L"", "Generic cheat overlay");
    AddCheatSignature(L"", L"D3DOverlay", L"", "Direct3D overlay cheat");
    AddCheatSignature(L"", L"UnityWndClass", L"Overlay", "Unity-based overlay");

    // Suspicious tools (could be legitimate but often used for cheats)
    AddSuspiciousSignature(L"obs64.exe", L"");      // OBS (legitimate but can hide overlays)
    AddSuspiciousSignature(L"obs32.exe", L"");
    AddSuspiciousSignature(L"", L"MicrosoftEdgeWebView2");  // WebView overlays

    // ESP/Wallhack common patterns
    AddCheatSignature(L"", L"", L"ESP", "ESP overlay detected");
    AddCheatSignature(L"", L"", L"Aimbot", "Aimbot overlay detected");
    AddCheatSignature(L"", L"", L"Wallhack", "Wallhack overlay detected");
    AddCheatSignature(L"", L"", L"Cheat", "Cheat overlay detected");
    AddCheatSignature(L"", L"", L"Hack", "Hack overlay detected");

    // Known cheat programs
    AddCheatSignature(L"cheat", L"", L"", "Cheat program detected");
    AddCheatSignature(L"hack", L"", L"", "Hack program detected");
    AddCheatSignature(L"injector", L"", L"", "Injector program detected");
}

void OverlayDetector::ClearSignatures() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_signatures.clear();
}

// ============================================================================
// WHITELIST
// ============================================================================

void OverlayDetector::AddWhitelistedProcess(const std::wstring& processName) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::wstring lower = processName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    m_whitelistedProcesses.insert(lower);
}

void OverlayDetector::AddWhitelistedClass(const std::wstring& className) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_whitelistedClasses.insert(className);
}

void OverlayDetector::ClearWhitelist() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_whitelistedProcesses.clear();
    m_whitelistedClasses.clear();
}

bool OverlayDetector::IsWhitelisted(const WindowInfo& info) {
    std::wstring lowerProcess = info.processName;
    std::transform(lowerProcess.begin(), lowerProcess.end(), lowerProcess.begin(), ::towlower);

    if (m_whitelistedProcesses.find(lowerProcess) != m_whitelistedProcesses.end()) {
        return true;
    }
    if (m_whitelistedClasses.find(info.className) != m_whitelistedClasses.end()) {
        return true;
    }
    return false;
}

// ============================================================================
// MONITORING
// ============================================================================

bool OverlayDetector::StartMonitoring(DWORD intervalMs) {
    if (m_monitoring) return true;

    if (!m_gameWindow) {
        m_lastError = "Game window not set";
        return false;
    }

    m_monitorInterval = intervalMs;
    m_monitoring = true;

    m_monitorThread = CreateThread(nullptr, 0, MonitorThreadProc, this, 0, nullptr);
    if (!m_monitorThread) {
        m_monitoring = false;
        m_lastError = "Failed to create monitor thread";
        return false;
    }

    return true;
}

void OverlayDetector::StopMonitoring() {
    if (!m_monitoring) return;

    m_monitoring = false;

    if (m_monitorThread) {
        WaitForSingleObject(m_monitorThread, 5000);
        CloseHandle(m_monitorThread);
        m_monitorThread = nullptr;
    }
}

DWORD WINAPI OverlayDetector::MonitorThreadProc(LPVOID param) {
    OverlayDetector* self = static_cast<OverlayDetector*>(param);
    self->MonitorLoop();
    return 0;
}

void OverlayDetector::MonitorLoop() {
    while (m_monitoring) {
        // Update game window rect
        if (m_gameWindow && IsWindow(m_gameWindow)) {
            GetWindowRect(m_gameWindow, &m_gameRect);
        }

        // Scan for overlays
        auto results = DetectCheatOverlays();

        for (const auto& result : results) {
            if (result.detected && m_detectionCallback) {
                m_detectionCallback(result);
            }
        }

        Sleep(m_monitorInterval);
    }
}

// ============================================================================
// SCANNING
// ============================================================================

BOOL CALLBACK OverlayDetector::EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    OverlayDetector* self = reinterpret_cast<OverlayDetector*>(lParam);
    self->ProcessWindow(hwnd);
    return TRUE;
}

void OverlayDetector::ProcessWindow(HWND hwnd) {
    // Skip our own game window
    if (hwnd == m_gameWindow) return;

    // Must be visible
    if (!IsWindowVisible(hwnd)) return;

    WindowInfo info = GetWindowInfo(hwnd);

    // Check if over game
    if (!IsWindowOverGame(hwnd)) return;

    // Check if it's an overlay-type window
    if (!IsOverlayWindow(hwnd)) return;

    // Check whitelist
    if (IsWhitelisted(info)) return;

    // Add to detected list
    std::lock_guard<std::mutex> lock(m_mutex);
    m_overlayWindows.push_back(info);
}

std::vector<OverlayDetector::WindowInfo> OverlayDetector::ScanForOverlays() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_overlayWindows.clear();
    }

    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(this));

    std::lock_guard<std::mutex> lock(m_mutex);
    return m_overlayWindows;
}

std::vector<OverlayDetector::DetectionResult> OverlayDetector::DetectCheatOverlays() {
    std::vector<DetectionResult> results;

    auto overlays = ScanForOverlays();

    for (auto& window : overlays) {
        DetectionResult result;
        result.detected = false;
        result.window = window;

        // Check against signatures
        for (const auto& sig : m_signatures) {
            if (MatchesSignature(window, sig)) {
                result.detected = true;
                result.reason = sig.description;
                result.severity = sig.severity;
                window.isSuspicious = true;
                window.suspicionReason = sig.description;
                break;
            }
        }

        // Even without signature match, check for suspicious patterns
        if (!result.detected && IsSuspiciousOverlay(window)) {
            result.detected = true;
            result.reason = window.suspicionReason;
            result.severity = Severity::Warning;
        }

        if (result.detected) {
            results.push_back(result);

            if (m_onOverlayFound) {
                m_onOverlayFound(result);
            }
        }
    }

    return results;
}

bool OverlayDetector::HasSuspiciousOverlays() {
    auto results = DetectCheatOverlays();
    return !results.empty();
}

// ============================================================================
// WINDOW ANALYSIS
// ============================================================================

OverlayDetector::WindowInfo OverlayDetector::GetWindowInfo(HWND hwnd) {
    WindowInfo info = {};
    info.hwnd = hwnd;

    // Get class name
    wchar_t className[256] = { 0 };
    GetClassNameW(hwnd, className, 256);
    info.className = className;

    // Get window title
    wchar_t title[256] = { 0 };
    GetWindowTextW(hwnd, title, 256);
    info.windowTitle = title;

    // Get process info
    info.processId = GetProcessIdFromWindow(hwnd);
    info.processName = GetProcessNameFromWindow(hwnd);

    // Get rect
    GetWindowRect(hwnd, &info.rect);

    // Check window styles
    LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
    info.isLayered = (exStyle & WS_EX_LAYERED) != 0;
    info.isTopmost = (exStyle & WS_EX_TOPMOST) != 0;
    info.isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;
    info.isClickThrough = info.isTransparent;

    // Get opacity
    info.opacity = 255;
    if (info.isLayered) {
        BYTE alpha;
        DWORD flags;
        COLORREF colorKey;
        if (GetLayeredWindowAttributes(hwnd, &colorKey, &alpha, &flags)) {
            if (flags & LWA_ALPHA) {
                info.opacity = alpha;
            }
        }
    }

    // Check fullscreen
    info.isFullscreen = IsWindowFullscreen(hwnd);

    info.isSuspicious = false;

    return info;
}

bool OverlayDetector::IsOverlayWindow(HWND hwnd) {
    LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);

    // Overlay windows are typically layered, topmost, or transparent
    if (exStyle & WS_EX_LAYERED) return true;
    if (exStyle & WS_EX_TOPMOST) return true;
    if (exStyle & WS_EX_TRANSPARENT) return true;

    // Check if it's a borderless window over game
    LONG style = GetWindowLongW(hwnd, GWL_STYLE);
    if (!(style & WS_BORDER) && !(style & WS_CAPTION)) {
        if (IsWindowOverGame(hwnd)) {
            return true;
        }
    }

    return false;
}

bool OverlayDetector::IsSuspiciousOverlay(const WindowInfo& info) {
    // Transparent + over game = suspicious
    if (info.isTransparent && IsWindowOverGame(info.hwnd)) {
        const_cast<WindowInfo&>(info).suspicionReason = "Transparent window over game";
        return true;
    }

    // Low opacity layered window over game
    if (info.isLayered && info.opacity < 255 && IsWindowOverGame(info.hwnd)) {
        const_cast<WindowInfo&>(info).suspicionReason = "Semi-transparent overlay";
        return true;
    }

    // Click-through window over game
    if (info.isClickThrough && IsWindowOverGame(info.hwnd)) {
        const_cast<WindowInfo&>(info).suspicionReason = "Click-through overlay";
        return true;
    }

    // Topmost borderless window matching game size
    if (info.isTopmost) {
        RECT gameRect;
        if (GetWindowRect(m_gameWindow, &gameRect)) {
            if (info.rect.left == gameRect.left && info.rect.top == gameRect.top &&
                info.rect.right == gameRect.right && info.rect.bottom == gameRect.bottom) {
                const_cast<WindowInfo&>(info).suspicionReason = "Topmost window matching game size";
                return true;
            }
        }
    }

    // Unknown process with overlay over game
    if (info.processName.empty() && IsWindowOverGame(info.hwnd)) {
        const_cast<WindowInfo&>(info).suspicionReason = "Unknown process overlay";
        return true;
    }

    return false;
}

bool OverlayDetector::IsWindowOverGame(HWND hwnd) {
    if (!m_gameWindow) return false;

    RECT windowRect, gameRect;
    if (!GetWindowRect(hwnd, &windowRect)) return false;
    if (!GetWindowRect(m_gameWindow, &gameRect)) return false;

    // Check for intersection
    RECT intersection;
    return IntersectRect(&intersection, &windowRect, &gameRect) != 0;
}

bool OverlayDetector::IsWindowTransparent(HWND hwnd) {
    LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
    return (exStyle & WS_EX_TRANSPARENT) != 0;
}

bool OverlayDetector::IsWindowLayered(HWND hwnd) {
    LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
    return (exStyle & WS_EX_LAYERED) != 0;
}

bool OverlayDetector::IsWindowClickThrough(HWND hwnd) {
    return IsWindowTransparent(hwnd);
}

bool OverlayDetector::IsWindowTopmost(HWND hwnd) {
    LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
    return (exStyle & WS_EX_TOPMOST) != 0;
}

bool OverlayDetector::IsWindowFullscreen(HWND hwnd) {
    RECT windowRect;
    GetWindowRect(hwnd, &windowRect);

    HMONITOR monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monitorInfo = { sizeof(MONITORINFO) };
    GetMonitorInfoW(monitor, &monitorInfo);

    return (windowRect.left == monitorInfo.rcMonitor.left &&
            windowRect.top == monitorInfo.rcMonitor.top &&
            windowRect.right == monitorInfo.rcMonitor.right &&
            windowRect.bottom == monitorInfo.rcMonitor.bottom);
}

bool OverlayDetector::MatchesSignature(const WindowInfo& info, const OverlaySignature& sig) {
    // Check process name
    if (!sig.processName.empty()) {
        std::wstring lowerProcess = info.processName;
        std::wstring lowerSig = sig.processName;
        std::transform(lowerProcess.begin(), lowerProcess.end(), lowerProcess.begin(), ::towlower);
        std::transform(lowerSig.begin(), lowerSig.end(), lowerSig.begin(), ::towlower);

        if (lowerProcess.find(lowerSig) == std::wstring::npos) {
            return false;
        }
    }

    // Check class name
    if (!sig.className.empty()) {
        std::wstring lowerClass = info.className;
        std::wstring lowerSig = sig.className;
        std::transform(lowerClass.begin(), lowerClass.end(), lowerClass.begin(), ::towlower);
        std::transform(lowerSig.begin(), lowerSig.end(), lowerSig.begin(), ::towlower);

        if (lowerClass.find(lowerSig) == std::wstring::npos) {
            return false;
        }
    }

    // Check window title
    if (!sig.windowTitle.empty()) {
        std::wstring lowerTitle = info.windowTitle;
        std::wstring lowerSig = sig.windowTitle;
        std::transform(lowerTitle.begin(), lowerTitle.end(), lowerTitle.begin(), ::towlower);
        std::transform(lowerSig.begin(), lowerSig.end(), lowerSig.begin(), ::towlower);

        if (lowerTitle.find(lowerSig) == std::wstring::npos) {
            return false;
        }
    }

    // At least one field must have been checked
    return !sig.processName.empty() || !sig.className.empty() || !sig.windowTitle.empty();
}

// ============================================================================
// PROCESS INFO
// ============================================================================

std::wstring OverlayDetector::GetProcessNameFromWindow(HWND hwnd) {
    DWORD processId;
    GetWindowThreadProcessId(hwnd, &processId);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess) return L"";

    wchar_t path[MAX_PATH];
    DWORD size = MAX_PATH;
    std::wstring processName;

    if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        processName = path;
        size_t pos = processName.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            processName = processName.substr(pos + 1);
        }
    }

    CloseHandle(hProcess);
    return processName;
}

DWORD OverlayDetector::GetProcessIdFromWindow(HWND hwnd) {
    DWORD processId = 0;
    GetWindowThreadProcessId(hwnd, &processId);
    return processId;
}

// ============================================================================
// GRAPHICS HOOK DETECTION
// ============================================================================

bool OverlayDetector::CheckD3DHooks() {
    // This would require checking D3D vtable for hooks
    // Placeholder - would need more complex implementation
    return false;
}

bool OverlayDetector::CheckDWMComposition() {
    BOOL enabled = FALSE;
    HRESULT hr = DwmIsCompositionEnabled(&enabled);

    if (SUCCEEDED(hr) && !enabled) {
        // DWM composition disabled - could indicate tampering
        return true;
    }

    return false;
}

} // namespace AntiCheat
