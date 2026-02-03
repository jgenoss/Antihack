/**
 * AntiCheatCore - Overlay Detector Implementation
 * Detects external overlay cheats (ESP, wallhacks via transparent windows)
 *
 * Thread Safety: Uses IMonitorModule base class for safe monitoring.
 * All callbacks are invoked outside of locks to prevent deadlocks.
 */

#include "stdafx.h"
#include "../include/internal/OverlayDetector.h"

namespace AntiCheat {

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

OverlayDetector::OverlayDetector()
    : TypedMonitorModule("OverlayDetector", 500)  // Default 500ms interval
    , m_gameWindow(NULL)
    , m_gameProcessId(0) {
    ZeroMemory(&m_gameRect, sizeof(m_gameRect));
}

OverlayDetector::~OverlayDetector() {
    Shutdown();
}

// ============================================================================
// INITIALIZATION
// ============================================================================

bool OverlayDetector::Initialize() {
    // Initialize base class first
    if (!IMonitorModule::Initialize()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_dataMutex);

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
    // Stop monitoring first (base class handles thread cleanup)
    IMonitorModule::Shutdown();

    std::lock_guard<std::mutex> lock(m_dataMutex);
    m_signatures.clear();
    m_overlayWindows.clear();
    m_gameWindow = NULL;
}

// ============================================================================
// MONITOR CYCLE (called by base class thread)
// ============================================================================

void OverlayDetector::DoMonitorCycle() {
    HWND gameWindow = NULL;
    RECT gameRect;

    // Atomically copy game window data
    {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        gameWindow = m_gameWindow;
        gameRect = m_gameRect;
    }

    // Update game window rect (outside lock - Windows API call)
    if (gameWindow && IsWindow(gameWindow)) {
        RECT newRect;
        if (GetWindowRect(gameWindow, &newRect)) {
            std::lock_guard<std::mutex> lock(m_dataMutex);
            m_gameRect = newRect;
            gameRect = newRect;
        }
    } else {
        // Game window closed or invalid
        return;
    }

    // Scan for overlays using context struct (no shared state during enum)
    EnumContext ctx;
    ctx.detector = this;
    ctx.gameRect = gameRect;

    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&ctx));

    // Process results
    std::vector<DetectionResult> detections;
    std::vector<OverlaySignature> signatures;

    {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        m_overlayWindows = std::move(ctx.windows);
        signatures = m_signatures;  // Copy signatures for processing
    }

    // Analyze outside lock
    for (auto& window : m_overlayWindows) {
        DetectionResult result;
        result.detected = false;
        result.window = window;

        // Check against signatures
        for (const auto& sig : signatures) {
            if (MatchesSignature(window, sig)) {
                result.detected = true;
                result.reason = sig.description;
                result.severity = sig.severity;
                window.isSuspicious = true;
                window.suspicionReason = sig.description;
                break;
            }
        }

        // Check for suspicious patterns if no signature match
        if (!result.detected && IsSuspiciousOverlay(window)) {
            result.detected = true;
            result.reason = window.suspicionReason;
            result.severity = Severity::Warning;
        }

        if (result.detected) {
            detections.push_back(result);

            // Queue event for dispatch (will be called outside of any lock)
            DetectionEvent event;
            event.type = DetectionType::SuspiciousProcess;
            event.severity = result.severity;
            event.description = result.reason;
            event.moduleName = WStringToString(window.processName);
            event.address = reinterpret_cast<void*>(window.hwnd);
            event.timestamp = GetTickCount();
            QueueEvent(event);
        }
    }

    // Queue typed events for overlay callback
    for (const auto& det : detections) {
        QueueTypedEvent(det);
    }

    // Dispatch typed events outside of lock
    DispatchTypedEvents();
}

// ============================================================================
// GAME WINDOW SETUP
// ============================================================================

bool OverlayDetector::SetGameWindow(HWND hwnd) {
    if (!IsWindow(hwnd)) {
        m_lastError = "Invalid window handle";
        return false;
    }

    std::lock_guard<std::mutex> lock(m_dataMutex);

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
    } data = { processId, NULL };

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
    std::lock_guard<std::mutex> lock(m_dataMutex);
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
    AddSuspiciousSignature(L"obs64.exe", L"");
    AddSuspiciousSignature(L"obs32.exe", L"");
    AddSuspiciousSignature(L"", L"MicrosoftEdgeWebView2");

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
    std::lock_guard<std::mutex> lock(m_dataMutex);
    m_signatures.clear();
}

// ============================================================================
// WHITELIST
// ============================================================================

void OverlayDetector::AddWhitelistedProcess(const std::wstring& processName) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    std::wstring lower = processName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    m_whitelistedProcesses.insert(lower);
}

void OverlayDetector::AddWhitelistedClass(const std::wstring& className) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    m_whitelistedClasses.insert(className);
}

void OverlayDetector::ClearWhitelist() {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    m_whitelistedProcesses.clear();
    m_whitelistedClasses.clear();
}

bool OverlayDetector::IsWhitelisted(const WindowInfo& info) {
    // Note: Caller should hold lock if needed
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
// SCANNING (uses context for thread safety)
// ============================================================================

BOOL CALLBACK OverlayDetector::EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    EnumContext* ctx = reinterpret_cast<EnumContext*>(lParam);
    ctx->detector->ProcessWindow(hwnd, *ctx);
    return TRUE;
}

void OverlayDetector::ProcessWindow(HWND hwnd, EnumContext& ctx) {
    HWND gameWindow;
    {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        gameWindow = m_gameWindow;
    }

    // Skip our own game window
    if (hwnd == gameWindow) return;

    // Must be visible
    if (!IsWindowVisible(hwnd)) return;

    WindowInfo info = GetWindowInfo(hwnd);

    // Check if over game (using context's cached gameRect)
    if (!IsWindowOverGame(hwnd, ctx.gameRect)) return;

    // Check if it's an overlay-type window
    if (!IsOverlayWindow(hwnd)) return;

    // Check whitelist
    {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        if (IsWhitelisted(info)) return;
    }

    // Add to context's list (not shared state)
    ctx.windows.push_back(info);
}

std::vector<OverlayDetector::WindowInfo> OverlayDetector::ScanForOverlays() {
    RECT gameRect;
    {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        gameRect = m_gameRect;
    }

    EnumContext ctx;
    ctx.detector = this;
    ctx.gameRect = gameRect;

    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&ctx));

    {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        m_overlayWindows = ctx.windows;
    }

    return ctx.windows;
}

std::vector<OverlayDetector::DetectionResult> OverlayDetector::DetectCheatOverlays() {
    std::vector<DetectionResult> results;
    std::vector<OverlaySignature> signatures;

    auto overlays = ScanForOverlays();

    {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        signatures = m_signatures;
    }

    for (auto& window : overlays) {
        DetectionResult result;
        result.detected = false;
        result.window = window;

        for (const auto& sig : signatures) {
            if (MatchesSignature(window, sig)) {
                result.detected = true;
                result.reason = sig.description;
                result.severity = sig.severity;
                window.isSuspicious = true;
                window.suspicionReason = sig.description;
                break;
            }
        }

        if (!result.detected && IsSuspiciousOverlay(window)) {
            result.detected = true;
            result.reason = window.suspicionReason;
            result.severity = Severity::Warning;
        }

        if (result.detected) {
            results.push_back(result);
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
    WindowInfo info;
    info.hwnd = hwnd;

    wchar_t className[256] = { 0 };
    GetClassNameW(hwnd, className, 256);
    info.className = className;

    wchar_t title[256] = { 0 };
    GetWindowTextW(hwnd, title, 256);
    info.windowTitle = title;

    info.processId = GetProcessIdFromWindow(hwnd);
    info.processName = GetProcessNameFromWindow(hwnd);

    GetWindowRect(hwnd, &info.rect);

    LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
    info.isLayered = (exStyle & WS_EX_LAYERED) != 0;
    info.isTopmost = (exStyle & WS_EX_TOPMOST) != 0;
    info.isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;
    info.isClickThrough = info.isTransparent;

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

    info.isFullscreen = IsWindowFullscreen(hwnd);

    return info;
}

bool OverlayDetector::IsOverlayWindow(HWND hwnd) {
    LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);

    if (exStyle & WS_EX_LAYERED) return true;
    if (exStyle & WS_EX_TOPMOST) return true;
    if (exStyle & WS_EX_TRANSPARENT) return true;

    LONG style = GetWindowLongW(hwnd, GWL_STYLE);
    if (!(style & WS_BORDER) && !(style & WS_CAPTION)) {
        RECT gameRect;
        {
            std::lock_guard<std::mutex> lock(m_dataMutex);
            gameRect = m_gameRect;
        }
        if (IsWindowOverGame(hwnd, gameRect)) {
            return true;
        }
    }

    return false;
}

bool OverlayDetector::IsSuspiciousOverlay(const WindowInfo& info) {
    RECT gameRect;
    {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        gameRect = m_gameRect;
    }

    if (info.isTransparent && IsWindowOverGame(info.hwnd, gameRect)) {
        const_cast<WindowInfo&>(info).suspicionReason = "Transparent window over game";
        return true;
    }

    if (info.isLayered && info.opacity < 255 && IsWindowOverGame(info.hwnd, gameRect)) {
        const_cast<WindowInfo&>(info).suspicionReason = "Semi-transparent overlay";
        return true;
    }

    if (info.isClickThrough && IsWindowOverGame(info.hwnd, gameRect)) {
        const_cast<WindowInfo&>(info).suspicionReason = "Click-through overlay";
        return true;
    }

    if (info.isTopmost) {
        if (info.rect.left == gameRect.left && info.rect.top == gameRect.top &&
            info.rect.right == gameRect.right && info.rect.bottom == gameRect.bottom) {
            const_cast<WindowInfo&>(info).suspicionReason = "Topmost window matching game size";
            return true;
        }
    }

    if (info.processName.empty() && IsWindowOverGame(info.hwnd, gameRect)) {
        const_cast<WindowInfo&>(info).suspicionReason = "Unknown process overlay";
        return true;
    }

    return false;
}

bool OverlayDetector::IsWindowOverGame(HWND hwnd, const RECT& gameRect) {
    RECT windowRect;
    if (!GetWindowRect(hwnd, &windowRect)) return false;

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
    if (!sig.processName.empty()) {
        std::wstring lowerProcess = info.processName;
        std::wstring lowerSig = sig.processName;
        std::transform(lowerProcess.begin(), lowerProcess.end(), lowerProcess.begin(), ::towlower);
        std::transform(lowerSig.begin(), lowerSig.end(), lowerSig.begin(), ::towlower);

        if (lowerProcess.find(lowerSig) == std::wstring::npos) {
            return false;
        }
    }

    if (!sig.className.empty()) {
        std::wstring lowerClass = info.className;
        std::wstring lowerSig = sig.className;
        std::transform(lowerClass.begin(), lowerClass.end(), lowerClass.begin(), ::towlower);
        std::transform(lowerSig.begin(), lowerSig.end(), lowerSig.begin(), ::towlower);

        if (lowerClass.find(lowerSig) == std::wstring::npos) {
            return false;
        }
    }

    if (!sig.windowTitle.empty()) {
        std::wstring lowerTitle = info.windowTitle;
        std::wstring lowerSig = sig.windowTitle;
        std::transform(lowerTitle.begin(), lowerTitle.end(), lowerTitle.begin(), ::towlower);
        std::transform(lowerSig.begin(), lowerSig.end(), lowerSig.begin(), ::towlower);

        if (lowerTitle.find(lowerSig) == std::wstring::npos) {
            return false;
        }
    }

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
    return false;
}

bool OverlayDetector::CheckDWMComposition() {
    BOOL enabled = FALSE;
    HRESULT hr = DwmIsCompositionEnabled(&enabled);

    if (SUCCEEDED(hr) && !enabled) {
        return true;
    }

    return false;
}

} // namespace AntiCheat
