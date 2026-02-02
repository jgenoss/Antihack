/**
 * Anti-Macro Detection Module
 * Detects automated input (macros, autoclickers, bots)
 */

#include "../include/anticheat_core.h"
#include <Windows.h>
#include <vector>
#include <deque>
#include <cmath>
#include <string>

static char g_macroError[256] = "";
static bool g_monitoringInput = false;
static HHOOK g_mouseHook = NULL;
static HHOOK g_keyboardHook = NULL;

// Input event record
struct InputEvent {
    DWORD timestamp;
    DWORD type;       // 0 = mouse, 1 = keyboard
    DWORD action;     // Button/Key code
    POINT position;   // Mouse position
};

// Click timing analysis
struct ClickPattern {
    std::deque<DWORD> intervals;     // Time between clicks
    std::deque<POINT> positions;     // Click positions
    int suspiciousCount;
    DWORD lastClickTime;
};

static std::deque<InputEvent> g_inputHistory;
static ClickPattern g_mousePattern;
static ClickPattern g_keyPattern;
static const int MAX_HISTORY = 1000;
static const int ANALYSIS_WINDOW = 100;

// Detection thresholds
static const double INTERVAL_VARIANCE_THRESHOLD = 5.0;   // Too consistent = suspicious
static const int MIN_CLICK_INTERVAL = 10;                 // Minimum ms between clicks (humanly impossible below)
static const int SUSPICIOUS_PATTERN_COUNT = 10;           // Consecutive suspicious events

// Calculate variance of intervals
static double CalculateVariance(const std::deque<DWORD>& intervals) {
    if (intervals.size() < 2) return 1000.0; // Not enough data

    double sum = 0;
    for (DWORD interval : intervals) {
        sum += interval;
    }
    double mean = sum / intervals.size();

    double variance = 0;
    for (DWORD interval : intervals) {
        variance += (interval - mean) * (interval - mean);
    }

    return variance / intervals.size();
}

// Check for inhuman click speeds
static bool IsInhumanSpeed(DWORD interval) {
    return interval < MIN_CLICK_INTERVAL;
}

// Check for perfect timing (too consistent)
static bool IsPerfectTiming(const std::deque<DWORD>& intervals) {
    if (intervals.size() < 10) return false;

    double variance = CalculateVariance(intervals);
    return variance < INTERVAL_VARIANCE_THRESHOLD;
}

// Check for grid-like mouse movement (autoclicker patterns)
static bool IsGridPattern(const std::deque<POINT>& positions) {
    if (positions.size() < 5) return false;

    int exactSameCount = 0;
    POINT last = positions.front();

    for (const POINT& pos : positions) {
        if (pos.x == last.x && pos.y == last.y) {
            exactSameCount++;
        }
        last = pos;
    }

    // If most clicks are at exact same position
    return exactSameCount > (int)(positions.size() * 0.8);
}

// Low-level mouse hook
static LRESULT CALLBACK MouseHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && g_monitoringInput) {
        MSLLHOOKSTRUCT* mouseInfo = (MSLLHOOKSTRUCT*)lParam;

        if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN) {
            DWORD currentTime = GetTickCount();
            DWORD interval = currentTime - g_mousePattern.lastClickTime;

            // Record interval
            if (g_mousePattern.lastClickTime > 0) {
                g_mousePattern.intervals.push_back(interval);
                if (g_mousePattern.intervals.size() > ANALYSIS_WINDOW) {
                    g_mousePattern.intervals.pop_front();
                }
            }

            // Record position
            g_mousePattern.positions.push_back(mouseInfo->pt);
            if (g_mousePattern.positions.size() > ANALYSIS_WINDOW) {
                g_mousePattern.positions.pop_front();
            }

            g_mousePattern.lastClickTime = currentTime;

            // Check for suspicious patterns
            if (IsInhumanSpeed(interval)) {
                g_mousePattern.suspiciousCount++;
            }

            // Record event
            InputEvent event;
            event.timestamp = currentTime;
            event.type = 0;
            event.action = (DWORD)wParam;
            event.position = mouseInfo->pt;

            g_inputHistory.push_back(event);
            if (g_inputHistory.size() > MAX_HISTORY) {
                g_inputHistory.pop_front();
            }
        }
    }

    return CallNextHookEx(g_mouseHook, nCode, wParam, lParam);
}

// Low-level keyboard hook
static LRESULT CALLBACK KeyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && g_monitoringInput) {
        KBDLLHOOKSTRUCT* kbInfo = (KBDLLHOOKSTRUCT*)lParam;

        if (wParam == WM_KEYDOWN) {
            DWORD currentTime = GetTickCount();
            DWORD interval = currentTime - g_keyPattern.lastClickTime;

            // Record interval
            if (g_keyPattern.lastClickTime > 0) {
                g_keyPattern.intervals.push_back(interval);
                if (g_keyPattern.intervals.size() > ANALYSIS_WINDOW) {
                    g_keyPattern.intervals.pop_front();
                }
            }

            g_keyPattern.lastClickTime = currentTime;

            // Check for inhuman speed
            if (IsInhumanSpeed(interval)) {
                g_keyPattern.suspiciousCount++;
            }

            // Record event
            InputEvent event;
            event.timestamp = currentTime;
            event.type = 1;
            event.action = kbInfo->vkCode;
            event.position = { 0, 0 };

            g_inputHistory.push_back(event);
            if (g_inputHistory.size() > MAX_HISTORY) {
                g_inputHistory.pop_front();
            }
        }
    }

    return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
}

// ============================================================================
// EXPORTED FUNCTIONS
// ============================================================================

AC_API bool AC_CALL AC_AntiMacroInit(void) {
    g_inputHistory.clear();
    g_mousePattern = {};
    g_keyPattern = {};
    g_macroError[0] = '\0';
    return true;
}

AC_API void AC_CALL AC_AntiMacroShutdown(void) {
    AC_StopInputMonitoring();
    g_inputHistory.clear();
}

AC_API bool AC_CALL AC_StartInputMonitoring(void) {
    if (g_monitoringInput) {
        return true; // Already running
    }

    g_mouseHook = SetWindowsHookExA(WH_MOUSE_LL, MouseHookProc, NULL, 0);
    g_keyboardHook = SetWindowsHookExA(WH_KEYBOARD_LL, KeyboardHookProc, NULL, 0);

    if (!g_mouseHook || !g_keyboardHook) {
        AC_StopInputMonitoring();
        strcpy_s(g_macroError, "Failed to install input hooks");
        return false;
    }

    g_monitoringInput = true;
    return true;
}

AC_API void AC_CALL AC_StopInputMonitoring(void) {
    g_monitoringInput = false;

    if (g_mouseHook) {
        UnhookWindowsHookEx(g_mouseHook);
        g_mouseHook = NULL;
    }

    if (g_keyboardHook) {
        UnhookWindowsHookEx(g_keyboardHook);
        g_keyboardHook = NULL;
    }
}

AC_API bool AC_CALL AC_IsInputMonitoringActive(void) {
    return g_monitoringInput;
}

AC_API bool AC_CALL AC_DetectAutoClicker(char* details, int bufferSize) {
    // Check mouse click patterns
    if (g_mousePattern.intervals.size() < 10) {
        return false; // Not enough data
    }

    bool detected = false;
    std::string report;

    // Check for inhuman click speed
    if (g_mousePattern.suspiciousCount >= SUSPICIOUS_PATTERN_COUNT) {
        detected = true;
        report += "Inhuman click speed detected. ";
    }

    // Check for perfect timing (too consistent)
    if (IsPerfectTiming(g_mousePattern.intervals)) {
        detected = true;
        report += "Perfect timing pattern detected. ";
    }

    // Check for grid pattern (same position clicks)
    if (IsGridPattern(g_mousePattern.positions)) {
        detected = true;
        report += "Grid pattern detected. ";
    }

    if (detected && details && bufferSize > 0) {
        snprintf(details, bufferSize, "AutoClicker: %s Suspicious events: %d",
                 report.c_str(), g_mousePattern.suspiciousCount);
    }

    return detected;
}

AC_API bool AC_CALL AC_DetectKeyboardMacro(char* details, int bufferSize) {
    if (g_keyPattern.intervals.size() < 10) {
        return false; // Not enough data
    }

    bool detected = false;
    std::string report;

    // Check for inhuman typing speed
    if (g_keyPattern.suspiciousCount >= SUSPICIOUS_PATTERN_COUNT) {
        detected = true;
        report += "Inhuman key speed detected. ";
    }

    // Check for perfect timing
    if (IsPerfectTiming(g_keyPattern.intervals)) {
        detected = true;
        report += "Perfect key timing detected. ";
    }

    if (detected && details && bufferSize > 0) {
        snprintf(details, bufferSize, "KeyboardMacro: %s Suspicious events: %d",
                 report.c_str(), g_keyPattern.suspiciousCount);
    }

    return detected;
}

AC_API bool AC_CALL AC_DetectInputAutomation(char* details, int bufferSize) {
    bool autoClick = AC_DetectAutoClicker(nullptr, 0);
    bool keyMacro = AC_DetectKeyboardMacro(nullptr, 0);

    if (autoClick || keyMacro) {
        if (details && bufferSize > 0) {
            snprintf(details, bufferSize, "Automation detected - AutoClick: %s, KeyMacro: %s",
                     autoClick ? "YES" : "NO", keyMacro ? "YES" : "NO");
        }
        return true;
    }

    return false;
}

// Get click statistics
AC_API void AC_CALL AC_GetClickStats(int* totalClicks, double* avgInterval,
                                      double* variance, int* suspiciousCount) {
    if (totalClicks) *totalClicks = (int)g_mousePattern.intervals.size();
    if (suspiciousCount) *suspiciousCount = g_mousePattern.suspiciousCount;

    if (g_mousePattern.intervals.size() > 0) {
        if (avgInterval) {
            double sum = 0;
            for (DWORD interval : g_mousePattern.intervals) {
                sum += interval;
            }
            *avgInterval = sum / g_mousePattern.intervals.size();
        }

        if (variance) {
            *variance = CalculateVariance(g_mousePattern.intervals);
        }
    } else {
        if (avgInterval) *avgInterval = 0;
        if (variance) *variance = 0;
    }
}

AC_API void AC_CALL AC_ResetMacroStats(void) {
    g_mousePattern.intervals.clear();
    g_mousePattern.positions.clear();
    g_mousePattern.suspiciousCount = 0;
    g_mousePattern.lastClickTime = 0;

    g_keyPattern.intervals.clear();
    g_keyPattern.positions.clear();
    g_keyPattern.suspiciousCount = 0;
    g_keyPattern.lastClickTime = 0;
}

// Detect macro software processes
AC_API bool AC_CALL AC_DetectMacroSoftware(char* detectedName, int bufferSize) {
    // Known macro software process names
    static const char* macroProcesses[] = {
        "AutoHotkey",
        "AutoIt",
        "TinyTask",
        "MacroRecorder",
        "JitBit",
        "Pulover",
        "MouseRecorder",
        "GhostMouse",
        "ReMouse",
        "Mini Mouse Macro",
        "OP Auto Clicker",
        "GS Auto Clicker",
        "Fast Clicker",
        "Speedy Autoclicker",
        "Murgee",
        "Perfect Automation",
        "RoboTask",
        nullptr
    };

    // This reuses the process scanning functionality
    for (int i = 0; macroProcesses[i] != nullptr; i++) {
        if (AC_AddToBlacklist(macroProcesses[i])) {
            // Added to blacklist for scanning
        }
    }

    char detected[256];
    bool found = AC_ScanProcesses(detected, sizeof(detected));

    if (found && detectedName && bufferSize > 0) {
        strncpy_s(detectedName, bufferSize, detected, _TRUNCATE);
    }

    return found;
}

AC_API const char* AC_CALL AC_GetMacroError(void) {
    return g_macroError;
}
