/**
 * AntiCheatCore - Unified Module Type Definitions
 *
 * Consolidates all shared types that were previously duplicated across
 * ProcessMonitor::ModuleInfo, HookDetector::ModuleInfo, etc.
 *
 * Single Responsibility: This file is the ONE source of truth for
 * detection-related data structures.
 */

#pragma once

#ifndef AC_MODULE_TYPES_HPP
#define AC_MODULE_TYPES_HPP

#include "common.h"

namespace AntiCheat {

// ============================================================================
// UNIFIED MODULE INFORMATION
// ============================================================================

/**
 * Comprehensive information about a loaded module (DLL/EXE).
 * Replaces the separate ModuleInfo structs in ProcessMonitor and HookDetector.
 */
struct LoadedModuleInfo {
    std::wstring name;              ///< Filename (e.g., "kernel32.dll")
    std::wstring fullPath;          ///< Full filesystem path
    void*        baseAddress;       ///< Base address in process memory
    size_t       imageSize;         ///< Total image size in bytes
    uint32_t     checksum;          ///< CRC32 of module contents
    bool         isSigned;          ///< Has valid digital signature
    bool         isTrusted;         ///< In the trusted whitelist
    bool         isSystemModule;    ///< Located in System32/SysWOW64
    FILETIME     loadTime;          ///< When the module was first observed

    LoadedModuleInfo()
        : baseAddress(nullptr)
        , imageSize(0)
        , checksum(0)
        , isSigned(false)
        , isTrusted(false)
        , isSystemModule(false)
        , loadTime{} {
    }
};

// ============================================================================
// UNIFIED THREAD INFORMATION
// ============================================================================

/**
 * Information about a thread within the monitored process.
 */
struct ThreadSnapshot {
    DWORD        threadId;          ///< OS thread ID
    void*        startAddress;      ///< Thread entry point address
    void*        stackBase;         ///< Base of the thread's stack
    DWORD        creationFlags;     ///< CREATE_SUSPENDED, etc.
    std::wstring ownerModulePath;   ///< Module containing the start address
    std::wstring ownerModuleName;   ///< Just the filename portion
    bool         isSuspicious;      ///< Flagged by heuristic analysis
    std::string  suspicionReason;   ///< Human-readable reason if suspicious

    ThreadSnapshot()
        : threadId(0)
        , startAddress(nullptr)
        , stackBase(nullptr)
        , creationFlags(0)
        , isSuspicious(false) {
    }
};

// ============================================================================
// INJECTION DETECTION
// ============================================================================

/**
 * Result of an injection detection scan.
 */
struct InjectionResult {
    enum class Technique {
        None,
        DLLInjection,       ///< LoadLibrary-based injection
        RemoteThread,       ///< CreateRemoteThread injection
        APCInjection,       ///< QueueUserAPC injection
        ManualMapping,      ///< Manual PE mapping (no LoadLibrary)
        ProcessHollowing,   ///< Replace process image in memory
        CodeCave            ///< Code written into existing module padding
    };

    Technique    technique;
    std::wstring moduleName;
    void*        address;
    DWORD        threadId;
    std::string  details;
    Severity     severity;

    InjectionResult()
        : technique(Technique::None)
        , address(nullptr)
        , threadId(0)
        , severity(Severity::Info) {
    }

    /** Returns true if an injection technique was detected. */
    [[nodiscard]] bool WasDetected() const noexcept {
        return technique != Technique::None;
    }
};

// ============================================================================
// HOOK DETECTION
// ============================================================================

/**
 * Classification of API hook types.
 */
enum class HookType {
    None,
    InlineHook,      ///< JMP/CALL patched at function entry
    IATHook,         ///< Import Address Table pointer replaced
    EATHook,         ///< Export Address Table pointer replaced
    VTableHook,      ///< C++ virtual function table modified
    HotPatch,        ///< Windows hot-patch area used for hooking
    Trampoline       ///< Detours-style trampoline hook
};

/**
 * Detailed information about a detected hook.
 */
struct HookInfo {
    HookType    type;
    std::string moduleName;         ///< Module containing the hooked function
    std::string functionName;       ///< Name of the hooked export
    void*       originalAddress;    ///< Where the function should point
    void*       hookedAddress;      ///< Where it actually points now
    ByteVector  originalBytes;      ///< Stored original prologue bytes
    ByteVector  currentBytes;       ///< Current bytes at function entry
    std::string targetModuleName;   ///< Module the hook redirects to

    HookInfo()
        : type(HookType::None)
        , originalAddress(nullptr)
        , hookedAddress(nullptr) {
    }

    /** Returns true if a hook was detected. */
    [[nodiscard]] bool WasDetected() const noexcept {
        return type != HookType::None;
    }
};

/**
 * Aggregated result of a hook scan across multiple functions.
 */
struct HookScanResult {
    std::vector<HookInfo>         detectedHooks;
    std::vector<LoadedModuleInfo> suspiciousModules;
    bool                          hasCriticalHooks;
    int                           totalHooksFound;

    HookScanResult()
        : hasCriticalHooks(false)
        , totalHooksFound(0) {
    }
};

// ============================================================================
// MACRO / INPUT ANALYSIS
// ============================================================================

/**
 * A single mouse click event for timing analysis.
 */
struct ClickEvent {
    DWORD timestamp;
    POINT position;
    DWORD button;   ///< VK_LBUTTON, VK_RBUTTON, etc.
};

/**
 * A single keyboard event for timing analysis.
 */
struct KeyEvent {
    DWORD timestamp;
    DWORD virtualKeyCode;
    bool  isKeyDown;
};

/**
 * Result of statistical analysis on input timing patterns.
 */
struct InputAnalysisResult {
    bool        isSuspicious;
    double      confidence;         ///< 0.0 to 1.0
    std::string reason;
    double      variance;           ///< Timing variance (low = bot)
    double      meanInterval;       ///< Average ms between events
    double      autocorrelation;    ///< Periodicity measure

    InputAnalysisResult()
        : isSuspicious(false)
        , confidence(0.0)
        , variance(0.0)
        , meanInterval(0.0)
        , autocorrelation(0.0) {
    }
};

// ============================================================================
// SELF-PROTECTION
// ============================================================================

/**
 * Event raised when something attempts to tamper with the anti-cheat process.
 */
struct TamperEvent {
    DWORD        timestamp;
    std::string  eventType;         ///< "SUSPEND_ATTEMPT", "TERMINATE_ATTEMPT", etc.
    std::string  description;
    DWORD        aggressorPid;      ///< PID of the process attempting tamper
    std::wstring aggressorName;     ///< Name of the aggressor process

    TamperEvent()
        : timestamp(0)
        , aggressorPid(0) {
    }
};

} // namespace AntiCheat

#endif // AC_MODULE_TYPES_HPP
