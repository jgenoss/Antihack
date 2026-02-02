/**
 * AntiCheatCore - Native Security Module
 * Header file for C++ DLL exports
 */

#ifndef ANTICHEAT_CORE_H
#define ANTICHEAT_CORE_H

#ifdef _WIN32
    #ifdef ANTICHEATCORE_EXPORTS
        #define AC_API __declspec(dllexport)
    #else
        #define AC_API __declspec(dllimport)
    #endif
    #define AC_CALL __stdcall
#else
    #define AC_API
    #define AC_CALL
#endif

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// INITIALIZATION
// ============================================================================

/**
 * Initialize the AntiCheat core module
 * @return true if successful, false otherwise
 */
AC_API bool AC_CALL AC_Initialize(void);

/**
 * Shutdown the AntiCheat core module
 */
AC_API void AC_CALL AC_Shutdown(void);

/**
 * Get the version of the core module
 * @return Version string (e.g., "1.0.0")
 */
AC_API const char* AC_CALL AC_GetVersion(void);

// ============================================================================
// PROCESS DETECTION
// ============================================================================

/**
 * Scan for blacklisted processes
 * @param detected_name Buffer to store detected process name (min 256 chars)
 * @param buffer_size Size of the buffer
 * @return true if a blacklisted process was detected
 */
AC_API bool AC_CALL AC_ScanProcesses(char* detected_name, int buffer_size);

/**
 * Add a process name to the blacklist
 * @param process_name Name of the process (without .exe)
 * @return true if added successfully
 */
AC_API bool AC_CALL AC_AddToBlacklist(const char* process_name);

/**
 * Clear the process blacklist
 */
AC_API void AC_CALL AC_ClearBlacklist(void);

/**
 * Get the count of blacklisted processes
 * @return Number of processes in blacklist
 */
AC_API int AC_CALL AC_GetBlacklistCount(void);

// ============================================================================
// ANTI-DEBUG DETECTION
// ============================================================================

/**
 * Check if a debugger is attached
 * @return Bitmask of detection methods that triggered
 *         0 = No debugger detected
 *         1 = IsDebuggerPresent
 *         2 = CheckRemoteDebuggerPresent
 *         4 = NtQueryInformationProcess
 *         8 = Hardware breakpoints detected
 *        16 = Timing check failed
 */
AC_API uint32_t AC_CALL AC_DetectDebugger(void);

/**
 * Check for known debugger processes
 * @param debugger_name Buffer to store detected debugger name
 * @param buffer_size Size of the buffer
 * @return true if debugger process found
 */
AC_API bool AC_CALL AC_DetectDebuggerProcess(char* debugger_name, int buffer_size);

// ============================================================================
// MEMORY INTEGRITY
// ============================================================================

/**
 * Calculate hash of a memory region
 * @param address Start address
 * @param size Size in bytes
 * @return CRC32 hash of the memory region
 */
AC_API uint32_t AC_CALL AC_HashMemory(void* address, size_t size);

/**
 * Verify integrity of a module
 * @param module_name Name of the module (e.g., "game.exe")
 * @param expected_hash Expected hash value
 * @return true if integrity check passed
 */
AC_API bool AC_CALL AC_VerifyModuleIntegrity(const char* module_name, uint32_t expected_hash);

/**
 * Scan for injected DLLs
 * @param injected_dll Buffer to store detected DLL name
 * @param buffer_size Size of the buffer
 * @return true if suspicious DLL found
 */
AC_API bool AC_CALL AC_ScanForInjectedDlls(char* injected_dll, int buffer_size);

// ============================================================================
// HARDWARE ID
// ============================================================================

/**
 * Generate hardware ID
 * @param hwid_buffer Buffer to store HWID (min 64 chars)
 * @param buffer_size Size of the buffer
 * @return true if HWID generated successfully
 */
AC_API bool AC_CALL AC_GenerateHWID(char* hwid_buffer, int buffer_size);

// ============================================================================
// HOOKS & PROTECTION
// ============================================================================

/**
 * Install API hooks for protection
 * @return true if hooks installed successfully
 */
AC_API bool AC_CALL AC_InstallHooks(void);

/**
 * Remove API hooks
 */
AC_API void AC_CALL AC_RemoveHooks(void);

/**
 * Check if a specific API is hooked by external code
 * @param module_name Module name (e.g., "kernel32.dll")
 * @param function_name Function name (e.g., "LoadLibraryA")
 * @return true if function appears to be hooked
 */
AC_API bool AC_CALL AC_IsApiHooked(const char* module_name, const char* function_name);

// ============================================================================
// CALLBACKS
// ============================================================================

typedef void (AC_CALL *AC_DetectionCallback)(const char* detection_type, const char* details);
typedef void (AC_CALL *AC_IpcMessageCallback)(const char* message);

/**
 * Set callback for detection events
 * @param callback Function to call when detection occurs
 */
AC_API void AC_CALL AC_SetDetectionCallback(AC_DetectionCallback callback);

// ============================================================================
// IPC - INTER-PROCESS COMMUNICATION
// ============================================================================

/**
 * Initialize IPC communication with AntiCheat process
 * @return true if connected successfully
 */
AC_API bool AC_CALL AC_IpcInitialize(void);

/**
 * Shutdown IPC communication
 */
AC_API void AC_CALL AC_IpcShutdown(void);

/**
 * Check if IPC is connected
 * @return true if connected
 */
AC_API bool AC_CALL AC_IpcIsConnected(void);

/**
 * Send a raw message to AntiCheat
 * @param message JSON formatted message
 * @return true if sent successfully
 */
AC_API bool AC_CALL AC_IpcSendMessage(const char* message);

/**
 * Report a detection to AntiCheat
 * @param detectionType Type of detection (e.g., "DEBUGGER", "INJECTION")
 * @param details Additional details
 * @return true if sent successfully
 */
AC_API bool AC_CALL AC_IpcReportDetection(const char* detectionType, const char* details);

/**
 * Report DLL injection attempt
 * @param dllPath Path of the injected DLL
 * @return true if sent successfully
 */
AC_API bool AC_CALL AC_IpcReportDllInjection(const char* dllPath);

/**
 * Report suspicious DLL loaded
 * @param dllName Name of the suspicious DLL
 * @return true if sent successfully
 */
AC_API bool AC_CALL AC_IpcReportSuspiciousDll(const char* dllName);

/**
 * Report debugger detected
 * @param debuggerInfo Information about the debugger
 * @return true if sent successfully
 */
AC_API bool AC_CALL AC_IpcReportDebugger(const char* debuggerInfo);

/**
 * Report memory modification
 * @param details Details about the modification
 * @return true if sent successfully
 */
AC_API bool AC_CALL AC_IpcReportMemoryModification(const char* details);

/**
 * Set callback for messages received from AntiCheat
 * @param callback Function to call when message received
 */
AC_API void AC_CALL AC_IpcSetMessageCallback(AC_IpcMessageCallback callback);

/**
 * Get last IPC error message
 * @return Error message string
 */
AC_API const char* AC_CALL AC_IpcGetLastError(void);

// ============================================================================
// UTILITY
// ============================================================================

/**
 * Get last error message
 * @return Error message string
 */
AC_API const char* AC_CALL AC_GetLastError(void);

#ifdef __cplusplus
}
#endif

#endif // ANTICHEAT_CORE_H
