/**
 * NativeInterop - P/Invoke wrapper for AntiCheatCore.dll
 * Provides managed interface to native security functions
 */

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace AntiCheat.Modules.Security
{
    /// <summary>
    /// Detection flags returned by AC_DetectDebugger
    /// </summary>
    [Flags]
    public enum DebuggerDetectionFlags : uint
    {
        None = 0,
        IsDebuggerPresent = 0x01,
        RemoteDebuggerPresent = 0x02,
        NtQueryInformationProcess = 0x04,
        HardwareBreakpoints = 0x08,
        TimingCheck = 0x10
    }

    /// <summary>
    /// Callback delegate for detection events
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    public delegate void DetectionCallback(string detectionType, string details);

    /// <summary>
    /// Callback delegate for IPC messages received from AntiCheat
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    public delegate void IpcMessageCallback(string message);

    /// <summary>
    /// P/Invoke wrapper for AntiCheatCore native DLL
    /// </summary>
    public static class NativeInterop
    {
        private const string DllName = "AntiCheatCore.dll";

        #region Initialization

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_Initialize();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern void AC_Shutdown();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr AC_GetVersion();

        #endregion

        #region Process Detection

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_ScanProcesses(StringBuilder detectedName, int bufferSize);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_AddToBlacklist([MarshalAs(UnmanagedType.LPStr)] string processName);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern void AC_ClearBlacklist();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern int AC_GetBlacklistCount();

        #endregion

        #region Anti-Debug

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern uint AC_DetectDebugger();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_DetectDebuggerProcess(StringBuilder debuggerName, int bufferSize);

        #endregion

        #region Memory Integrity

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern uint AC_HashMemory(IntPtr address, UIntPtr size);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_VerifyModuleIntegrity(
            [MarshalAs(UnmanagedType.LPStr)] string moduleName,
            uint expectedHash);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_ScanForInjectedDlls(StringBuilder injectedDll, int bufferSize);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_IsApiHooked(
            [MarshalAs(UnmanagedType.LPStr)] string moduleName,
            [MarshalAs(UnmanagedType.LPStr)] string functionName);

        #endregion

        #region Hardware ID

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_GenerateHWID(StringBuilder hwidBuffer, int bufferSize);

        #endregion

        #region Hooks

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_InstallHooks();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern void AC_RemoveHooks();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern void AC_SetDetectionCallback(DetectionCallback callback);

        #endregion

        #region Utility

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr AC_GetLastError();

        #endregion

        #region Memory Pattern Scanning

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_MemoryScanInit();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_AddCheatPattern(
            [MarshalAs(UnmanagedType.LPStr)] string name,
            byte[] pattern, bool[] mask, int length);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_ScanProcessMemory(uint processId, StringBuilder detectedPattern, int bufferSize);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_ScanCurrentProcess(StringBuilder detectedPattern, int bufferSize);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_ScanMemoryRegion(IntPtr address, UIntPtr size, StringBuilder detectedPattern, int bufferSize);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern int AC_GetPatternCount();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern void AC_ClearPatterns();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr AC_GetPatternError();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_DetectCodeModification(IntPtr codeStart, UIntPtr codeSize, uint originalHash);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_DetectCodeCaves(StringBuilder details, int bufferSize);

        #endregion

        #region File Protection

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_FileProtectionInit();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern void AC_FileProtectionShutdown();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_ProtectFile([MarshalAs(UnmanagedType.LPWStr)] string filePath);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_ProtectFileA([MarshalAs(UnmanagedType.LPStr)] string filePath);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_UnprotectFile([MarshalAs(UnmanagedType.LPWStr)] string filePath);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_VerifyFileIntegrity([MarshalAs(UnmanagedType.LPWStr)] string filePath);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_VerifyAllFiles(StringBuilder failedFile, int bufferSize);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_StartFileMonitoring();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern void AC_StopFileMonitoring();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern int AC_GetProtectedFileCount();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private static extern uint AC_GetFileHash([MarshalAs(UnmanagedType.LPWStr)] string filePath);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern uint AC_GetFileHashA([MarshalAs(UnmanagedType.LPStr)] string filePath);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr AC_GetFileProtectionError();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private static extern int AC_ProtectDirectory(
            [MarshalAs(UnmanagedType.LPWStr)] string dirPath,
            [MarshalAs(UnmanagedType.LPWStr)] string pattern);

        #endregion

        #region Encryption Library

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_EncryptionInit();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_GenerateSessionKey();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_SetSessionKey(byte[] key, int keyLength);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_GetSessionKey(byte[] keyBuffer, int bufferSize);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_XorEncrypt(byte[] data, int dataLength, byte[] key, int keyLength);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_XorDecrypt(byte[] data, int dataLength, byte[] key, int keyLength);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_RC4Encrypt(byte[] data, int dataLength, byte[] key, int keyLength);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_RC4Decrypt(byte[] data, int dataLength, byte[] key, int keyLength);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_EncryptWithSessionKey(byte[] data, int dataLength);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_DecryptWithSessionKey(byte[] data, int dataLength);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_EncryptString(
            [MarshalAs(UnmanagedType.LPStr)] string input,
            byte[] output, ref int outputLength, byte[] key, int keyLength);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_DecryptString(
            byte[] input, int inputLength, StringBuilder output, int outputSize, byte[] key, int keyLength);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_GenerateRandom(byte[] buffer, int length);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern uint AC_HashData(byte[] data, int length);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern uint AC_HashString([MarshalAs(UnmanagedType.LPStr)] string str);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern void AC_ObfuscateData(byte[] data, int length);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern void AC_DeobfuscateData(byte[] data, int length);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr AC_GetEncryptionError();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern void AC_SecureClear(byte[] buffer, UIntPtr length);

        #endregion

        #region Hook Detection

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_HookDetectionInit();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_DetectInlineHook(
            [MarshalAs(UnmanagedType.LPStr)] string moduleName,
            [MarshalAs(UnmanagedType.LPStr)] string functionName,
            StringBuilder hookDetails, int bufferSize);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_DetectIATHook(
            [MarshalAs(UnmanagedType.LPStr)] string targetModule,
            [MarshalAs(UnmanagedType.LPStr)] string importModule,
            [MarshalAs(UnmanagedType.LPStr)] string functionName,
            StringBuilder hookDetails, int bufferSize);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern int AC_ScanCommonHooks(StringBuilder report, int reportSize);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern int AC_GetDetectedHookCount();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern void AC_ClearDetectedHooks();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr AC_GetHookError();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_DetectVEHHooks();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_DetectHardwareBreakpoints();

        #endregion

        #region Anti-Macro Detection

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_AntiMacroInit();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern void AC_AntiMacroShutdown();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_StartInputMonitoring();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern void AC_StopInputMonitoring();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_IsInputMonitoringActive();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_DetectAutoClicker(StringBuilder details, int bufferSize);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_DetectKeyboardMacro(StringBuilder details, int bufferSize);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_DetectInputAutomation(StringBuilder details, int bufferSize);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern void AC_GetClickStats(
            out int totalClicks, out double avgInterval, out double variance, out int suspiciousCount);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern void AC_ResetMacroStats();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_DetectMacroSoftware(StringBuilder detectedName, int bufferSize);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr AC_GetMacroError();

        #endregion

        #region IPC - Inter-Process Communication

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_IpcInitialize();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern void AC_IpcShutdown();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_IpcIsConnected();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_IpcSendMessage([MarshalAs(UnmanagedType.LPStr)] string message);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_IpcReportDetection(
            [MarshalAs(UnmanagedType.LPStr)] string detectionType,
            [MarshalAs(UnmanagedType.LPStr)] string details);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_IpcReportDllInjection([MarshalAs(UnmanagedType.LPStr)] string dllPath);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_IpcReportSuspiciousDll([MarshalAs(UnmanagedType.LPStr)] string dllName);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_IpcReportDebugger([MarshalAs(UnmanagedType.LPStr)] string debuggerInfo);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool AC_IpcReportMemoryModification([MarshalAs(UnmanagedType.LPStr)] string details);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern void AC_IpcSetMessageCallback(IpcMessageCallback callback);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr AC_IpcGetLastError();

        #endregion

        // ====================================================================
        // Managed Wrappers
        // ====================================================================

        private static bool _initialized = false;
        private static DetectionCallback _detectionCallback;

        /// <summary>
        /// Initialize the native security module
        /// </summary>
        public static bool Initialize()
        {
            try
            {
                _initialized = AC_Initialize();
                return _initialized;
            }
            catch (DllNotFoundException)
            {
                System.Diagnostics.Debug.WriteLine("AntiCheatCore.dll not found");
                return false;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Native init failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Shutdown the native security module
        /// </summary>
        public static void Shutdown()
        {
            if (_initialized)
            {
                AC_Shutdown();
                _initialized = false;
            }
        }

        /// <summary>
        /// Get the native module version
        /// </summary>
        public static string GetVersion()
        {
            try
            {
                IntPtr ptr = AC_GetVersion();
                return Marshal.PtrToStringAnsi(ptr) ?? "Unknown";
            }
            catch
            {
                return "Unknown";
            }
        }

        /// <summary>
        /// Scan for blacklisted processes
        /// </summary>
        /// <param name="detectedProcess">Name of detected process if found</param>
        /// <returns>True if blacklisted process found</returns>
        public static bool ScanProcesses(out string detectedProcess)
        {
            detectedProcess = null;
            try
            {
                StringBuilder sb = new StringBuilder(256);
                if (AC_ScanProcesses(sb, sb.Capacity))
                {
                    detectedProcess = sb.ToString();
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Add a process to the blacklist
        /// </summary>
        public static bool AddToBlacklist(string processName)
        {
            try
            {
                return AC_AddToBlacklist(processName);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Clear the process blacklist
        /// </summary>
        public static void ClearBlacklist()
        {
            try
            {
                AC_ClearBlacklist();
            }
            catch { }
        }

        /// <summary>
        /// Get number of blacklisted processes
        /// </summary>
        public static int GetBlacklistCount()
        {
            try
            {
                return AC_GetBlacklistCount();
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// Detect if a debugger is attached
        /// </summary>
        /// <returns>Detection flags indicating which methods detected a debugger</returns>
        public static DebuggerDetectionFlags DetectDebugger()
        {
            try
            {
                return (DebuggerDetectionFlags)AC_DetectDebugger();
            }
            catch
            {
                return DebuggerDetectionFlags.None;
            }
        }

        /// <summary>
        /// Check for debugger processes
        /// </summary>
        public static bool DetectDebuggerProcess(out string debuggerName)
        {
            debuggerName = null;
            try
            {
                StringBuilder sb = new StringBuilder(256);
                if (AC_DetectDebuggerProcess(sb, sb.Capacity))
                {
                    debuggerName = sb.ToString();
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Scan for injected DLLs
        /// </summary>
        public static bool ScanForInjectedDlls(out string injectedDll)
        {
            injectedDll = null;
            try
            {
                StringBuilder sb = new StringBuilder(512);
                if (AC_ScanForInjectedDlls(sb, sb.Capacity))
                {
                    injectedDll = sb.ToString();
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Check if a Windows API function is hooked
        /// </summary>
        public static bool IsApiHooked(string moduleName, string functionName)
        {
            try
            {
                return AC_IsApiHooked(moduleName, functionName);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Generate hardware ID using native module
        /// </summary>
        public static string GenerateHWID()
        {
            try
            {
                StringBuilder sb = new StringBuilder(128);
                if (AC_GenerateHWID(sb, sb.Capacity))
                {
                    return sb.ToString();
                }
                return null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Install API hooks for protection
        /// </summary>
        public static bool InstallHooks()
        {
            try
            {
                return AC_InstallHooks();
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Remove API hooks
        /// </summary>
        public static void RemoveHooks()
        {
            try
            {
                AC_RemoveHooks();
            }
            catch { }
        }

        /// <summary>
        /// Set callback for detection events
        /// </summary>
        public static void SetDetectionCallback(Action<string, string> callback)
        {
            try
            {
                if (callback != null)
                {
                    _detectionCallback = (type, details) => callback(type, details);
                    AC_SetDetectionCallback(_detectionCallback);
                }
            }
            catch { }
        }

        /// <summary>
        /// Get last error message from native module
        /// </summary>
        public static string GetLastError()
        {
            try
            {
                IntPtr ptr = AC_GetLastError();
                return Marshal.PtrToStringAnsi(ptr) ?? "Unknown error";
            }
            catch
            {
                return "Unknown error";
            }
        }

        // ====================================================================
        // IPC Managed Wrappers (for DLL injected in game process)
        // ====================================================================

        private static IpcMessageCallback _ipcMessageCallback;

        /// <summary>
        /// Initialize IPC connection to AntiCheat process
        /// Call this from the DLL when injected into game
        /// </summary>
        public static bool IpcInitialize()
        {
            try
            {
                return AC_IpcInitialize();
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Shutdown IPC connection
        /// </summary>
        public static void IpcShutdown()
        {
            try
            {
                AC_IpcShutdown();
            }
            catch { }
        }

        /// <summary>
        /// Check if IPC is connected to AntiCheat
        /// </summary>
        public static bool IpcIsConnected()
        {
            try
            {
                return AC_IpcIsConnected();
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Send raw JSON message to AntiCheat
        /// </summary>
        public static bool IpcSendMessage(string message)
        {
            try
            {
                return AC_IpcSendMessage(message);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Report a detection to AntiCheat
        /// </summary>
        public static bool IpcReportDetection(string detectionType, string details)
        {
            try
            {
                return AC_IpcReportDetection(detectionType, details ?? "");
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Report DLL injection attempt
        /// </summary>
        public static bool IpcReportDllInjection(string dllPath)
        {
            try
            {
                return AC_IpcReportDllInjection(dllPath);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Report suspicious DLL loaded
        /// </summary>
        public static bool IpcReportSuspiciousDll(string dllName)
        {
            try
            {
                return AC_IpcReportSuspiciousDll(dllName);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Report debugger detected
        /// </summary>
        public static bool IpcReportDebugger(string debuggerInfo)
        {
            try
            {
                return AC_IpcReportDebugger(debuggerInfo);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Report memory modification detected
        /// </summary>
        public static bool IpcReportMemoryModification(string details)
        {
            try
            {
                return AC_IpcReportMemoryModification(details);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Set callback for messages received from AntiCheat
        /// </summary>
        public static void IpcSetMessageCallback(Action<string> callback)
        {
            try
            {
                if (callback != null)
                {
                    _ipcMessageCallback = (msg) => callback(msg);
                    AC_IpcSetMessageCallback(_ipcMessageCallback);
                }
            }
            catch { }
        }

        /// <summary>
        /// Get last IPC error message
        /// </summary>
        public static string IpcGetLastError()
        {
            try
            {
                IntPtr ptr = AC_IpcGetLastError();
                return Marshal.PtrToStringAnsi(ptr) ?? "Unknown IPC error";
            }
            catch
            {
                return "Unknown IPC error";
            }
        }

        // ====================================================================
        // Memory Pattern Scanning Managed Wrappers
        // ====================================================================

        /// <summary>
        /// Initialize memory scanning subsystem
        /// </summary>
        public static bool MemoryScanInit()
        {
            try { return AC_MemoryScanInit(); }
            catch { return false; }
        }

        /// <summary>
        /// Add a cheat pattern to scan for
        /// </summary>
        public static bool AddCheatPattern(string name, byte[] pattern, bool[] mask)
        {
            try
            {
                if (pattern == null || mask == null || pattern.Length != mask.Length)
                    return false;
                return AC_AddCheatPattern(name, pattern, mask, pattern.Length);
            }
            catch { return false; }
        }

        /// <summary>
        /// Scan a process memory for cheat patterns
        /// </summary>
        public static bool ScanProcessMemory(uint processId, out string detectedPattern)
        {
            detectedPattern = null;
            try
            {
                StringBuilder sb = new StringBuilder(256);
                if (AC_ScanProcessMemory(processId, sb, sb.Capacity))
                {
                    detectedPattern = sb.ToString();
                    return true;
                }
                return false;
            }
            catch { return false; }
        }

        /// <summary>
        /// Scan current process memory for cheat patterns
        /// </summary>
        public static bool ScanCurrentProcess(out string detectedPattern)
        {
            detectedPattern = null;
            try
            {
                StringBuilder sb = new StringBuilder(256);
                if (AC_ScanCurrentProcess(sb, sb.Capacity))
                {
                    detectedPattern = sb.ToString();
                    return true;
                }
                return false;
            }
            catch { return false; }
        }

        /// <summary>
        /// Get number of registered patterns
        /// </summary>
        public static int GetPatternCount()
        {
            try { return AC_GetPatternCount(); }
            catch { return 0; }
        }

        /// <summary>
        /// Clear all registered patterns
        /// </summary>
        public static void ClearPatterns()
        {
            try { AC_ClearPatterns(); }
            catch { }
        }

        /// <summary>
        /// Get pattern scanning error message
        /// </summary>
        public static string GetPatternError()
        {
            try
            {
                IntPtr ptr = AC_GetPatternError();
                return Marshal.PtrToStringAnsi(ptr) ?? "Unknown error";
            }
            catch { return "Unknown error"; }
        }

        /// <summary>
        /// Detect code modifications in memory region
        /// </summary>
        public static bool DetectCodeModification(IntPtr codeStart, UIntPtr codeSize, uint originalHash)
        {
            try { return AC_DetectCodeModification(codeStart, codeSize, originalHash); }
            catch { return false; }
        }

        /// <summary>
        /// Detect code caves (injected code regions)
        /// </summary>
        public static bool DetectCodeCaves(out string details)
        {
            details = null;
            try
            {
                StringBuilder sb = new StringBuilder(512);
                if (AC_DetectCodeCaves(sb, sb.Capacity))
                {
                    details = sb.ToString();
                    return true;
                }
                return false;
            }
            catch { return false; }
        }

        // ====================================================================
        // File Protection Managed Wrappers
        // ====================================================================

        /// <summary>
        /// Initialize file protection subsystem
        /// </summary>
        public static bool FileProtectionInit()
        {
            try { return AC_FileProtectionInit(); }
            catch { return false; }
        }

        /// <summary>
        /// Shutdown file protection subsystem
        /// </summary>
        public static void FileProtectionShutdown()
        {
            try { AC_FileProtectionShutdown(); }
            catch { }
        }

        /// <summary>
        /// Add file to protection list
        /// </summary>
        public static bool ProtectFile(string filePath)
        {
            try { return AC_ProtectFile(filePath); }
            catch { return false; }
        }

        /// <summary>
        /// Add file to protection list (ANSI version)
        /// </summary>
        public static bool ProtectFileA(string filePath)
        {
            try { return AC_ProtectFileA(filePath); }
            catch { return false; }
        }

        /// <summary>
        /// Remove file from protection list
        /// </summary>
        public static bool UnprotectFile(string filePath)
        {
            try { return AC_UnprotectFile(filePath); }
            catch { return false; }
        }

        /// <summary>
        /// Verify integrity of a protected file
        /// </summary>
        public static bool VerifyFileIntegrity(string filePath)
        {
            try { return AC_VerifyFileIntegrity(filePath); }
            catch { return false; }
        }

        /// <summary>
        /// Verify all protected files
        /// </summary>
        public static bool VerifyAllFiles(out string failedFile)
        {
            failedFile = null;
            try
            {
                StringBuilder sb = new StringBuilder(512);
                if (AC_VerifyAllFiles(sb, sb.Capacity))
                {
                    failedFile = sb.ToString();
                    return true;
                }
                return false;
            }
            catch { return false; }
        }

        /// <summary>
        /// Start file monitoring thread
        /// </summary>
        public static bool StartFileMonitoring()
        {
            try { return AC_StartFileMonitoring(); }
            catch { return false; }
        }

        /// <summary>
        /// Stop file monitoring thread
        /// </summary>
        public static void StopFileMonitoring()
        {
            try { AC_StopFileMonitoring(); }
            catch { }
        }

        /// <summary>
        /// Get number of protected files
        /// </summary>
        public static int GetProtectedFileCount()
        {
            try { return AC_GetProtectedFileCount(); }
            catch { return 0; }
        }

        /// <summary>
        /// Get CRC32 hash of a file
        /// </summary>
        public static uint GetFileHash(string filePath)
        {
            try { return AC_GetFileHash(filePath); }
            catch { return 0; }
        }

        /// <summary>
        /// Get CRC32 hash of a file (ANSI version)
        /// </summary>
        public static uint GetFileHashA(string filePath)
        {
            try { return AC_GetFileHashA(filePath); }
            catch { return 0; }
        }

        /// <summary>
        /// Get file protection error message
        /// </summary>
        public static string GetFileProtectionError()
        {
            try
            {
                IntPtr ptr = AC_GetFileProtectionError();
                return Marshal.PtrToStringAnsi(ptr) ?? "Unknown error";
            }
            catch { return "Unknown error"; }
        }

        /// <summary>
        /// Protect all files in a directory matching pattern
        /// </summary>
        public static int ProtectDirectory(string dirPath, string pattern)
        {
            try { return AC_ProtectDirectory(dirPath, pattern); }
            catch { return 0; }
        }

        // ====================================================================
        // Encryption Library Managed Wrappers
        // ====================================================================

        /// <summary>
        /// Initialize encryption subsystem
        /// </summary>
        public static bool EncryptionInit()
        {
            try { return AC_EncryptionInit(); }
            catch { return false; }
        }

        /// <summary>
        /// Generate a random session key
        /// </summary>
        public static bool GenerateSessionKey()
        {
            try { return AC_GenerateSessionKey(); }
            catch { return false; }
        }

        /// <summary>
        /// Set the session encryption key
        /// </summary>
        public static bool SetSessionKey(byte[] key)
        {
            try { return AC_SetSessionKey(key, key?.Length ?? 0); }
            catch { return false; }
        }

        /// <summary>
        /// Get the current session encryption key
        /// </summary>
        public static byte[] GetSessionKey(int keySize = 32)
        {
            try
            {
                byte[] buffer = new byte[keySize];
                if (AC_GetSessionKey(buffer, keySize))
                    return buffer;
                return null;
            }
            catch { return null; }
        }

        /// <summary>
        /// XOR encrypt data in-place
        /// </summary>
        public static bool XorEncrypt(byte[] data, byte[] key)
        {
            try { return AC_XorEncrypt(data, data?.Length ?? 0, key, key?.Length ?? 0); }
            catch { return false; }
        }

        /// <summary>
        /// XOR decrypt data in-place
        /// </summary>
        public static bool XorDecrypt(byte[] data, byte[] key)
        {
            try { return AC_XorDecrypt(data, data?.Length ?? 0, key, key?.Length ?? 0); }
            catch { return false; }
        }

        /// <summary>
        /// RC4 encrypt data in-place
        /// </summary>
        public static bool RC4Encrypt(byte[] data, byte[] key)
        {
            try { return AC_RC4Encrypt(data, data?.Length ?? 0, key, key?.Length ?? 0); }
            catch { return false; }
        }

        /// <summary>
        /// RC4 decrypt data in-place
        /// </summary>
        public static bool RC4Decrypt(byte[] data, byte[] key)
        {
            try { return AC_RC4Decrypt(data, data?.Length ?? 0, key, key?.Length ?? 0); }
            catch { return false; }
        }

        /// <summary>
        /// Encrypt data using the session key
        /// </summary>
        public static bool EncryptWithSessionKey(byte[] data)
        {
            try { return AC_EncryptWithSessionKey(data, data?.Length ?? 0); }
            catch { return false; }
        }

        /// <summary>
        /// Decrypt data using the session key
        /// </summary>
        public static bool DecryptWithSessionKey(byte[] data)
        {
            try { return AC_DecryptWithSessionKey(data, data?.Length ?? 0); }
            catch { return false; }
        }

        /// <summary>
        /// Generate cryptographically secure random bytes
        /// </summary>
        public static byte[] GenerateRandom(int length)
        {
            try
            {
                byte[] buffer = new byte[length];
                if (AC_GenerateRandom(buffer, length))
                    return buffer;
                return null;
            }
            catch { return null; }
        }

        /// <summary>
        /// Calculate CRC32 hash of data
        /// </summary>
        public static uint HashData(byte[] data)
        {
            try { return AC_HashData(data, data?.Length ?? 0); }
            catch { return 0; }
        }

        /// <summary>
        /// Calculate CRC32 hash of string
        /// </summary>
        public static uint HashString(string str)
        {
            try { return AC_HashString(str); }
            catch { return 0; }
        }

        /// <summary>
        /// Obfuscate data in-place
        /// </summary>
        public static void ObfuscateData(byte[] data)
        {
            try { AC_ObfuscateData(data, data?.Length ?? 0); }
            catch { }
        }

        /// <summary>
        /// Deobfuscate data in-place
        /// </summary>
        public static void DeobfuscateData(byte[] data)
        {
            try { AC_DeobfuscateData(data, data?.Length ?? 0); }
            catch { }
        }

        /// <summary>
        /// Get encryption error message
        /// </summary>
        public static string GetEncryptionError()
        {
            try
            {
                IntPtr ptr = AC_GetEncryptionError();
                return Marshal.PtrToStringAnsi(ptr) ?? "Unknown error";
            }
            catch { return "Unknown error"; }
        }

        /// <summary>
        /// Securely clear sensitive data from memory
        /// </summary>
        public static void SecureClear(byte[] buffer)
        {
            try { AC_SecureClear(buffer, (UIntPtr)(buffer?.Length ?? 0)); }
            catch { }
        }

        // ====================================================================
        // Hook Detection Managed Wrappers
        // ====================================================================

        /// <summary>
        /// Initialize hook detection subsystem
        /// </summary>
        public static bool HookDetectionInit()
        {
            try { return AC_HookDetectionInit(); }
            catch { return false; }
        }

        /// <summary>
        /// Detect inline hook on a function
        /// </summary>
        public static bool DetectInlineHook(string moduleName, string functionName, out string hookDetails)
        {
            hookDetails = null;
            try
            {
                StringBuilder sb = new StringBuilder(512);
                if (AC_DetectInlineHook(moduleName, functionName, sb, sb.Capacity))
                {
                    hookDetails = sb.ToString();
                    return true;
                }
                return false;
            }
            catch { return false; }
        }

        /// <summary>
        /// Detect IAT hook on a function
        /// </summary>
        public static bool DetectIATHook(string targetModule, string importModule, string functionName, out string hookDetails)
        {
            hookDetails = null;
            try
            {
                StringBuilder sb = new StringBuilder(512);
                if (AC_DetectIATHook(targetModule, importModule, functionName, sb, sb.Capacity))
                {
                    hookDetails = sb.ToString();
                    return true;
                }
                return false;
            }
            catch { return false; }
        }

        /// <summary>
        /// Scan for common API hooks
        /// </summary>
        public static int ScanCommonHooks(out string report)
        {
            report = null;
            try
            {
                StringBuilder sb = new StringBuilder(4096);
                int count = AC_ScanCommonHooks(sb, sb.Capacity);
                report = sb.ToString();
                return count;
            }
            catch { return 0; }
        }

        /// <summary>
        /// Get count of detected hooks
        /// </summary>
        public static int GetDetectedHookCount()
        {
            try { return AC_GetDetectedHookCount(); }
            catch { return 0; }
        }

        /// <summary>
        /// Clear detected hooks list
        /// </summary>
        public static void ClearDetectedHooks()
        {
            try { AC_ClearDetectedHooks(); }
            catch { }
        }

        /// <summary>
        /// Get hook detection error message
        /// </summary>
        public static string GetHookError()
        {
            try
            {
                IntPtr ptr = AC_GetHookError();
                return Marshal.PtrToStringAnsi(ptr) ?? "Unknown error";
            }
            catch { return "Unknown error"; }
        }

        /// <summary>
        /// Detect Vectored Exception Handler hooks
        /// </summary>
        public static bool DetectVEHHooks()
        {
            try { return AC_DetectVEHHooks(); }
            catch { return false; }
        }

        /// <summary>
        /// Detect hardware breakpoints (debug registers)
        /// </summary>
        public static bool DetectHardwareBreakpoints()
        {
            try { return AC_DetectHardwareBreakpoints(); }
            catch { return false; }
        }

        // ====================================================================
        // Anti-Macro Detection Managed Wrappers
        // ====================================================================

        /// <summary>
        /// Initialize anti-macro detection subsystem
        /// </summary>
        public static bool AntiMacroInit()
        {
            try { return AC_AntiMacroInit(); }
            catch { return false; }
        }

        /// <summary>
        /// Shutdown anti-macro detection subsystem
        /// </summary>
        public static void AntiMacroShutdown()
        {
            try { AC_AntiMacroShutdown(); }
            catch { }
        }

        /// <summary>
        /// Start input monitoring for macro detection
        /// </summary>
        public static bool StartInputMonitoring()
        {
            try { return AC_StartInputMonitoring(); }
            catch { return false; }
        }

        /// <summary>
        /// Stop input monitoring
        /// </summary>
        public static void StopInputMonitoring()
        {
            try { AC_StopInputMonitoring(); }
            catch { }
        }

        /// <summary>
        /// Check if input monitoring is active
        /// </summary>
        public static bool IsInputMonitoringActive()
        {
            try { return AC_IsInputMonitoringActive(); }
            catch { return false; }
        }

        /// <summary>
        /// Detect auto-clicker usage
        /// </summary>
        public static bool DetectAutoClicker(out string details)
        {
            details = null;
            try
            {
                StringBuilder sb = new StringBuilder(512);
                if (AC_DetectAutoClicker(sb, sb.Capacity))
                {
                    details = sb.ToString();
                    return true;
                }
                return false;
            }
            catch { return false; }
        }

        /// <summary>
        /// Detect keyboard macro usage
        /// </summary>
        public static bool DetectKeyboardMacro(out string details)
        {
            details = null;
            try
            {
                StringBuilder sb = new StringBuilder(512);
                if (AC_DetectKeyboardMacro(sb, sb.Capacity))
                {
                    details = sb.ToString();
                    return true;
                }
                return false;
            }
            catch { return false; }
        }

        /// <summary>
        /// Detect input automation software
        /// </summary>
        public static bool DetectInputAutomation(out string details)
        {
            details = null;
            try
            {
                StringBuilder sb = new StringBuilder(512);
                if (AC_DetectInputAutomation(sb, sb.Capacity))
                {
                    details = sb.ToString();
                    return true;
                }
                return false;
            }
            catch { return false; }
        }

        /// <summary>
        /// Click statistics for macro detection analysis
        /// </summary>
        public struct ClickStats
        {
            public int TotalClicks;
            public double AverageInterval;
            public double Variance;
            public int SuspiciousCount;
        }

        /// <summary>
        /// Get click statistics for analysis
        /// </summary>
        public static ClickStats GetClickStats()
        {
            var stats = new ClickStats();
            try
            {
                AC_GetClickStats(out stats.TotalClicks, out stats.AverageInterval,
                    out stats.Variance, out stats.SuspiciousCount);
            }
            catch { }
            return stats;
        }

        /// <summary>
        /// Reset macro detection statistics
        /// </summary>
        public static void ResetMacroStats()
        {
            try { AC_ResetMacroStats(); }
            catch { }
        }

        /// <summary>
        /// Detect known macro software processes
        /// </summary>
        public static bool DetectMacroSoftware(out string detectedName)
        {
            detectedName = null;
            try
            {
                StringBuilder sb = new StringBuilder(256);
                if (AC_DetectMacroSoftware(sb, sb.Capacity))
                {
                    detectedName = sb.ToString();
                    return true;
                }
                return false;
            }
            catch { return false; }
        }

        /// <summary>
        /// Get macro detection error message
        /// </summary>
        public static string GetMacroError()
        {
            try
            {
                IntPtr ptr = AC_GetMacroError();
                return Marshal.PtrToStringAnsi(ptr) ?? "Unknown error";
            }
            catch { return "Unknown error"; }
        }
    }
}
