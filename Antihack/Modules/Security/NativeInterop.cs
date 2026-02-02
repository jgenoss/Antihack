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
    }
}
