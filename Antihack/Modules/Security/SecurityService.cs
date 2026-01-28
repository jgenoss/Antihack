/**
 * SecurityService - High-level security scanning service
 * Coordinates native and managed security checks
 */

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AntiCheat.Modules.Security
{
    /// <summary>
    /// Detection event arguments
    /// </summary>
    public class SecurityDetectionEventArgs : EventArgs
    {
        public string DetectionType { get; set; }
        public string ProcessName { get; set; }
        public string Details { get; set; }
        public DateTime Timestamp { get; set; }
        public bool IsCritical { get; set; }
    }

    /// <summary>
    /// Security scan result
    /// </summary>
    public class SecurityScanResult
    {
        public bool IsClean { get; set; }
        public List<string> Detections { get; set; } = new List<string>();
        public DebuggerDetectionFlags DebuggerFlags { get; set; }
        public string DetectedProcess { get; set; }
        public string InjectedDll { get; set; }
    }

    /// <summary>
    /// High-level security service that combines native and managed detection
    /// </summary>
    public class SecurityService : IDisposable
    {
        private readonly List<string> _blacklistedProcesses;
        private bool _isRunning;
        private bool _nativeInitialized;
        private CancellationTokenSource _scanCts;

        public event EventHandler<SecurityDetectionEventArgs> OnDetection;
        public event EventHandler<string> OnLogMessage;

        public bool IsNativeModuleLoaded => _nativeInitialized;

        public SecurityService()
        {
            _blacklistedProcesses = new List<string>();
            _isRunning = false;
        }

        /// <summary>
        /// Initialize the security service
        /// </summary>
        public bool Initialize()
        {
            try
            {
                // Try to initialize native module
                _nativeInitialized = NativeInterop.Initialize();

                if (_nativeInitialized)
                {
                    string version = NativeInterop.GetVersion();
                    Log($"Native security module loaded (v{version})");

                    // Set up detection callback
                    NativeInterop.SetDetectionCallback((type, details) =>
                    {
                        RaiseDetection(type, details, null, true);
                    });
                }
                else
                {
                    Log("Native module not available, using managed detection only");
                }

                return true;
            }
            catch (Exception ex)
            {
                Log($"Security service initialization failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Set the list of blacklisted processes
        /// </summary>
        public void SetBlacklist(IEnumerable<string> processes)
        {
            _blacklistedProcesses.Clear();
            _blacklistedProcesses.AddRange(processes);

            if (_nativeInitialized)
            {
                NativeInterop.ClearBlacklist();
                foreach (var process in _blacklistedProcesses)
                {
                    NativeInterop.AddToBlacklist(process);
                }
                Log($"Blacklist loaded: {NativeInterop.GetBlacklistCount()} processes");
            }
        }

        /// <summary>
        /// Perform a full security scan
        /// </summary>
        public async Task<SecurityScanResult> PerformFullScanAsync()
        {
            return await Task.Run(() =>
            {
                var result = new SecurityScanResult { IsClean = true };

                // 1. Scan for blacklisted processes
                if (_nativeInitialized)
                {
                    if (NativeInterop.ScanProcesses(out string detected))
                    {
                        result.IsClean = false;
                        result.DetectedProcess = detected;
                        result.Detections.Add($"Blacklisted process: {detected}");
                        RaiseDetection("BLACKLISTED_PROCESS", detected, detected, true);
                    }
                }

                // 2. Check for debuggers
                if (_nativeInitialized)
                {
                    var debuggerFlags = NativeInterop.DetectDebugger();
                    result.DebuggerFlags = debuggerFlags;

                    if (debuggerFlags != DebuggerDetectionFlags.None)
                    {
                        result.IsClean = false;
                        result.Detections.Add($"Debugger detected: {debuggerFlags}");
                        RaiseDetection("DEBUGGER", debuggerFlags.ToString(), null, true);
                    }

                    // Check debugger processes
                    if (NativeInterop.DetectDebuggerProcess(out string debugger))
                    {
                        result.IsClean = false;
                        result.Detections.Add($"Debugger process: {debugger}");
                        RaiseDetection("DEBUGGER_PROCESS", debugger, debugger, true);
                    }
                }

                // 3. Scan for injected DLLs
                if (_nativeInitialized)
                {
                    if (NativeInterop.ScanForInjectedDlls(out string dll))
                    {
                        result.IsClean = false;
                        result.InjectedDll = dll;
                        result.Detections.Add($"Suspicious DLL: {dll}");
                        RaiseDetection("INJECTED_DLL", dll, null, true);
                    }
                }

                // 4. Check for hooked APIs
                if (_nativeInitialized)
                {
                    CheckCriticalApiHooks(result);
                }

                return result;
            });
        }

        /// <summary>
        /// Start continuous background scanning
        /// </summary>
        public void StartContinuousScan(int intervalMs = 5000)
        {
            if (_isRunning) return;

            _isRunning = true;
            _scanCts = new CancellationTokenSource();

            Task.Run(async () =>
            {
                while (!_scanCts.Token.IsCancellationRequested)
                {
                    try
                    {
                        var result = await PerformFullScanAsync();
                        if (!result.IsClean)
                        {
                            Log($"Security scan found {result.Detections.Count} issue(s)");
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"Scan error: {ex.Message}");
                    }

                    await Task.Delay(intervalMs, _scanCts.Token);
                }
            }, _scanCts.Token);

            Log("Continuous security scanning started");
        }

        /// <summary>
        /// Stop continuous scanning
        /// </summary>
        public void StopContinuousScan()
        {
            if (!_isRunning) return;

            _scanCts?.Cancel();
            _isRunning = false;
            Log("Continuous scanning stopped");
        }

        /// <summary>
        /// Generate hardware ID
        /// </summary>
        public string GetHardwareId()
        {
            if (_nativeInitialized)
            {
                string nativeHwid = NativeInterop.GenerateHWID();
                if (!string.IsNullOrEmpty(nativeHwid))
                {
                    return nativeHwid;
                }
            }

            // Fallback to managed implementation
            return GenerateManagedHwid();
        }

        /// <summary>
        /// Install protective hooks
        /// </summary>
        public bool InstallProtection()
        {
            if (_nativeInitialized)
            {
                bool result = NativeInterop.InstallHooks();
                Log(result ? "Protection hooks installed" : "Failed to install hooks");
                return result;
            }
            return false;
        }

        /// <summary>
        /// Remove protective hooks
        /// </summary>
        public void RemoveProtection()
        {
            if (_nativeInitialized)
            {
                NativeInterop.RemoveHooks();
                Log("Protection hooks removed");
            }
        }

        private void CheckCriticalApiHooks(SecurityScanResult result)
        {
            var criticalApis = new[]
            {
                ("kernel32.dll", "LoadLibraryA"),
                ("kernel32.dll", "LoadLibraryW"),
                ("kernel32.dll", "GetProcAddress"),
                ("ntdll.dll", "NtReadVirtualMemory"),
                ("ntdll.dll", "NtWriteVirtualMemory")
            };

            foreach (var (module, function) in criticalApis)
            {
                if (NativeInterop.IsApiHooked(module, function))
                {
                    result.IsClean = false;
                    result.Detections.Add($"API hooked: {module}!{function}");
                    RaiseDetection("API_HOOK", $"{module}!{function}", null, false);
                }
            }
        }

        private string GenerateManagedHwid()
        {
            // Fallback managed HWID generation
            try
            {
                string machineName = Environment.MachineName;
                string userName = Environment.UserName;
                int processorCount = Environment.ProcessorCount;

                string combined = $"{machineName}-{userName}-{processorCount}";
                int hash = combined.GetHashCode();

                return $"MANAGED-{Math.Abs(hash):X8}";
            }
            catch
            {
                return $"FALLBACK-{Guid.NewGuid():N}".Substring(0, 32);
            }
        }

        private void RaiseDetection(string type, string details, string process, bool isCritical)
        {
            OnDetection?.Invoke(this, new SecurityDetectionEventArgs
            {
                DetectionType = type,
                Details = details,
                ProcessName = process,
                Timestamp = DateTime.Now,
                IsCritical = isCritical
            });
        }

        private void Log(string message)
        {
            OnLogMessage?.Invoke(this, message);
        }

        public void Dispose()
        {
            StopContinuousScan();

            if (_nativeInitialized)
            {
                NativeInterop.RemoveHooks();
                NativeInterop.Shutdown();
            }
        }
    }
}
