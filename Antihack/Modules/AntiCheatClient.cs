/**
 * AntiCheatClient - Main Client Facade
 * Integrates all modules into a single easy-to-use interface
 */

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AntiCheat.Modules.Config;
using AntiCheat.Modules.Logging;
using AntiCheat.Modules.Network;
using AntiCheat.Modules.Security;

namespace AntiCheat.Modules
{
    /// <summary>
    /// Client state
    /// </summary>
    public enum ClientState
    {
        Uninitialized,
        Initializing,
        Connecting,
        Connected,
        Running,
        Disconnected,
        Error
    }

    /// <summary>
    /// Main AntiCheat client that integrates all modules
    /// </summary>
    public class AntiCheatClient : IDisposable
    {
        // Modules
        private readonly ConfigManager _config;
        private readonly NetworkClient _network;
        private readonly SecurityService _security;

        // State
        private ClientState _state;
        private string _userId;
        private string _hwid;

        // Blacklisted processes
        private readonly List<string> _blacklist;

        // Events
        public event EventHandler<ClientState> OnStateChanged;
        public event EventHandler<SecurityDetectionEventArgs> OnSecurityDetection;
        public event EventHandler<string> OnServerCommand;

        public ClientState State => _state;
        public bool IsConnected => _network?.IsConnected ?? false;
        public bool IsSecurityEnabled => _security?.IsNativeModuleLoaded ?? false;

        public AntiCheatClient()
        {
            _config = new ConfigManager();
            _network = new NetworkClient();
            _security = new SecurityService();
            _blacklist = new List<string>();
            _state = ClientState.Uninitialized;

            // Wire up events
            _config.OnLogMessage += (s, msg) => Logger.Info("Config", msg);
            _network.OnLogMessage += (s, msg) => Logger.Info("Network", msg);
            _security.OnLogMessage += (s, msg) => Logger.Info("Security", msg);

            _security.OnDetection += Security_OnDetection;
            _network.OnDataReceived += Network_OnDataReceived;
            _network.OnDisconnected += Network_OnDisconnected;
        }

        /// <summary>
        /// Initialize the client with all modules
        /// </summary>
        public async Task<bool> InitializeAsync(string[] args)
        {
            SetState(ClientState.Initializing);

            try
            {
                // Initialize logger
                Logger.Initialize();
                Logger.Info("Client", "=== AntiCheat Client Starting ===");

                // Validate arguments
                if (args == null || args.Length < 2)
                {
                    Logger.Error("Client", "Invalid arguments provided");
                    SetState(ClientState.Error);
                    return false;
                }

                _userId = args[0];

                // Load configuration
                if (!_config.Load())
                {
                    Logger.Error("Client", "Failed to load configuration");
                    SetState(ClientState.Error);
                    return false;
                }

                // Validate configuration
                if (!_config.Validate(out string configError))
                {
                    Logger.Error("Client", $"Invalid configuration: {configError}");
                    SetState(ClientState.Error);
                    return false;
                }

                // Initialize security module
                if (!_security.Initialize())
                {
                    Logger.Warning("Client", "Security module initialization failed - continuing with limited protection");
                }

                // Set blacklist
                _security.SetBlacklist(_blacklist);

                // Generate HWID
                _hwid = _security.GetHardwareId();
                Logger.Info("Client", $"Hardware ID: {_hwid}");

                // Configure network
                _network.Configure(_config.Config.Network);

                Logger.Info("Client", "Initialization complete");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Critical("Client", "Initialization failed", ex);
                SetState(ClientState.Error);
                return false;
            }
        }

        /// <summary>
        /// Connect to server and authenticate
        /// </summary>
        public async Task<bool> ConnectAsync()
        {
            SetState(ClientState.Connecting);

            try
            {
                // Connect to server
                if (!await _network.ConnectAsync())
                {
                    Logger.Error("Client", "Failed to connect to server");
                    SetState(ClientState.Disconnected);
                    return false;
                }

                // Authenticate
                if (!await _network.AuthenticateAsync(_hwid))
                {
                    Logger.Error("Client", "Authentication failed");
                    SetState(ClientState.Error);
                    return false;
                }

                SetState(ClientState.Connected);
                Logger.Info("Client", "Connected and authenticated");

                return true;
            }
            catch (Exception ex)
            {
                Logger.Error("Client", "Connection failed", ex);
                SetState(ClientState.Error);
                return false;
            }
        }

        /// <summary>
        /// Start protection and monitoring
        /// </summary>
        public void StartProtection()
        {
            if (_state != ClientState.Connected)
            {
                Logger.Warning("Client", "Cannot start protection - not connected");
                return;
            }

            SetState(ClientState.Running);

            // Install hooks
            _security.InstallProtection();

            // Start continuous scanning
            _security.StartContinuousScan(5000);

            // Start heartbeat
            _network.StartHeartbeat(120000);

            Logger.Info("Client", "Protection active");
        }

        /// <summary>
        /// Stop protection
        /// </summary>
        public void StopProtection()
        {
            _security.StopContinuousScan();
            _security.RemoveProtection();
            _network.StopHeartbeat();

            Logger.Info("Client", "Protection stopped");
        }

        /// <summary>
        /// Set the process blacklist
        /// </summary>
        public void SetBlacklist(IEnumerable<string> processes)
        {
            _blacklist.Clear();
            _blacklist.AddRange(processes);
            _security.SetBlacklist(_blacklist);
        }

        /// <summary>
        /// Report a threat to the server
        /// </summary>
        public async Task ReportThreatAsync(string threatType, string details)
        {
            await _network.ReportDetectionAsync(threatType, details, _userId);
        }

        /// <summary>
        /// Perform a manual security scan
        /// </summary>
        public async Task<SecurityScanResult> ScanAsync()
        {
            return await _security.PerformFullScanAsync();
        }

        private void Security_OnDetection(object sender, SecurityDetectionEventArgs e)
        {
            Logger.Warning("Security", $"Detection: {e.DetectionType} - {e.Details}");

            // Report to server
            Task.Run(async () =>
            {
                await _network.ReportDetectionAsync(e.DetectionType, e.Details, _userId);
            });

            // Raise event for UI
            OnSecurityDetection?.Invoke(this, e);

            // Critical detections may require action
            if (e.IsCritical)
            {
                Logger.Critical("Security", $"CRITICAL: {e.DetectionType}");
            }
        }

        private void Network_OnDataReceived(object sender, NetworkEventArgs e)
        {
            try
            {
                // Parse and handle server commands
                dynamic data = Newtonsoft.Json.JsonConvert.DeserializeObject(e.Data);
                string action = data?.action?.ToString();

                if (!string.IsNullOrEmpty(action))
                {
                    OnServerCommand?.Invoke(this, e.Data);
                }
            }
            catch (Exception ex)
            {
                Logger.Error("Client", "Error processing server data", ex);
            }
        }

        private void Network_OnDisconnected(object sender, NetworkEventArgs e)
        {
            SetState(ClientState.Disconnected);
            Logger.Warning("Client", "Disconnected from server");
        }

        private void SetState(ClientState newState)
        {
            if (_state != newState)
            {
                _state = newState;
                OnStateChanged?.Invoke(this, newState);
            }
        }

        public void Dispose()
        {
            StopProtection();
            _network?.Disconnect();
            _network?.Dispose();
            _security?.Dispose();

            Logger.Info("Client", "Client disposed");
        }
    }
}
