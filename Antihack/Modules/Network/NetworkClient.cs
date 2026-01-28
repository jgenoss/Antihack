/**
 * NetworkClient - TCP Client Module
 * Handles all network communication with the server
 */

using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using SuperSimpleTcp;

namespace AntiCheat.Modules.Network
{
    /// <summary>
    /// Network configuration
    /// </summary>
    public class NetworkConfig
    {
        public string IPv4Address { get; set; }
        public string IPv6Address { get; set; }
        public int Port { get; set; }
        public string AuthKey { get; set; }
        public string Priority { get; set; } = "ipv4";
        public bool EnableFallback { get; set; } = true;
        public int ConnectionTimeout { get; set; } = 10000;
        public int MaxRetries { get; set; } = 5;
    }

    /// <summary>
    /// Network event arguments
    /// </summary>
    public class NetworkEventArgs : EventArgs
    {
        public string EventType { get; set; }
        public string Data { get; set; }
        public bool Success { get; set; }
    }

    /// <summary>
    /// Network client for server communication
    /// </summary>
    public class NetworkClient : IDisposable
    {
        private SimpleTcpClient _client;
        private NetworkConfig _config;
        private string _activeIp;
        private bool _isConnected;
        private CancellationTokenSource _heartbeatCts;

        public event EventHandler<NetworkEventArgs> OnConnected;
        public event EventHandler<NetworkEventArgs> OnDisconnected;
        public event EventHandler<NetworkEventArgs> OnDataReceived;
        public event EventHandler<string> OnLogMessage;

        public bool IsConnected => _client?.IsConnected ?? false;
        public string ActiveAddress => _activeIp;

        public NetworkClient()
        {
        }

        /// <summary>
        /// Configure the network client
        /// </summary>
        public void Configure(NetworkConfig config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
        }

        /// <summary>
        /// Initialize and connect to server
        /// </summary>
        public async Task<bool> ConnectAsync()
        {
            if (_config == null)
            {
                Log("Network not configured");
                return false;
            }

            // Select IP based on priority
            _activeIp = SelectAddress();

            if (string.IsNullOrEmpty(_activeIp))
            {
                Log("No valid server address configured");
                return false;
            }

            Log($"Connecting to {_activeIp}:{_config.Port}...");

            // Try primary address
            bool connected = await TryConnectAsync(_activeIp, _config.Port);

            // Try fallback if enabled and primary failed
            if (!connected && _config.EnableFallback)
            {
                string fallbackIp = GetFallbackAddress();
                if (!string.IsNullOrEmpty(fallbackIp) && fallbackIp != _activeIp)
                {
                    Log($"Trying fallback address: {fallbackIp}");
                    _activeIp = fallbackIp;
                    connected = await TryConnectAsync(_activeIp, _config.Port);
                }
            }

            return connected;
        }

        private string SelectAddress()
        {
            if (_config.Priority?.ToLower() == "ipv6")
            {
                if (!string.IsNullOrWhiteSpace(_config.IPv6Address))
                    return NormalizeIpv6(_config.IPv6Address);
                if (_config.EnableFallback && !string.IsNullOrWhiteSpace(_config.IPv4Address))
                    return _config.IPv4Address;
            }
            else
            {
                if (!string.IsNullOrWhiteSpace(_config.IPv4Address))
                    return _config.IPv4Address;
                if (_config.EnableFallback && !string.IsNullOrWhiteSpace(_config.IPv6Address))
                    return NormalizeIpv6(_config.IPv6Address);
            }

            return null;
        }

        private string GetFallbackAddress()
        {
            if (_config.Priority?.ToLower() == "ipv6")
            {
                return _config.IPv4Address;
            }
            else
            {
                return !string.IsNullOrWhiteSpace(_config.IPv6Address)
                    ? NormalizeIpv6(_config.IPv6Address)
                    : null;
            }
        }

        private string NormalizeIpv6(string address)
        {
            return address?.Trim('[', ']');
        }

        private async Task<bool> TryConnectAsync(string ip, int port)
        {
            return await Task.Run(() =>
            {
                int retryCount = 0;
                int baseDelay = 2000;

                while (retryCount < _config.MaxRetries)
                {
                    try
                    {
                        Log($"Connection attempt {retryCount + 1}/{_config.MaxRetries}");

                        // Dispose old client if exists
                        _client?.Dispose();

                        // Create new client
                        _client = new SimpleTcpClient(ip, port);
                        _client.Events.Connected += Client_Connected;
                        _client.Events.Disconnected += Client_Disconnected;
                        _client.Events.DataReceived += Client_DataReceived;

                        _client.Connect();
                        Thread.Sleep(2000); // Wait for connection to stabilize

                        if (_client.IsConnected)
                        {
                            _isConnected = true;
                            return true;
                        }
                    }
                    catch (SocketException sockEx)
                    {
                        string error = GetSocketErrorDescription(sockEx.SocketErrorCode);
                        Log($"Socket error: {error}");

                        if (IsUnrecoverableError(sockEx.SocketErrorCode))
                        {
                            break;
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"Connection error: {ex.Message}");
                    }

                    retryCount++;
                    int delay = Math.Min(baseDelay * retryCount, 10000);
                    Thread.Sleep(delay);
                }

                return false;
            });
        }

        /// <summary>
        /// Send authentication request
        /// </summary>
        public async Task<bool> AuthenticateAsync(string hwid)
        {
            if (!IsConnected) return false;

            var authRequest = new
            {
                action = "AUTH",
                key = _config.AuthKey,
                hwid = hwid
            };

            return await SendAsync(JsonConvert.SerializeObject(authRequest));
        }

        /// <summary>
        /// Send data to server
        /// </summary>
        public async Task<bool> SendAsync(string data)
        {
            return await Task.Run(() =>
            {
                try
                {
                    if (_client?.IsConnected == true)
                    {
                        _client.Send(data);
                        return true;
                    }
                    return false;
                }
                catch (Exception ex)
                {
                    Log($"Send error: {ex.Message}");
                    return false;
                }
            });
        }

        /// <summary>
        /// Send JSON object to server
        /// </summary>
        public async Task<bool> SendJsonAsync(object data)
        {
            string json = JsonConvert.SerializeObject(data);
            return await SendAsync(json);
        }

        /// <summary>
        /// Report a security detection to server
        /// </summary>
        public async Task ReportDetectionAsync(string detectionType, string details, string userId)
        {
            var report = new
            {
                action = detectionType,
                message = details,
                user_id = userId,
                timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
            };

            await SendJsonAsync(report);
        }

        /// <summary>
        /// Start heartbeat timer
        /// </summary>
        public void StartHeartbeat(int intervalMs = 120000)
        {
            _heartbeatCts?.Cancel();
            _heartbeatCts = new CancellationTokenSource();

            Task.Run(async () =>
            {
                while (!_heartbeatCts.Token.IsCancellationRequested)
                {
                    if (IsConnected)
                    {
                        var heartbeat = new
                        {
                            action = "HEARTBEAT",
                            timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
                        };
                        await SendJsonAsync(heartbeat);
                    }

                    await Task.Delay(intervalMs, _heartbeatCts.Token);
                }
            }, _heartbeatCts.Token);
        }

        /// <summary>
        /// Stop heartbeat timer
        /// </summary>
        public void StopHeartbeat()
        {
            _heartbeatCts?.Cancel();
        }

        /// <summary>
        /// Disconnect from server
        /// </summary>
        public void Disconnect()
        {
            StopHeartbeat();

            if (_client != null)
            {
                try
                {
                    _client.Disconnect();
                }
                catch { }
            }

            _isConnected = false;
        }

        private void Client_Connected(object sender, ConnectionEventArgs e)
        {
            Log("Connected to server");
            OnConnected?.Invoke(this, new NetworkEventArgs
            {
                EventType = "CONNECTED",
                Success = true
            });
        }

        private void Client_Disconnected(object sender, ConnectionEventArgs e)
        {
            _isConnected = false;
            Log("Disconnected from server");
            OnDisconnected?.Invoke(this, new NetworkEventArgs
            {
                EventType = "DISCONNECTED",
                Success = false
            });
        }

        private void Client_DataReceived(object sender, DataReceivedEventArgs e)
        {
            try
            {
                byte[] data = e.Data.Array;
                int offset = e.Data.Offset;
                int count = e.Data.Count;

                string json = Encoding.UTF8.GetString(data, offset, count);

                OnDataReceived?.Invoke(this, new NetworkEventArgs
                {
                    EventType = "DATA",
                    Data = json,
                    Success = true
                });
            }
            catch (Exception ex)
            {
                Log($"Data receive error: {ex.Message}");
            }
        }

        private string GetSocketErrorDescription(SocketError error)
        {
            return error switch
            {
                SocketError.ConnectionRefused => "Connection refused - server not running",
                SocketError.NetworkUnreachable => "Network unreachable",
                SocketError.HostUnreachable => "Host unreachable",
                SocketError.TimedOut => "Connection timed out",
                SocketError.AddressFamilyNotSupported => "Address family not supported (IPv6?)",
                _ => $"Socket error: {error}"
            };
        }

        private bool IsUnrecoverableError(SocketError error)
        {
            return error == SocketError.AddressFamilyNotSupported ||
                   error == SocketError.AddressNotAvailable ||
                   error == SocketError.HostNotFound ||
                   error == SocketError.ProtocolNotSupported;
        }

        private void Log(string message)
        {
            OnLogMessage?.Invoke(this, message);
        }

        public void Dispose()
        {
            Disconnect();
            _client?.Dispose();
        }
    }
}
