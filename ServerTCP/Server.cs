using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Antihack;
using ext_encrypt_decrypt;

//using Newtonsoft.Json;
using json_ext;
using Newtonsoft.Json;
using SuperSimpleTcp;

namespace ServerTCP
{
    public partial class Form1 : Form
    {
        #region Fields & Configuration

        private readonly string _basePath = Directory.GetCurrentDirectory();
        private readonly ClassJson _jsonHelper = new ClassJson();
        private readonly encrypt_decrypt _crypto = new encrypt_decrypt();

        private SimpleTcpServer _server;
        private string _serverIp;
        private int _serverPort;
        private string _serverKey;

        // Stream Viewer Config
        private string _streamHost;
        private int _streamPort;

        // Client Management
        private readonly Dictionary<string, ClientInfo> _connectedClients = new Dictionary<string, ClientInfo>();
        private readonly Dictionary<string, bool> _authenticatedClients = new Dictionary<string, bool>();

        // Security
        private readonly List<string> _ipBlacklist = new List<string>();

        #endregion

        #region Inner Structures

        private class ClientInfo
        {
            public string IpPort { get; set; }
            public DateTime ConnectedTime { get; set; }
            public DateTime LastActivityTime { get; set; }
            public string Status { get; set; }
            public long BytesReceived { get; set; }
            public long BytesSent { get; set; }
        }

        #endregion

        #region Initialization

        public Form1()
        {
            InitializeComponent();
            LoadConfiguration();
            InitializeGui();
        }

        private void Server_Load(object sender, EventArgs e)
        {
            InitializeNetworkService();
        }

        private void InitializeGui()
        {
            inputServerIp.Text = $"{_serverIp}:{_serverPort}";
            inputSelect.SelectedIndex = 0;
            btnSend.Enabled = false;
        }

        private void LoadConfiguration()
        {
            try
            {
                INIFile ini = new INIFile(Path.Combine(_basePath, "Config.ini"));

                // Network Configuration
                string ipv4 = ini.IniReadValue("CONFIG", "IPV4");
                string ipv6 = ini.IniReadValue("CONFIG", "IPV6");

                // Priority: IPv6 > IPv4 > Legacy
                if (!string.IsNullOrWhiteSpace(ipv6))
                    _serverIp = ipv6;
                else if (!string.IsNullOrWhiteSpace(ipv4))
                    _serverIp = ipv4;
                else
                    _serverIp = ini.IniReadValue("CONFIG", "IP");

                _serverPort = int.Parse(ini.IniReadValue("CONFIG", "PORT"));
                _serverKey = ini.IniReadValue("CONFIG", "KEY");

                // Stream Configuration
                _streamHost = ini.IniReadValue("server", "host");
                _streamPort = int.Parse(ini.IniReadValue("server", "port"));
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Configuration Error: {ex.Message}", "Critical Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void InitializeNetworkService()
        {
            try
            {
                string listenAddress = GetDualStackListenAddress(_serverIp);
                _server = new SimpleTcpServer(listenAddress, _serverPort);

                // High Performance Settings
                _server.Settings.MaxConnections = 2000;
                _server.Settings.NoDelay = true;
                _server.Keepalive = new SimpleTcpKeepaliveSettings
                {
                    EnableTcpKeepAlives = true,
                    TcpKeepAliveInterval = 5,
                    TcpKeepAliveTime = 5,
                    TcpKeepAliveRetryCount = 5,
                };

                // Event Binding
                _server.Events.ClientConnected += OnClientConnected;
                _server.Events.ClientDisconnected += OnClientDisconnected;
                _server.Events.DataReceived += OnDataReceived;

                // Maintenance Timers
                InitializeTimers();
            }
            catch (Exception ex)
            {
                LogSystemMessage($"Initialization Failed: {ex.Message}");
            }
        }

        private void InitializeTimers()
        {
            Timer statsTimer = new Timer { Interval = 1000 };
            statsTimer.Tick += (s, e) => UpdateClientStats();
            statsTimer.Start();

            Timer securityTimer = new Timer { Interval = 30000 }; // Check every 30s
            securityTimer.Tick += (s, e) => EnforceSecurityPolicies();
            securityTimer.Start();
        }

        #endregion

        #region Network Logic & Security

        private string GetDualStackListenAddress(string configuredIp)
        {
            if (string.IsNullOrWhiteSpace(configuredIp)) return "::";
            if (configuredIp == "0.0.0.0") return "::";

            if (IPAddress.TryParse(configuredIp, out IPAddress ipAddr))
            {
                if (ipAddr.AddressFamily == AddressFamily.InterNetworkV6) return configuredIp;
                if (ipAddr.Equals(IPAddress.Any)) return "::";
            }
            return configuredIp;
        }

        private string ExtractIpAddress(string ipPort)
        {
            try
            {
                string ip = ipPort;
                if (ipPort.StartsWith("["))
                {
                    int endBracket = ipPort.IndexOf("]");
                    if (endBracket > 0) ip = ipPort.Substring(1, endBracket - 1);
                }
                else
                {
                    int lastColon = ipPort.LastIndexOf(":");
                    if (lastColon > 0) ip = ipPort.Substring(0, lastColon);
                }

                if (ip != null && ip.StartsWith("::ffff:")) ip = ip.Substring(7);
                return ip;
            }
            catch { return ipPort; }
        }

        private bool IsIpBlacklisted(string ipPort)
        {
            string ip = ExtractIpAddress(ipPort);
            return _ipBlacklist.Contains(ip);
        }

        private void EnforceSecurityPolicies()
        {
            var now = DateTime.Now;
            var clientsToRemove = new List<string>();

            foreach (var client in _connectedClients)
            {
                // Policy 1: Unauthenticated timeout (30s)
                if (!_authenticatedClients.ContainsKey(client.Key) || !_authenticatedClients[client.Key])
                {
                    if ((now - client.Value.ConnectedTime).TotalSeconds > 30)
                    {
                        clientsToRemove.Add(client.Key);
                        LogSystemMessage($"Security: Dropped unauthenticated client {client.Key}");
                    }
                }
                // Policy 2: Inactivity timeout (15m)
                else if ((now - client.Value.LastActivityTime).TotalMinutes > 15)
                {
                    clientsToRemove.Add(client.Key);
                    LogSystemMessage($"Security: Dropped inactive client {client.Key}");
                }
            }

            foreach (var ip in clientsToRemove) _server.DisconnectClient(ip);
        }

        #endregion

        #region Event Handlers

        private void OnClientConnected(object sender, ConnectionEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                if (IsIpBlacklisted(e.IpPort))
                {
                    _server.DisconnectClient(e.IpPort);
                    LogSystemMessage($"Security: Blocked blacklisted IP {e.IpPort}");
                    return;
                }

                _connectedClients[e.IpPort] = new ClientInfo
                {
                    IpPort = e.IpPort,
                    ConnectedTime = DateTime.Now,
                    LastActivityTime = DateTime.Now,
                    Status = "Connected",
                };

                lstClientIP.Items.Add(e.IpPort);
                UpdateServerStats();
            });
        }

        private void OnClientDisconnected(object sender, ConnectionEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                _connectedClients.Remove(e.IpPort);
                _authenticatedClients.Remove(e.IpPort);
                lstClientIP.Items.Remove(e.IpPort);

                LogSystemMessage($"Client disconnected: {e.IpPort}");
                UpdateServerStats();
            });
        }

        private void OnDataReceived(object sender, SuperSimpleTcp.DataReceivedEventArgs e)
        {
            Invoke((MethodInvoker)delegate
            {
                UpdateActivity(e.IpPort, e.Data.Count);
                ProcessIncomingPacket(e.IpPort, e.Data.Array, e.Data.Count);
            });
        }

        #endregion

        #region Packet Processing

        private void UpdateActivity(string ipPort, int bytes)
        {
            if (_connectedClients.ContainsKey(ipPort))
            {
                _connectedClients[ipPort].LastActivityTime = DateTime.Now;
                _connectedClients[ipPort].BytesReceived += bytes;
            }
        }

        private void ProcessIncomingPacket(string ipPort, byte[] data, int length)
        {
            try
            {
                string jsonString = Encoding.UTF8.GetString(data, 0, length).Trim();
                if (string.IsNullOrWhiteSpace(jsonString)) return;

                if (!IsValidJson(jsonString))
                {
                    LogSystemMessage($"Warning: Invalid payload from {ipPort}");
                    return;
                }

                dynamic packet = JsonConvert.DeserializeObject(jsonString);
                if (packet == null || packet.action == null) return;

                string action = packet.action.ToString();

                // Security Check: Authentication
                if (action != "AUTH" && action != "INIT")
                {
                    if (!_authenticatedClients.ContainsKey(ipPort) || !_authenticatedClients[ipPort])
                    {
                        LogSystemMessage($"Security: Unauthorized action '{action}' from {ipPort}");
                        _server.DisconnectClient(ipPort);
                        return;
                    }
                }

                HandleAction(ipPort, action, packet);
            }
            catch (Exception ex)
            {
                LogSystemMessage($"Packet Error ({ipPort}): {ex.Message}");
            }
        }

        private bool IsValidJson(string str)
        {
            return str.StartsWith("{") || str.StartsWith("[");
        }

        private void HandleAction(string ipPort, string action, dynamic packet)
        {
            string userId = packet.user_id?.ToString() ?? "UNKNOWN";

            switch (action)
            {
                case "HEARTBEAT":
                    // Activity already updated
                    break;

                case "INIT":
                    string hwid = packet.hwid?.ToString() ?? "UNKNOWN";
                    LogSystemMessage($"INIT | HWID: {hwid} | IP: {ipPort} | USER: {userId}");
                    break;

                case "STREAMVIEWER":
                case "THREAT":
                case "REPORT_DLL":
                case "INJECTION_ALERT":
                    string msg = packet.message?.ToString() ?? "NO_MESSAGE";
                    LogReport($"{action} | MSG: {msg} | IP: {ipPort} | USER: {userId}");
                    break;

                case "CHEAT_REPORT":
                    string process = packet.process?.ToString() ?? "UNKNOWN";
                    LogReport($"{action} | PROCESS: {process} | IP: {ipPort} | USER: {userId}");
                    break;

                default:
                    LogSystemMessage($"Unknown Action: {action} from {ipPort}");
                    break;
            }
        }

        #endregion

        #region UI Helpers & Logging

        private void LogSystemMessage(string message)
        {
            string log = $"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}";
            inputInfo.AppendText(log);
            ScrollToBottom(inputInfo);
        }

        private void LogReport(string message)
        {
            string log = $"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}";
            textBox_playes_report.AppendText(log);
            ScrollToBottom(textBox_playes_report);
        }

        private void ScrollToBottom(TextBox textBox)
        {
            textBox.SelectionStart = textBox.TextLength;
            textBox.SelectionLength = 0;
            textBox.ScrollToCaret();
        }

        private void UpdateServerStats()
        {
            int authCount = _authenticatedClients.Count(c => c.Value);
            long rx = _server.Statistics.ReceivedBytes;
            long tx = _server.Statistics.SentBytes;
            toolStripStatusLabel2.Text = $"Auth Clients: {authCount} | RX: {FormatBytes(rx)} | TX: {FormatBytes(tx)}";
            toolStripStatusLabel1.Text = $"Connected: {_connectedClients.Count}";
        }

        private void UpdateClientStats()
        {
            foreach (var client in _connectedClients.Values)
            {
                TimeSpan duration = DateTime.Now - client.ConnectedTime;
                client.Status = $"Connected ({duration:hh\\:mm\\:ss})";
            }
        }

        private string FormatBytes(long bytes)
        {
            string[] suffix = { "B", "KB", "MB", "GB" };
            int i = 0;
            double dblBytes = bytes;
            while (dblBytes >= 1024 && i < suffix.Length - 1)
            {
                dblBytes /= 1024;
                i++;
            }
            return $"{dblBytes:0.##} {suffix[i]}";
        }

        #endregion

        #region User Interaction

        private void btnStart_Click(object sender, EventArgs e)
        {
            try
            {
                _server.Start();
                inputServerIp.Text = $"{_serverIp}:{_serverPort}";
                LogSystemMessage($"Server Service Started on {_serverIp}:{_serverPort} (Dual-Stack)");
                btnStart.Enabled = false;
                btnSend.Enabled = true;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Start Failed: {ex.Message}");
            }
        }

        private void btnSend_Click(object sender, EventArgs e)
        {
            if (!_server.IsListening) return;
            if (inputSelect.SelectedIndex == 0 || lstClientIP.SelectedItem == null)
            {
                MessageBox.Show("Select a target and action.");
                return;
            }

            string targetIp = lstClientIP.SelectedItem.ToString();
            ExecuteCommand(targetIp, inputSelect.SelectedIndex);
        }

        private void ExecuteCommand(string targetIp, int commandIndex)
        {
            string payload = "";
            string cmdName = "";

            switch (commandIndex)
            {
                case 1: // Shutdown
                    payload = JsonConvert.SerializeObject(new { action = "shutdown" });
                    cmdName = "SHUTDOWN";
                    break;
                case 2: // Disconnect
                    _server.DisconnectClient(targetIp);
                    LogSystemMessage($"Command: Disconnected {targetIp}");
                    return;
                case 3: // Stream Viewer
                    payload = JsonConvert.SerializeObject(new
                    {
                        action = "streamviewer",
                        ip = _streamHost,
                        port = _streamPort,
                        executable = "StreamClient.exe"
                    });
                    cmdName = "STREAM_VIEWER";
                    break;
            }

            if (!string.IsNullOrEmpty(payload))
            {
                SendPayload(targetIp, payload, cmdName);
            }
        }

        private void SendPayload(string ip, string data, string description)
        {
            try
            {
                _server.Send(ip, data);
                if (_connectedClients.ContainsKey(ip))
                {
                    _connectedClients[ip].LastActivityTime = DateTime.Now;
                    _connectedClients[ip].BytesSent += Encoding.UTF8.GetBytes(data).Length;
                }
                LogSystemMessage($"Command Sent: {description} -> {ip}");
            }
            catch (Exception ex)
            {
                LogSystemMessage($"Send Error: {ex.Message}");
            }
        }

        private void searchBox_TextChanged(object sender, EventArgs e)
        {
            string filter = searchBox.Text.ToLower();
            var matches = _connectedClients.Keys
                .Where(k => k.ToLower().Contains(filter))
                .ToArray();

            lstClientIP.Items.Clear();
            lstClientIP.Items.AddRange(matches);
        }

        #endregion
    }
}