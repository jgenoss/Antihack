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

        // Servidores duales - IPv4 e IPv6 simultaneamente
        private SimpleTcpServer _serverIPv4;
        private SimpleTcpServer _serverIPv6;
        private string _serverIpv4;
        private string _serverIpv6;
        private int _serverPort;
        private string _serverKey;

        // Stream Viewer Config
        private string _streamHostIPv4;
        private string _streamHostIPv6;
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
            // Mostrar ambas direcciones configuradas
            string displayText = "";
            if (!string.IsNullOrWhiteSpace(_serverIpv4))
                displayText += $"IPv4: {_serverIpv4}:{_serverPort}";
            if (!string.IsNullOrWhiteSpace(_serverIpv6))
            {
                if (!string.IsNullOrEmpty(displayText)) displayText += " | ";
                displayText += $"IPv6: [{_serverIpv6}]:{_serverPort}";
            }
            inputServerIp.Text = displayText;
            inputSelect.SelectedIndex = 0;
            btnSend.Enabled = false;
        }

        private void LoadConfiguration()
        {
            try
            {
                INIFile ini = new INIFile(Path.Combine(_basePath, "Config.ini"));

                // Network Configuration - Ambas direcciones para listeners duales
                _serverIpv4 = ini.IniReadValue("CONFIG", "IPV4");
                _serverIpv6 = ini.IniReadValue("CONFIG", "IPV6");

                // Compatibilidad con config legacy (IP unica)
                if (string.IsNullOrWhiteSpace(_serverIpv4) && string.IsNullOrWhiteSpace(_serverIpv6))
                {
                    string legacyIp = ini.IniReadValue("CONFIG", "IP");
                    if (!string.IsNullOrWhiteSpace(legacyIp))
                    {
                        if (legacyIp.Contains(":"))
                            _serverIpv6 = legacyIp;
                        else
                            _serverIpv4 = legacyIp;
                    }
                }

                _serverPort = int.Parse(ini.IniReadValue("CONFIG", "PORT"));
                _serverKey = ini.IniReadValue("CONFIG", "KEY");

                // Stream Configuration - Ambas direcciones
                _streamHostIPv4 = ini.IniReadValue("server", "ipv4_host");
                _streamHostIPv6 = ini.IniReadValue("server", "ipv6_host");

                // Compatibilidad con config legacy
                if (string.IsNullOrWhiteSpace(_streamHostIPv4) && string.IsNullOrWhiteSpace(_streamHostIPv6))
                {
                    string legacyHost = ini.IniReadValue("server", "host");
                    if (!string.IsNullOrWhiteSpace(legacyHost))
                    {
                        if (legacyHost.Contains(":") && legacyHost != "0.0.0.0")
                            _streamHostIPv6 = legacyHost;
                        else
                            _streamHostIPv4 = legacyHost;
                    }
                }

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
                // Inicializar servidor IPv4 si esta configurado
                if (!string.IsNullOrWhiteSpace(_serverIpv4))
                {
                    try
                    {
                        _serverIPv4 = new SimpleTcpServer(_serverIpv4, _serverPort);
                        ConfigureServer(_serverIPv4);
                        LogSystemMessage($"IPv4 listener preparado: {_serverIpv4}:{_serverPort}");
                    }
                    catch (Exception ex)
                    {
                        LogSystemMessage($"IPv4 init error: {ex.Message}");
                        _serverIPv4 = null;
                    }
                }

                // Inicializar servidor IPv6 si esta configurado
                if (!string.IsNullOrWhiteSpace(_serverIpv6))
                {
                    try
                    {
                        string ipv6Addr = _serverIpv6.Trim('[', ']');
                        _serverIPv6 = new SimpleTcpServer(ipv6Addr, _serverPort);
                        ConfigureServer(_serverIPv6);
                        LogSystemMessage($"IPv6 listener preparado: [{ipv6Addr}]:{_serverPort}");
                    }
                    catch (Exception ex)
                    {
                        LogSystemMessage($"IPv6 init error: {ex.Message}");
                        _serverIPv6 = null;
                    }
                }

                if (_serverIPv4 == null && _serverIPv6 == null)
                {
                    LogSystemMessage("ERROR: No se pudo inicializar ningun servidor");
                }

                // Maintenance Timers
                InitializeTimers();
            }
            catch (Exception ex)
            {
                LogSystemMessage($"Initialization Failed: {ex.Message}");
            }
        }

        private void ConfigureServer(SimpleTcpServer server)
        {
            // High Performance Settings
            server.Settings.MaxConnections = 2000;
            server.Settings.NoDelay = true;
            server.Keepalive = new SimpleTcpKeepaliveSettings
            {
                EnableTcpKeepAlives = true,
                TcpKeepAliveInterval = 5,
                TcpKeepAliveTime = 5,
                TcpKeepAliveRetryCount = 5,
            };

            // Event Binding
            server.Events.ClientConnected += OnClientConnected;
            server.Events.ClientDisconnected += OnClientDisconnected;
            server.Events.DataReceived += OnDataReceived;
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
            // Caso: vacio o null - usar dual-stack
            if (string.IsNullOrWhiteSpace(configuredIp)) return "::";

            // Caso: direccion IPv4 any (0.0.0.0) - convertir a dual-stack
            if (configuredIp == "0.0.0.0") return "::";

            // Caso: direccion IPv6 any (::) - ya es dual-stack
            if (configuredIp == "::") return "::";

            // Intentar parsear la direccion
            if (IPAddress.TryParse(configuredIp.Trim('[', ']'), out IPAddress ipAddr))
            {
                // Si es IPv6, usarla directamente
                if (ipAddr.AddressFamily == AddressFamily.InterNetworkV6)
                    return ipAddr.ToString();

                // Si es IPv4 Any, usar dual-stack
                if (ipAddr.Equals(IPAddress.Any))
                    return "::";

                // Si es IPv4 especifica, usarla (no dual-stack)
                if (ipAddr.AddressFamily == AddressFamily.InterNetwork)
                    return ipAddr.ToString();
            }

            // Si no se puede parsear, intentar resolver como hostname
            try
            {
                IPAddress[] addresses = Dns.GetHostAddresses(configuredIp);
                // Preferir IPv6 si esta disponible
                foreach (var addr in addresses)
                {
                    if (addr.AddressFamily == AddressFamily.InterNetworkV6)
                        return addr.ToString();
                }
                // Fallback a IPv4
                foreach (var addr in addresses)
                {
                    if (addr.AddressFamily == AddressFamily.InterNetwork)
                        return addr.ToString();
                }
            }
            catch (Exception ex)
            {
                LogSystemMessage($"Error resolviendo hostname '{configuredIp}': {ex.Message}");
            }

            return configuredIp;
        }

        private string ExtractIpAddress(string ipPort)
        {
            if (string.IsNullOrEmpty(ipPort)) return string.Empty;

            try
            {
                string ip = ipPort;

                // Caso IPv6 con brackets: [::1]:8080 o [::ffff:192.168.1.1]:8080
                if (ipPort.StartsWith("["))
                {
                    int endBracket = ipPort.IndexOf("]");
                    if (endBracket > 0)
                        ip = ipPort.Substring(1, endBracket - 1);
                }
                // Caso IPv4: 192.168.1.1:8080
                else if (ipPort.Contains(":"))
                {
                    // Contar los dos puntos para distinguir IPv4:port de IPv6
                    int colonCount = ipPort.Count(c => c == ':');
                    if (colonCount == 1)
                    {
                        // Es IPv4:port
                        int lastColon = ipPort.LastIndexOf(":");
                        if (lastColon > 0)
                            ip = ipPort.Substring(0, lastColon);
                    }
                    // Si tiene mas de un ":", es IPv6 sin brackets (no deberia pasar pero por seguridad)
                }

                // Convertir IPv4-mapped IPv6 a IPv4 pura
                // ::ffff:192.168.1.1 -> 192.168.1.1
                if (!string.IsNullOrEmpty(ip) && ip.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase))
                    ip = ip.Substring(7);

                return ip ?? ipPort;
            }
            catch
            {
                return ipPort;
            }
        }

        private string GetClientDisplayAddress(string ipPort)
        {
            string ip = ExtractIpAddress(ipPort);

            // Si es localhost IPv6, mostrar como localhost
            if (ip == "::1") return "localhost (IPv6)";
            if (ip == "127.0.0.1") return "localhost (IPv4)";

            // Indicar si la conexion vino via IPv4-mapped
            if (ipPort.Contains("::ffff:"))
                return $"{ip} (IPv4 via IPv6)";

            // Verificar si es direccion IPv6
            if (IPAddress.TryParse(ip, out IPAddress addr))
            {
                if (addr.AddressFamily == AddressFamily.InterNetworkV6)
                    return $"{ip} (IPv6)";
            }

            return ip;
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

            foreach (var ip in clientsToRemove) DisconnectClientFromServer(ip);
        }

        #endregion

        #region Event Handlers

        private void OnClientConnected(object sender, ConnectionEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                if (IsIpBlacklisted(e.IpPort))
                {
                    DisconnectClientFromServer(e.IpPort);
                    LogSystemMessage($"Security: Blocked blacklisted IP {e.IpPort}");
                    return;
                }

                string displayAddr = GetClientDisplayAddress(e.IpPort);

                _connectedClients[e.IpPort] = new ClientInfo
                {
                    IpPort = e.IpPort,
                    ConnectedTime = DateTime.Now,
                    LastActivityTime = DateTime.Now,
                    Status = "Connected",
                };

                lstClientIP.Items.Add(e.IpPort);
                LogSystemMessage($"Client connected: {displayAddr}");
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
                        DisconnectClientFromServer(ipPort);
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

            // Sumar estadisticas de ambos servidores
            long rx = 0, tx = 0;
            if (_serverIPv4 != null)
            {
                rx += _serverIPv4.Statistics.ReceivedBytes;
                tx += _serverIPv4.Statistics.SentBytes;
            }
            if (_serverIPv6 != null)
            {
                rx += _serverIPv6.Statistics.ReceivedBytes;
                tx += _serverIPv6.Statistics.SentBytes;
            }

            toolStripStatusLabel2.Text = $"Auth: {authCount} | RX: {FormatBytes(rx)} | TX: {FormatBytes(tx)}";
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
            bool startedAny = false;
            List<string> activeProtocols = new List<string>();

            // Iniciar servidor IPv4
            if (_serverIPv4 != null)
            {
                try
                {
                    _serverIPv4.Start();
                    LogSystemMessage($"IPv4 listener activo: {_serverIpv4}:{_serverPort}");
                    activeProtocols.Add("IPv4");
                    startedAny = true;
                }
                catch (Exception ex)
                {
                    LogSystemMessage($"IPv4 start failed: {GetFriendlyError(ex)}");
                }
            }

            // Iniciar servidor IPv6
            if (_serverIPv6 != null)
            {
                try
                {
                    _serverIPv6.Start();
                    LogSystemMessage($"IPv6 listener activo: [{_serverIpv6}]:{_serverPort}");
                    activeProtocols.Add("IPv6");
                    startedAny = true;
                }
                catch (Exception ex)
                {
                    LogSystemMessage($"IPv6 start failed: {GetFriendlyError(ex)}");
                }
            }

            if (startedAny)
            {
                LogSystemMessage($"Servidor activo - Protocolos: {string.Join(" + ", activeProtocols)}");

                // Mostrar direcciones locales disponibles
                ShowLocalAddresses();

                btnStart.Enabled = false;
                btnSend.Enabled = true;
            }
            else
            {
                MessageBox.Show("No se pudo iniciar ningun servidor.\nVerifique la configuracion de red.",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private string GetFriendlyError(Exception ex)
        {
            string msg = ex.Message;
            if (msg.Contains("Address already in use") || msg.Contains("Only one usage"))
                return $"Puerto {_serverPort} ya esta en uso";
            if (msg.Contains("Access denied") || msg.Contains("Permission"))
                return $"Sin permisos para puerto {_serverPort}";
            return msg;
        }

        private void ShowLocalAddresses()
        {
            try
            {
                string hostName = Dns.GetHostName();
                IPAddress[] addresses = Dns.GetHostAddresses(hostName);

                foreach (var addr in addresses)
                {
                    if (addr.AddressFamily == AddressFamily.InterNetwork && _serverIPv4 != null)
                        LogSystemMessage($"  Disponible IPv4: {addr}:{_serverPort}");
                    else if (addr.AddressFamily == AddressFamily.InterNetworkV6 && !addr.IsIPv6LinkLocal && _serverIPv6 != null)
                        LogSystemMessage($"  Disponible IPv6: [{addr}]:{_serverPort}");
                }
            }
            catch { /* No es critico */ }
        }

        private void btnSend_Click(object sender, EventArgs e)
        {
            if (!IsServerListening()) return;
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
                    DisconnectClientFromServer(targetIp);
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
                bool sent = false;

                // Intentar enviar por IPv4
                if (_serverIPv4 != null && _serverIPv4.IsListening)
                {
                    try
                    {
                        _serverIPv4.Send(ip, data);
                        sent = true;
                    }
                    catch { }
                }

                // Si no se envio por IPv4, intentar IPv6
                if (!sent && _serverIPv6 != null && _serverIPv6.IsListening)
                {
                    try
                    {
                        _serverIPv6.Send(ip, data);
                        sent = true;
                    }
                    catch { }
                }

                if (sent)
                {
                    if (_connectedClients.ContainsKey(ip))
                    {
                        _connectedClients[ip].LastActivityTime = DateTime.Now;
                        _connectedClients[ip].BytesSent += Encoding.UTF8.GetBytes(data).Length;
                    }
                    LogSystemMessage($"Command Sent: {description} -> {ip}");
                }
                else
                {
                    LogSystemMessage($"Send Failed: Client {ip} not found on any server");
                }
            }
            catch (Exception ex)
            {
                LogSystemMessage($"Send Error: {ex.Message}");
            }
        }

        private bool IsServerListening()
        {
            return (_serverIPv4 != null && _serverIPv4.IsListening) ||
                   (_serverIPv6 != null && _serverIPv6.IsListening);
        }

        private void DisconnectClientFromServer(string ipPort)
        {
            try
            {
                if (_serverIPv4 != null) _serverIPv4.DisconnectClient(ipPort);
            }
            catch { }

            try
            {
                if (_serverIPv6 != null) _serverIPv6.DisconnectClient(ipPort);
            }
            catch { }
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