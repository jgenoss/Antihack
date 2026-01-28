using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using AntiCheat.Properties;
using HardwareIds.NET.Structures;
using Microsoft.Win32;
using Newtonsoft.Json;
using SuperSimpleTcp;

namespace AntiCheat
{
    public partial class AntiCheatForm : Form
    {
        #region Fields & Constants

        private const int LOADING_BAR_MAX_WIDTH = 492;
        private readonly string _basePath = Directory.GetCurrentDirectory();
        private readonly string _logFilePath = Path.Combine(Directory.GetCurrentDirectory(), "antihack.log");

        private readonly encrypt_decrypt _crypto = new encrypt_decrypt();
        private readonly ProcessStartInfo _gameStartInfo = new ProcessStartInfo();
        private readonly List<string> _blacklistedProcesses;

        private SimpleTcpClient _client;
        private string _serverIp;
        private int _serverPort;
        private string _serverKey;
        private string _gameExecutable;

        private string[] _launchArguments;
        private int _loadingProgress = 0;
        private Timer _heartbeatTimer;

        // IPC
        private bool _isPipeServerRunning = false;
        private List<string> _pendingMessages = new List<string>();

        #endregion

        #region Initialization

        public AntiCheatForm(string[] args)
        {
            if (args.Length < 2 || args.Length <= 0)
            {
                this.Close();
                MessageBox.Show("Invalid arguments. Please provide the correct parameters.");
                Application.Exit();
            }
            else
            {
                _launchArguments = args;
                InitializeComponent();
                _blacklistedProcesses = InitializeBlacklistedProcesses();
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            try
            {
                InitializeApplication();
            }
            catch (Exception ex)
            {
                LogError("Error during initialization", ex);
                ShowAndExit($"Error during startup. Please check your installation. {ex}", "alert", 10000);
            }
        }

        private async void InitializeApplication()
        {
            if (!VerifyDependencies()) return;
            
            LoadConfiguration();
            StartNamedPipeServer();
            InitializeClient();
            InitializeTimers();
            
            this.ShowInTaskbar = false;
            LoadingBar.Width = 0;
            
            await ConnectToServerAsync();
        }

        private void InitializeTimers()
        {
            // _loadingTimer y _securityTimer ya están inicializados por InitializeComponent (Designer)
            // Solo configuramos el heartbeat adicional
            _heartbeatTimer = new Timer();
            _heartbeatTimer.Tick += OnHeartbeatTimerTick;
            _heartbeatTimer.Interval = 120000; // 2 minutos
        }

        private bool VerifyDependencies()
        {
            string[] requiredFiles = new[] { "ext11c.dll", "Newtonsoft.Json.dll", "SuperSimpleTcp.dll" };
            foreach (string file in requiredFiles)
            {
                if (!File.Exists(Path.Combine(_basePath, file)))
                {
                    ShowAndExit($"Failed to load '{file}'", "alert", 10000);
                    return false;
                }
            }
            return true;
        }

        private void LoadConfiguration()
        {
            try
            {
                string configPath = Path.Combine(_basePath, "ext11c.dll");
                if (!File.Exists(configPath))
                {
                    string errorMsg = $"Archivo de configuración 'ext11c.dll' no encontrado en: {configPath}";
                    LogError(errorMsg, new Exception("Archivo no encontrado"));
                    ShowAndExit(errorMsg, "Error de Configuración", 10000);
                    return;
                }

                INIFile tx = new INIFile(configPath);

                _gameExecutable = tx.IniReadValue("CONFIG", "GAME");
                if (string.IsNullOrEmpty(_gameExecutable))
                {
                    LogError("Valor 'GAME' no encontrado o vacío", new Exception("Configuración faltante"));
                }

                // Configuración de IP
                string ipv4 = tx.IniReadValue("CONFIG", "IPV4");
                string ipv6 = tx.IniReadValue("CONFIG", "IPV6");

                if (!string.IsNullOrWhiteSpace(ipv6)) _serverIp = ipv6;
                else if (!string.IsNullOrWhiteSpace(ipv4)) _serverIp = ipv4;
                else _serverIp = tx.IniReadValue("CONFIG", "IP");

                if (string.IsNullOrEmpty(_serverIp))
                {
                    LogError("No se encontró una configuración de IP válida", new Exception("Configuración faltante"));
                }

                string portStr = tx.IniReadValue("CONFIG", "PORT");
                if (string.IsNullOrEmpty(portStr) || !int.TryParse(portStr, out _serverPort))
                {
                    LogError("Valor 'PORT' inválido", new Exception("Configuración inválida"));
                }

                _serverKey = tx.IniReadValue("CONFIG", "KEY");
                if (string.IsNullOrEmpty(_serverKey))
                {
                    LogError("Valor 'KEY' no encontrado", new Exception("Configuración faltante"));
                }
            }
            catch (Exception ex)
            {
                LogError($"Error loading configuration", ex);
                ShowAndExit($"Error loading configuration: {ex.Message}", "Error de Configuración", 10000);
            }
        }

        #endregion

        #region Hardware ID Logic

        private string getHwid()
        {
            try
            {
                // Intentar obtener HWID con la biblioteca HardwareIds.NET
                var ids = HardwareIds.NET.HardwareIds.GetHwid();

                if (ids != null && ids.Motherboard != null && ids.Motherboard.UUID != null)
                {
                    string hwid = ids.Motherboard.UUID.ToString().ToUpper();
                    LogClientStatus($"HWID obtenido correctamente: {hwid}");
                    return hwid;
                }

                // Si no podemos obtener el HWID usando la biblioteca, crear uno alternativo
                LogClientStatus("No se pudo obtener UUID de la placa base, usando ID alternativo");
                return GenerateAlternativeHWID();
            }
            catch (Exception ex)
            {
                LogError("Error obteniendo HWID", ex);
                return GenerateAlternativeHWID();
            }
        }

        // Método alternativo para generar un ID único para este equipo
        private string GenerateAlternativeHWID()
        {
            try
            {
                // Opción 1: Usar el ID de volumen del disco C
                string volumeId = GetVolumeId();
                if (!string.IsNullOrEmpty(volumeId))
                {
                    LogClientStatus($"Usando ID de volumen como HWID alternativo: {volumeId}");
                    return volumeId;
                }

                // Opción 2: Usar dirección MAC como alternativa
                string macAddress = GetMacAddress();
                if (!string.IsNullOrEmpty(macAddress))
                {
                    LogClientStatus($"Usando dirección MAC como HWID alternativo: {macAddress}");
                    return macAddress;
                }

                // Opción 3: Usar nombre de máquina + fecha de instalación de Windows
                string computerName = Environment.MachineName;
                string installDate = GetWindowsInstallDate();
                string combined = $"{computerName}-{installDate}";

                LogClientStatus($"Usando ID compuesto como HWID alternativo: {combined}");
                return combined;
            }
            catch (Exception ex)
            {
                LogError("Error generando HWID alternativo", ex);

                // Como último recurso, generar un ID aleatorio
                string randomId = Guid.NewGuid().ToString().ToUpper();
                LogClientStatus($"Usando ID aleatorio como HWID alternativo: {randomId}");
                return randomId;
            }
        }

        // Obtener ID de volumen del disco C
        private string GetVolumeId()
        {
            try
            {
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "cmd.exe";
                    process.StartInfo.Arguments = "/c vol C:";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;

                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    // Buscar el número de serie del volumen
                    int index = output.IndexOf("es") + 2;
                    if (index > 2 && index < output.Length)
                    {
                        string volumeId = output.Substring(index).Trim();
                        return volumeId.Replace("-", "");
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("Error obteniendo ID de volumen", ex);
            }

            return string.Empty;
        }

        // Obtener dirección MAC
        private string GetMacAddress()
        {
            try
            {
                NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
                foreach (NetworkInterface adapter in nics)
                {
                    // Solo usar adaptadores físicos activos
                    if (
                        adapter.OperationalStatus == OperationalStatus.Up
                        && (
                            adapter.NetworkInterfaceType == NetworkInterfaceType.Ethernet
                            || adapter.NetworkInterfaceType == NetworkInterfaceType.Wireless80211
                        )
                    )
                    {
                        PhysicalAddress address = adapter.GetPhysicalAddress();
                        if (address != null)
                        {
                            byte[] bytes = address.GetAddressBytes();
                            if (bytes != null && bytes.Length > 0)
                            {
                                return BitConverter.ToString(bytes).Replace("-", "");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("Error obteniendo dirección MAC", ex);
            }

            return string.Empty;
        }

        // Obtener fecha de instalación de Windows
        private string GetWindowsInstallDate()
        {
            try
            {
                using (
                    RegistryKey key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                    )
                )
                {
                    if (key != null)
                    {
                        object value = key.GetValue("InstallDate");
                        if (value != null)
                        {
                            return value.ToString();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("Error obteniendo fecha de instalación de Windows", ex);
            }

            return DateTime.Now.Ticks.ToString();
        }

        #endregion

        #region Security & Detection

        private void StopTimers()
        {
            if (_loadingTimer != null) _loadingTimer.Stop();
            if (_securityTimer != null) _securityTimer.Stop();
            if (_heartbeatTimer != null) _heartbeatTimer.Stop();
        }

        public static void ExisteClaveRegistro()
        {
            // Abre la clave sin crearla
            using (RegistryKey clave = Registry.CurrentUser.OpenSubKey("Software", true))
            {
                if (clave != null)
                {
                    try
                    {
                        clave.DeleteSubKeyTree("LatinoFPS");
                    }
                    catch (System.Exception) { }
                }
            }
        }

        private List<string> InitializeBlacklistedProcesses()
        {
            return new List<string>
            {
                "RazerAppEngine",
                "MACRO COSZ 2024",
                "Tempfilenam",
                "Razer Synapse",
                "RzSynapse",
                "lghub",
                "logitechg_discord",
                "LCore",
                "SteelSeriesEngine3",
                "SteelSeriesGG",
                "XMouseButtonControl",
                "MacroRecorder",
                "AutoHotkey",
                "Redragon",
                "RedragonGamingMouse",
                "GloriousCore",
                "Roccat_Swarm",
                "rzmntr",
                "RazerCortex",
                "ggtray",
                "Bloody6",
                "Bloody",
                "Bloody5",
                "M711Software",
                "RoccatMonitor",
                "AutoHotkeyU64",
                "AutoHotkeyU32",
                "MacroCreator",
                "Keyran",
                "reWASD",
                "reWASDTray",
                "reWASDAgent",
                "tgm",
                "tgm_macro",
                "LightKeeper",
                "cmportal",
                "cm_sw",
                "HyperX NGENUITY",
                "HyperXNgenuity",
                "ZowieMouse",
                "BenQZowie",
                "XPGPrime",
                "HavitGamingMouse",
                "uRageGamingSoftware",
                "SpeedlinkMouseEditor",
                "MARVO_M618",
                "FantechMouseSoftware",
                "DeluxMouseSetting",
                "CougarUIxSystem",
                "CougarFusion",
                "T-DaggerMacroSoftware",
                "T-DaggerMouse",
                "AulaMouseMacro",
                "AulaSoftware",
                "OnikumaMouse",
                "OnikumaControl",
                "NubwoMacroEditor",
                "DragonwarGamingMouse",
                "ZeusMouseMacro",
                "ZeusEditor",
                "MachinatorMouseTool",
                "MeetionMouseSoftware",
                "AutoIt3",
                "ClickMachine",
                "MouseClicker",
                "MouseMacro",
                "SpeedMouse",
                "FastClicker",
                "RapidClick",
                "BotMice",
                "ClickBot",
                "GhostMouse",
                "MouseRecorderPro",
                "GS_AutoClicker",
                "FreeMacroPlayer",
                "MacroExpress",
                "PerfectMacro",
                "ClickerPlus",
                "EasyMacroTool",
                "QuickMacro",
                "InputAutomationTool",
                "ClickAssistant",
                "AutoClickTyper",
                "M808",
                "M908",
                "M990",
                "Attack_SharkX3Mouse",
                "wg",
                "Surfshark",
                "Surfshark.Service",
                "Surfshark.UpdateService",
                //Administradores de Procesos y Análisis del Sistema
                "ProcessHacker",
                "procexp",
                //"Taskmgr",
                "perfmon",
                "procexp64",
                "procexp32",
                "anvir",
                "securitytaskmanager",
                "systemexplorer",
                "prio",
                "winspy",
                "daphne",
                "taskcoach",
                "taskmanagerdeluxe",
                "taskmgrpro",
                "processlasso",
                "procmon",
                "procmon64",
                "procmon32",
                "whatishang",
                "whoslock",
                "openhandles",
                "handle",
                "handles",
                "sysinternals",
                "taskmanagerspynet",
                "taskexplorer",
                "autoruns",
                "autorunsc",
                "taskmanagerplus",
                "tasksmanager",
                //Depuradores y Desensambladores
                "ollydbg",
                "ollydbg64",
                "x64dbg",
                "x32dbg",
                "windbg",
                "gdb",
                "idag",
                "idag64",
                "idaq",
                "idaq64",
                "ida",
                "ida64",
                "radare2",
                "dnspy",
                "cheatengine",
                "cheatengine-x86_64",
                "reclass",
                "reclass64",
                "de4dot",
                // Inyectores de DLL y Herramientas de Modificación de Memoria
                "extremeinjector",
                "processinjector",
                "xenos64",
                "xenos",
                "dllinjector",
                "injector",
                "threadhijacker",
                "hijackthis",
                "blackbone",
                "winject",
                "remoteinjector",
                "apcinject",
                "kprocesshacker",
                "phlib",
                "freeinjector",
                //Editores de Código y Herramientas de Ingeniería Inversa
                "notepad++",
                "hexeditor",
                "winhex",
                "hxd",
                "010editor",
                "immunitydebugger",
                "peid",
                "peexplorer",
                "c32asm",
                "ollyice",
                //Escáneres y Herramientas de Análisis de Malware
                "tcpview",
                "wireshark",
                "snifferspy",
                "networkspy",
                "networkminer",
                "netscan",
                "smartsniff",
                "smartwhois",
                //Emuladores y Sandboxes
                "sandboxiedcomlaunch",
                "sandboxierpcss",
                //"vmware",
                //"vmtoolsd",
                //"vmwaretray",
                //"vmwareuser",
                "vboxservice",
                "vboxtray",
                "qemu-system",
                "wine",
                "fiddler",
                "mitmproxy",
                "burpsuite",
                "proxycap",
                "proxifier",
                "proxytunnel",
                "charlesproxy",
                "tor",
                "torbrowser",
                "vidalia",
                "privoxy",
                "squid",
                "hydra",
                "medusa",
                "ncrack",
                "john",
                "hashcat",
                "crunch",
                "aircrack-ng",
                "reaver",
                "wifite",
                "sqlmap",
                "sqlninja",
                "metasploit",
                "msfconsole",
                "msfvenom",
                "beef",
                "ares",
                "cobaltstrike",
                "bruteforce",
                "hashkiller",
                "unpacker",
                "de4dot",
                "upx",
                "armadillo",
                "vmprotect",
                "themida",
                "xnosnoop",
                "dumper",
                "hxdump",
                "cracker",
                "keygen",
                "patcher",
                "regmon",
                "sniffpass",
                "productkey",
                "serialbox",
                "winspy",
                "perfectkeylogger",
                "actualspy",
                "refog",
                "bestkeylogger",
                "spytech",
                "spystorm",
                "realtime-spy",
                "shadowkeylogger",
                "monitoringsoftware",
                "wiredkeys",
                "stalker",
                "sniper-spy",
                "systeminfo",
                "processmonitor",
                "taskanalysis",
                "taskmanagerplus64",
                "advancedtaskmanager",
                "securityexplorer",
                "sysanalyzer",
                "processxray",
                "taskinspector",
                "taskkiller",
                "winprocessmanager",
                "procview",
                "prcsview",
                "taskfreezer",
                "hiddenprocess",
                "processrevealer",
                "prockill",
                "taskguard",
                "taskviewer",
                "sysinspector",
                "kerneltrace",
                "winspyplus",
                "debugger64",
                "debugger32",
                "debugme",
                "trapflag",
                "breakpointchecker",
                "stacktrace",
                "opcodeviewer",
                "dissasemblerpro",
                "codeinspector",
                "opcodeanalyzer",
                "fastdebugger",
                "ptrace",
                "decompiler",
                "asmdebug",
                "codehunter",
                "memanalyst",
                "softice",
                "comtrace",
                "reveng",
                "hwbpmonitor",
                "bytecodeviewer",
                "injectplus",
                "dllhijacker",
                "memhijacker",
                "dllsnoop",
                "libinjector",
                "hijackdll",
                "remotecode",
                "processsyringe",
                "dynamicinjector",
                "apcspy",
                "hookdetect",
                "detours",
                "codepatcher",
                "memmod",
                "cheatdev",
                "memhackpro",
                "stealthinjector",
                "dllmodder",
                "patchinj",
                "dumperx",
                "binaryeditor",
                "hexworkshop",
                "biteshift",
                "bytepatcher",
                "memview",
                "memscan",
                "binanalyzer",
                "memscraper",
                "patternscanner",
                "memorypro",
                "hexdec",
                "ramreader",
                "fastedit",
                "tracehex",
                "xorviewer",
                "bitmaskedit",
                "fuzzeditor",
                "ramtracer",
                "payloadeditor",
                "procscanner",
                "netanalyzer",
                "packetspy",
                "sniffingtool",
                "tcpdump",
                "netpeek",
                "spyproxy",
                "packetrace",
                "rawsockets",
                "netwatch",
                "netmonitorplus",
                "iptracer",
                "dnslookup",
                "netrecon",
                "packetstorm",
                "networkwatchdog",
                "packetsnifferpro",
                "lanmonitor",
                "wifisniffer",
                "firewallbypass",
                "pktcapture",
                "bochs",
                "xenctrl",
                "guesttools",
                "parallelsvm",
                "dockerdaemon",
                "wineserver",
                "winecfg",
                "sandboxutility",
                "emuhost",
                "testcontainer",
                "qemuwrapper",
                "cloudhost",
                "vmsecurity",
                "hypervclient",
                "virtmon",
                "vboxguest",
                "bluepill",
                "hvmloader",
                "kvmservice",
                "shadowvm",
                "stealthproxy",
                "dnsbypass",
                "proxyhunter",
                "torproxy",
                "hiddenweb",
                "relaystation",
                "tunnelblick",
                "sockscap",
                "proxytool",
                "privatesocks",
                "browserspoofer",
                "mitmsuite",
                "networkstealth",
                "webcamblocker",
                "hostmanip",
                "ipspoof",
                "hashdecrypt",
                "exploitscanner",
                "hackingtool",
                "reverseproxy",
                "webscanner",
                "bruteforceattack",
                "pwnsuite",
                "securitybypass",
                "sqlscanner",
                "cfrtools",
                "shellgen",
                "wafbypass",
                "exploitbuilder",
                "vulnscanner",
                "pwnhub",
                "sqlihunter",
                "portstealer",
                "sessionstealer",
                "authbypass",
                "securityhacker",
                "keyfinder",
                "licensebypass",
                "serialhunter",
                "unlocker",
                "registryunlock",
                "keymaker",
                "trialreset",
                "cracked",
                "patcherpro",
                "serialseeker",
                "activationtool",
                "hwidspoof",
                "fakekeygen",
                "bypasslicense",
                "passwordstealer",
                "productkeyfinder",
                "licensekeygen",
                "serialbruteforce",
                "activator",
                "licensepatch",
                "ratserver",
                "backdoor",
                "spyagent",
                "keycapture",
                "keystrokeviewer",
                "activitylogger",
                "spyrat",
                "remoteadmin",
                "stealthkeylogger",
                "keyspy",
                "systemmonitor",
                "rootkit",
                "monitoringtool",
                "silentlogger",
                "wiretapper",
                "camspy",
                "passwordlogger",
                "invisiblekeylogger",
                "stealthmonitor",
                "spyrecorder",
                "razerCentralService",
                "razer synapse service",
                "razer synapse service process",
                "razer synapse service 3",
                "razer central",
            };
        }

        private async Task DetectCheatProcessesAsync()
        {
            try
            {
                Process[] processes = Process.GetProcesses();
                foreach (Process process in processes)
                {
                    if (_blacklistedProcesses.Contains(process.ProcessName))
                    {
                        await HandleCheatDetectionAsync(process);
                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("Cheat detection error", ex);
            }
        }

        private async Task HandleCheatDetectionAsync(Process cheatProcess)
        {
            StopTimers();
            await KillGameProcessesAsync();
            ShowDetectionUI(cheatProcess.ProcessName);
            await SendDetectionToServerAsync(cheatProcess.ProcessName);
            ShowAndExit($"Game terminated due to illegal program {cheatProcess.ProcessName} detection", "alert", 10000);
        }

        private async Task KillGameProcessesAsync()
        {
            await Task.WhenAll(KillProcessAsync("PointBlank"));
        }

        private async Task KillProcessAsync(string processName)
        {
            await Task.Run(() =>
            {
                try
                {
                    Process[] processes = Process.GetProcessesByName(processName);
                    foreach (Process process in processes)
                    {
                        process.Kill();
                        process.WaitForExit(10000);
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error killing process {processName}", ex);
                }
            });
        }

        private async Task CheckSystemState()
        {
            await DetectCheatProcessesAsync();

            if (!await IsGameRunningAsync() || !CheckInternetConnection())
            {
                await HandleGameTermination();
            }
        }

        private async Task<bool> IsGameRunningAsync()
        {
            return await Task.Run(() =>
            {
                return Process.GetProcessesByName("PointBlank").Length > 0;
            });
        }

        private bool CheckInternetConnection()
        {
            return NetworkInterface.GetIsNetworkAvailable();
        }

        private async Task HandleGameTermination()
        {
            StopTimers();
            await KillGameProcessesAsync();
            Application.Exit();
        }

        #endregion

        #region Network Logic

        private void InitializeClient()
        {
            try
            {
                string normalizedIp = NormalizeIpAddress(_serverIp);

                // Validar que la direccion sea alcanzable
                if (!ValidateServerAddress(normalizedIp))
                {
                    LogClientStatus($"Advertencia: No se pudo validar la direccion {normalizedIp}");
                }

                _client = new SimpleTcpClient(normalizedIp, _serverPort);
                _client.Events.Connected += Events_Connected;
                _client.Events.DataReceived += Events_DataReceived;
                _client.Events.Disconnected += Events_Disconnected;

                string addrType = GetAddressType(normalizedIp);
                LogClientStatus($"Cliente TCP inicializado para {normalizedIp}:{_serverPort} ({addrType})");
            }
            catch (Exception ex)
            {
                LogError("Error al inicializar el cliente TCP", ex);
                _client = null;
            }
        }

        private string NormalizeIpAddress(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
            {
                LogError("Direccion IP vacia", new ArgumentException("IP address is empty"));
                return "127.0.0.1";
            }

            try
            {
                // Remover brackets de IPv6 si existen: [::1] -> ::1
                string cleanAddr = ipAddress.Trim().Trim('[', ']');

                // Intentar parsear directamente
                if (IPAddress.TryParse(cleanAddr, out IPAddress parsedIp))
                {
                    return parsedIp.ToString();
                }

                // Si no es una IP, podria ser un hostname - resolver
                try
                {
                    IPAddress[] addresses = Dns.GetHostAddresses(cleanAddr);
                    if (addresses.Length > 0)
                    {
                        // Preferir IPv4 para mayor compatibilidad, a menos que solo haya IPv6
                        IPAddress preferred = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                                           ?? addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetworkV6)
                                           ?? addresses[0];

                        LogClientStatus($"Hostname '{cleanAddr}' resuelto a {preferred}");
                        return preferred.ToString();
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error resolviendo hostname '{cleanAddr}'", ex);
                }

                return cleanAddr;
            }
            catch (Exception ex)
            {
                LogError("Error normalizando direccion IP", ex);
                return ipAddress;
            }
        }

        private bool ValidateServerAddress(string ipAddress)
        {
            try
            {
                if (IPAddress.TryParse(ipAddress, out IPAddress addr))
                {
                    // Verificar si es direccion de loopback
                    if (IPAddress.IsLoopback(addr))
                    {
                        LogClientStatus("Conectando a servidor local (loopback)");
                        return true;
                    }

                    // Verificar si la direccion es valida para conexion
                    if (addr.Equals(IPAddress.Any) || addr.Equals(IPAddress.IPv6Any))
                    {
                        LogError("Direccion no valida para conexion", new ArgumentException("Cannot connect to 0.0.0.0 or ::"));
                        return false;
                    }

                    return true;
                }

                // Si no se puede parsear, asumir que es valido (hostname)
                return true;
            }
            catch
            {
                return false;
            }
        }

        private string GetAddressType(string ipAddress)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress addr))
            {
                if (addr.AddressFamily == AddressFamily.InterNetworkV6)
                    return "IPv6";
                else if (addr.AddressFamily == AddressFamily.InterNetwork)
                    return "IPv4";
            }
            return "hostname";
        }

        private bool ConnectWithRetries(int timeoutMs, int maxRetries = 5)
        {
            if (_client == null)
            {
                LogError("Error de conexion", new Exception("Cliente TCP no inicializado"));
                return false;
            }

            int retryCount = 0;
            int baseDelayMs = 2000;
            bool hasNetworkIssue = false;

            while (retryCount < maxRetries)
            {
                try
                {
                    LogClientStatus($"Intento de conexion {retryCount + 1}/{maxRetries} a {_serverIp}:{_serverPort}");
                    _client.Connect();

                    // Esperar para verificar estabilidad de conexion
                    System.Threading.Thread.Sleep(2000);

                    if (_client.IsConnected)
                    {
                        LogClientStatus("Conexion establecida y estable");
                        return true;
                    }
                    else
                    {
                        LogClientStatus("Conexion cerrada inmediatamente por el servidor");
                    }
                }
                catch (SocketException sockEx)
                {
                    // Manejar errores especificos de socket
                    string errorDetail = GetSocketErrorDescription(sockEx.SocketErrorCode);
                    LogError($"Error de socket: {errorDetail}", sockEx);

                    // Si es un error de red que no se resolvera con reintentos, salir antes
                    if (IsUnrecoverableNetworkError(sockEx.SocketErrorCode))
                    {
                        hasNetworkIssue = true;
                        LogClientStatus("Error de red no recuperable, abortando reintentos");
                        break;
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error en intento de conexion {retryCount + 1}", ex);
                }

                retryCount++;

                // Backoff exponencial: 2s, 4s, 6s, 8s...
                int delayMs = Math.Min(baseDelayMs * retryCount, 10000);
                LogClientStatus($"Esperando {delayMs}ms antes del siguiente intento...");
                System.Threading.Thread.Sleep(delayMs);
            }

            if (hasNetworkIssue)
            {
                LogClientStatus("Verifica: 1) Conexion a internet 2) Firewall 3) Direccion del servidor");
            }
            else
            {
                LogClientStatus($"Fallaron los {maxRetries} intentos de conexion");
            }

            return false;
        }

        private string GetSocketErrorDescription(SocketError errorCode)
        {
            switch (errorCode)
            {
                case SocketError.ConnectionRefused:
                    return "Conexion rechazada - El servidor no esta ejecutandose o el puerto esta cerrado";
                case SocketError.NetworkUnreachable:
                    return "Red inalcanzable - Verifica tu conexion a internet";
                case SocketError.HostUnreachable:
                    return "Host inalcanzable - El servidor no esta disponible";
                case SocketError.TimedOut:
                    return "Tiempo de espera agotado - El servidor no responde";
                case SocketError.AddressNotAvailable:
                    return "Direccion no disponible - Verifica la configuracion de IP";
                case SocketError.AddressFamilyNotSupported:
                    return "Familia de direcciones no soportada - IPv6 puede no estar disponible";
                case SocketError.HostNotFound:
                    return "Host no encontrado - Verifica el nombre del servidor";
                default:
                    return $"Error de socket ({errorCode})";
            }
        }

        private bool IsUnrecoverableNetworkError(SocketError errorCode)
        {
            // Errores que indican problemas de configuracion, no temporales
            return errorCode == SocketError.AddressFamilyNotSupported ||
                   errorCode == SocketError.AddressNotAvailable ||
                   errorCode == SocketError.HostNotFound ||
                   errorCode == SocketError.ProtocolNotSupported;
        }

        private async Task ConnectToServerAsync()
        {
            await Task.Run(() =>
            {
                try
                {
                    if (_client == null)
                    {
                        throw new Exception("Cliente TCP no inicializado");
                    }

                    bool connected = ConnectWithRetries(10000);

                    if (connected && _client.IsConnected)
                    {
                        // Enviar autenticación
                        var authRequest = new
                        {
                            action = "AUTH",
                            key = _serverKey,
                            hwid = getHwid(),
                        };

                        LogClientStatus("Enviando solicitud de autenticación...");
                        _client.Send(JsonConvert.SerializeObject(authRequest));

                        // Añadir una pausa para dar tiempo a recibir la respuesta
                        System.Threading.Thread.Sleep(1000);

                        if (!_client.IsConnected)
                        {
                            throw new Exception(
                                "La conexión se perdió después de la autenticación"
                            );
                        }

                        LogClientStatus(
                            "Verificación de conexión después de autenticación: Conectado"
                        );
                    }
                    else
                    {
                        throw new Exception("La conexión falló después de varios intentos");
                    }
                }
                catch (Exception ex)
                {
                    LogError("Initial connection failed", ex);
                    this.Invoke(
                        (MethodInvoker)
                            delegate
                            {
                                string errorMsg = "Failed to connect to server. Possible causes:\n";
                                errorMsg += "- Check your internet connection\n";
                                errorMsg += "- Firewall may be blocking the connection\n";
                                errorMsg += "- Server may be temporarily unavailable\n";
                                errorMsg += $"\nTechnical details: {ex.Message}";

                                ShowAndExit(errorMsg, "Connection Error", 8000);
                            }
                    );
                }
            });
        }

        #endregion

        #region Game Management

        private void StartGame()
        {
            _gameStartInfo.FileName = $"{_gameExecutable}.exe";
            _gameStartInfo.Arguments = $"{_launchArguments[0]} {_launchArguments[1]}";
            _gameStartInfo.WorkingDirectory = _basePath.Replace("\\HackShield", "\\");
            _gameStartInfo.ErrorDialog = true;

            try
            {
                Process.Start(_gameStartInfo);
            }
            catch (Exception ex)
            {
                LogError("Game start error", ex);
                ShowAndExit("Failed to start game", "alert", 10000);
            }
        }

        private async Task ReportThreatAsync(string processName)
        {
            await Task.Run(() =>
            {
                string jsonData = JsonConvert.SerializeObject(
                    new
                    {
                        action = "THREAT",
                        message = processName,
                        user_id = _launchArguments.Length > 0 ? _launchArguments[0] : null,
                    }
                );
                _client.Send(jsonData);
            });
        }


        private void ShowDetectionUI(string detectedProcess)
        {
            this.Show();
            this.BackgroundImage = Resources.detected;
            LoadingBar.Hide();
        }

        private void ReportThreat(string thread)
        {
            try
            {
                if (_client.IsConnected)
                {
                    string jsonData = JsonConvert.SerializeObject(
                        new
                        {
                            action = "THREAT",
                            message = thread,
                            user_id = _launchArguments.Length > 0 ? _launchArguments[0] : null,
                        }
                    );
                    _client.Send(jsonData);
                }
            }
            catch (Exception ex)
            {
                LogError("Error reporting threat", ex);
            }
        }

        private async Task SendDetectionToServerAsync(string detectedProcess)
        {
            if (_client.IsConnected)
            {
                string jsonData = JsonConvert.SerializeObject(
                    new
                    {
                        action = "CHEAT_REPORT",
                        process = detectedProcess,
                        user_id = _launchArguments.Length > 0 ? _launchArguments[0] : null,
                    }
                );

                await SendToServerAsync(jsonData);
            }
        }

        private async Task SendToServerAsync(string message)
        {
            await Task.Run(() =>
            {
                try
                {
                    _client.Send(message);
                }
                catch (Exception ex)
                {
                    LogError("Error sending message to server", ex);
                }
            });
        }

        #endregion

        #region Event Handlers

        private void Events_Connected(object sender, SuperSimpleTcp.ConnectionEventArgs e)
        {
            this.Invoke(
                (MethodInvoker)
                    delegate
                    {
                        try
                        {
                            LogClientStatus("Connected to server");

                            // Esperar un momento antes de iniciar timers o enviar datos
                            // Esto ayuda a evitar problemas de temporización
                            System.Threading.Thread.Sleep(500);

                            if (_client.IsConnected)
                            {
                                LogClientStatus("Conexión estable después de 500ms");
                                if (_loadingTimer != null)
                                    _loadingTimer.Start();
                            }
                            else
                            {
                                LogClientStatus(
                                    "La conexión se perdió inmediatamente después de conectar"
                                );
                            }
                        }
                        catch (Exception ex)
                        {
                            LogError("Error in connection event handler", ex);
                        }
                    }
            );
        }

        private void Events_DataReceived(object sender, SuperSimpleTcp.DataReceivedEventArgs e)
        {
            this.Invoke(
                (MethodInvoker)
                    async delegate
                    {
                        try
                        {
                            byte[] rawData = e
                                .Data.Array.Skip(e.Data.Offset)
                                .Take(e.Data.Count)
                                .ToArray();
                            string receivedData = Encoding.UTF8.GetString(
                                e.Data.Array,
                                e.Data.Offset,
                                e.Data.Count
                            );
                            dynamic response = JsonConvert.DeserializeObject(receivedData);
                            if (response.action == "AUTH_RESPONSE")
                            {
                                if (response.status == "success")
                                {
                                    LogClientStatus("AUTH_RESPONSE OK");
                                }
                                else
                                {
                                    _client.Disconnect();
                                }
                            }
                            await HandleServerCommandAsync(rawData);
                        }
                        catch (Exception ex)
                        {
                            LogError("Error processing server command", ex);
                        }
                    }
            );
        }

        private void Events_Disconnected(object sender, SuperSimpleTcp.ConnectionEventArgs e)
        {
            this.Invoke(
                (MethodInvoker)
                    async delegate
                    {
                        try
                        {
                            LogClientStatus("Disconnected from server");
                            StopTimers();
                            await KillGameProcessesAsync();
                        }
                        catch (Exception ex)
                        {
                            LogError("Error in disconnection event handler", ex);
                            Application.Exit();
                        }
                    }
            );
        }

        #endregion

        #region Packet Handling

        private async Task HandleServerCommandAsync(byte[] data)
        {
            string jsonData = Encoding.UTF8.GetString(data);
            dynamic obj = JsonConvert.DeserializeObject(jsonData);
            string action = obj.action;
            string key = obj.key;

            switch (action)
            {
                case "disconnect":
                    await HandleGameTermination();
                    break;

                case "shutdown":
                    await ExecuteShutdownCommand();
                    break;

                case "streamviewer":
                    await StartStreamViewer(obj);
                    break;
            }
        }

        private async Task StartStreamViewer(dynamic obj)
        {
            string executable = obj.executable;
            string ip = obj.ip;
            string port = obj.port;
            string postData;

            await Task.Run(() =>
            {
                try
                {
                    // Configura el proceso
                    var process = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = executable,
                            Arguments = $"{ip} {port}",
                            UseShellExecute = false,
                            RedirectStandardOutput = false,
                            CreateNoWindow = false,
                        },
                        EnableRaisingEvents = true, // Necesario para el evento Exited
                    };

                    // Evento que se dispara cuando el proceso termina
                    process.Exited += (sender, e) =>
                    {
                        //Console.WriteLine($"🛑 Proceso terminado (Código: {process.ExitCode})");
                        if (_client.IsConnected)
                        {
                            postData = JsonConvert.SerializeObject(
                                new
                                {
                                    action = "STREAMVIEWER",
                                    message = "Process terminated",
                                    user_id = _launchArguments.Length > 0 ? _launchArguments[0] : null,
                                }
                            );

                            _client.Send(postData);
                        }
                        //process.Dispose(); // Liberar recursos
                    };

                    // Intenta iniciar el proceso
                    bool started = process.Start();

                    if (!started)
                    {
                        if (_client.IsConnected)
                        {
                            postData = JsonConvert.SerializeObject(
                                new
                                {
                                    action = "STREAMVIEWER",
                                    message = "Failed to start process",
                                    user_id = _launchArguments.Length > 0 ? _launchArguments[0] : null,
                                }
                            );
                            _client.Send(postData);
                        }
                        //Console.WriteLine("❌ Error: No se pudo iniciar el proceso.");
                        //process.Dispose();
                    }

                    if (_client.IsConnected)
                    {
                        postData = JsonConvert.SerializeObject(
                            new
                            {
                                action = "STREAMVIEWER",
                                message = "Process started successfully",
                                user_id = _launchArguments.Length > 0 ? _launchArguments[0] : null,
                            }
                        );
                        _client.Send(postData);
                    }
                }
                catch (Exception ex)
                {
                    if (_client.IsConnected)
                    {
                        postData = JsonConvert.SerializeObject(
                            new
                            {
                                action = "STREAMVIEWER",
                                message = $"Error: {ex.Message}",
                                user_id = _launchArguments.Length > 0 ? _launchArguments[0] : null,
                            }
                        );
                        _client.Send(postData);
                    }
                }
            });
        }

        private async Task ExecuteShutdownCommand()
        {
            await Task.Run(() =>
            {
                ProcessStartInfo shutdownInfo = new ProcessStartInfo
                {
                    FileName = "cmd",
                    Arguments = "/c shutdown -p",
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true,
                };

                try
                {
                    Process.Start("shutdown / s / t 1");
                    //Process.Start(shutdownInfo);
                }
                catch (Exception ex)
                {
                    LogError("Shutdown command failed", ex);
                    Application.Exit();
                }
            });
        }

        #endregion

        #region UI & Logging

        public static void ShowAndExit(
            string message,
            string title,
            int durationMilliseconds = 3000
        )
        {
            Form msgForm = new Form()
            {
                Width = 300,
                Height = 150,
                StartPosition = FormStartPosition.CenterScreen,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                ControlBox = false,
                Text = title,
                TopMost = true,
            };

            Label lbl = new Label()
            {
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font("Segoe UI", 12),
                Text = message,
            };

            msgForm.Controls.Add(lbl);

            Timer timer = new Timer();
            timer.Interval = durationMilliseconds;
            timer.Tick += (s, e) =>
            {
                timer.Stop();
                msgForm.Close();
                Application.Exit(); // Salida automática de la app
            };

            timer.Start();
            msgForm.ShowDialog();
        }

        private void OnLoadingTimerTick(object sender, EventArgs e)
        {
            UpdateLoadingProgress();
            if (_loadingProgress >= 6)
            {
                ExisteClaveRegistro();
                _loadingTimer.Stop();
                this.Hide();
                StartInfoClient();
                _securityTimer.Start();
                _heartbeatTimer.Start(); // Iniciar el timer de heartbeat
            }
        }

        private async void OnSecurityTimerTick(object sender, EventArgs e)
        {
            await CheckSystemState();
        }

        private void OnHeartbeatTimerTick(object sender, EventArgs e)
        {
            SendHeartbeat();
        }

        // Método para enviar el heartbeat
        private void SendHeartbeat()
        {
            try
            {
                if (_client != null && _client.IsConnected)
                {
                    // Enviar un mensaje simple de heartbeat
                    string heartbeatData = JsonConvert.SerializeObject(
                        new
                        {
                            action = "HEARTBEAT",
                            user_id = _launchArguments.Length > 0 ? _launchArguments[0] : null,
                            timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                        }
                    );

                    _client.Send(heartbeatData);
                    LogClientStatus("Heartbeat enviado");
                }
                else
                {
                    LogClientStatus("No se pudo enviar heartbeat: cliente no conectado");
                    // Intentar reconectar si es necesario
                    if (_client != null && !_client.IsConnected)
                    {
                        LogClientStatus("Intentando reconectar debido a desconexión detectada...");
                        // Intentar reconectar
                        ConnectWithRetries(10000);
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("Error enviando heartbeat", ex);
            }
        }

        private void UpdateLoadingProgress()
        {
            _loadingProgress++;
            int progressPercentage = (_loadingProgress * 20);

            if (progressPercentage <= 100)
            {
                UpdateLoadingBar(progressPercentage);
            }

            if (_loadingProgress >= 6)
            {
                ExisteClaveRegistro();
                _loadingTimer.Stop();
                this.Hide();
                StartInfoClient();
                _securityTimer.Start();
            }
        }

        private void StartInfoClient()
        {
            try
            {
                if (_client == null)
                {
                    LogClientStatus("No se pudo enviar INIT: cliente no inicializado");
                    return;
                }

                // Verificar si estamos conectados y reconectar si es necesario
                if (!_client.IsConnected)
                {
                    LogClientStatus("El cliente se desconectó. Intentando reconectar...");

                    // Intentar reconectar
                    bool reconnected = ConnectWithRetries(10000);
                    if (!reconnected || !_client.IsConnected)
                    {
                        LogClientStatus("No se pudo reconectar al servidor");
                        return;
                    }

                    // Reenviar la autenticación
                    var authRequest = new
                    {
                        action = "AUTH",
                        key = _serverKey,
                        hwid = getHwid(),
                    };
                    _client.Send(JsonConvert.SerializeObject(authRequest));

                    // Esperar brevemente para la autenticación
                    System.Threading.Thread.Sleep(1000);

                    if (!_client.IsConnected)
                    {
                        LogClientStatus("La reconexión falló durante la autenticación");
                        return;
                    }
                }

                // Si llegamos aquí, estamos conectados y autenticados
                string postData = JsonConvert.SerializeObject(
                    new
                    {
                        action = "INIT",
                        user_id = _launchArguments.Length > 0 ? _launchArguments[0] : null,
                        hwid = getHwid(),
                    }
                );

                _client.Send(postData);
                LogClientStatus("Mensaje INIT enviado correctamente");
            }
            catch (Exception ex)
            {
                LogError("Error starting InfoClient", ex);
            }
        }

        private void UpdateLoadingBar(int percentage)
        {
            LoadingBar.Width = (int)(percentage * LOADING_BAR_MAX_WIDTH / 100);
        }

        private void LogClientStatus(string status)
        {
            string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {status}";
            Debug.WriteLine(logEntry);
            AppendToLogFile(logEntry);
        }

        private void LogError(string message, Exception ex)
        {
            string logEntry =
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] ERROR: {message}: {ex.Message}";
            Debug.WriteLine(logEntry);
            AppendToLogFile(logEntry);
        }

        private void AppendToLogFile(string logEntry)
        {
            try
            {
                using (StreamWriter writer = new StreamWriter(_logFilePath, true))
                {
                    writer.WriteLine(logEntry);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error writing to log file: {ex.Message}");
            }
        }

        #endregion

        #region IPC (Named Pipe)

        private void StartNamedPipeServer()
        {
            // Evitar iniciar múltiples instancias
            if (_isPipeServerRunning)
                return;

            _isPipeServerRunning = true;
            LogClientStatus("[Pipe] Iniciando servidor de pipe...");
            new System.Threading.Thread(() =>
            {
                while (_isPipeServerRunning)
                {
                    using (
                        NamedPipeServerStream pipeServer = new NamedPipeServerStream(
                            "AntiCheatPipe",
                            PipeDirection.In,
                            1,
                            PipeTransmissionMode.Byte,
                            PipeOptions.None
                        )
                    ) // Modo síncrono para depurar
                    {
                        try
                        {
                            // Esperar conexión
                            pipeServer.WaitForConnection();

                            Invoke(
                                (MethodInvoker)(
                                    () =>
                                    {
                                        LogClientStatus("[Pipe] Cliente conectado!");
                                    }
                                )
                            );

                            // Buffer para recibir datos
                            byte[] buffer = new byte[1024];

                            // Mientras la conexión esté activa
                            while (pipeServer.IsConnected)
                            {
                                try
                                {
                                    // Leer datos (bloqueante)
                                    int bytesRead = pipeServer.Read(buffer, 0, buffer.Length);

                                    if (bytesRead > 0)
                                    {
                                        string response = System.Text.Encoding.UTF8.GetString(
                                            buffer,
                                            0,
                                            bytesRead
                                        );

                                        Invoke(
                                            (MethodInvoker)(
                                                () =>
                                                {
                                                    // Procesar el mensaje
                                                    //LogClientStatus(response);

                                                    dynamic obj = JsonConvert.DeserializeObject(
                                                        response
                                                    );

                                                    string action = obj.action;
                                                    string message = obj.message;

                                                    switch (action)
                                                    {
                                                        case "REPORT_DL":
                                                            {
                                                                if (_client.IsConnected)
                                                                {
                                                                    var jsonData = new
                                                                    {
                                                                        action = action,
                                                                        message = message,
                                                                        user_id = _launchArguments.Length
                                                                        > 0
                                                                            ? _launchArguments[0]
                                                                            : null,
                                                                    };

                                                                    _client.Send(
                                                                        JsonConvert.SerializeObject(
                                                                            jsonData
                                                                        )
                                                                    );
                                                                }
                                                            }
                                                            break;

                                                        case "INJECTION_ALERT":
                                                            {
                                                                if (_client.IsConnected)
                                                                {
                                                                    var jsonData = new
                                                                    {
                                                                        action = action,
                                                                        message = message,
                                                                        user_id = _launchArguments.Length
                                                                        > 0
                                                                            ? _launchArguments[0]
                                                                            : null,
                                                                    };

                                                                    _client.Send(
                                                                        JsonConvert.SerializeObject(
                                                                            jsonData
                                                                        )
                                                                    );
                                                                }
                                                            }
                                                            break;

                                                        default:
                                                            break;
                                                    }
                                                }
                                            )
                                        );
                                    }
                                    else
                                    {
                                        break;
                                    }
                                }
                                catch (IOException)
                                {
                                    break;
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Invoke(
                                (MethodInvoker)(
                                    () =>
                                    {
                                        pipeServer.Disconnect();
                                        pipeServer.Close();

                                        LogError("Error en Pipe Server", ex);
                                    }
                                )
                            );
                        }
                        // Esperar un momento antes de reiniciar
                        System.Threading.Thread.Sleep(500);
                    } // El using se asegura de que el pipe se cierre correctamente
                }
            })
            {
                IsBackground = true,
                Name = "PipeServerThread",
            }.Start();
        }

        #endregion

        #region Helpers

        private static int ObtenerVersionDotNet()
        {
            using (RegistryKey clave = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\"))
            {
                if (clave != null && clave.GetValue("Release") != null)
                {
                    return (int)clave.GetValue("Release");
                }
                else
                {
                    return 0; // No está instalado
                }
            }
        }

        #endregion
    }
}