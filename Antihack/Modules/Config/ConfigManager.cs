/**
 * ConfigManager - Configuration Management Module
 * Handles loading and managing application configuration
 */

using System;
using System.IO;
using AntiCheat.Modules.Network;

namespace AntiCheat.Modules.Config
{
    /// <summary>
    /// Application configuration
    /// </summary>
    public class AppConfig
    {
        // Network settings
        public NetworkConfig Network { get; set; } = new NetworkConfig();

        // Game settings
        public string GameExecutable { get; set; }
        public string HardwareId { get; set; }

        // Stream viewer settings
        public string StreamIPv4Host { get; set; }
        public string StreamIPv6Host { get; set; }
        public int StreamPort { get; set; }
    }

    /// <summary>
    /// Configuration manager for loading and saving settings
    /// </summary>
    public class ConfigManager
    {
        private readonly string _basePath;
        private readonly string _configFileName;
        private AppConfig _config;

        public event EventHandler<string> OnLogMessage;

        public AppConfig Config => _config;

        public ConfigManager(string basePath = null, string configFileName = "ext11c.dll")
        {
            _basePath = basePath ?? Directory.GetCurrentDirectory();
            _configFileName = configFileName;
            _config = new AppConfig();
        }

        /// <summary>
        /// Load configuration from INI file
        /// </summary>
        public bool Load()
        {
            try
            {
                string configPath = Path.Combine(_basePath, _configFileName);

                if (!File.Exists(configPath))
                {
                    Log($"Config file not found: {configPath}");
                    return false;
                }

                INIFile ini = new INIFile(configPath);

                // Load game settings
                _config.GameExecutable = ini.IniReadValue("CONFIG", "GAME");
                _config.HardwareId = ini.IniReadValue("CONFIG", "HWID");

                // Load network settings
                _config.Network.IPv4Address = ini.IniReadValue("CONFIG", "IPV4");
                _config.Network.IPv6Address = ini.IniReadValue("CONFIG", "IPV6");

                // Legacy IP support
                if (string.IsNullOrWhiteSpace(_config.Network.IPv4Address) &&
                    string.IsNullOrWhiteSpace(_config.Network.IPv6Address))
                {
                    string legacyIp = ini.IniReadValue("CONFIG", "IP");
                    if (!string.IsNullOrWhiteSpace(legacyIp))
                    {
                        if (legacyIp.Contains(":") && legacyIp != "0.0.0.0")
                            _config.Network.IPv6Address = legacyIp;
                        else
                            _config.Network.IPv4Address = legacyIp;
                    }
                }

                // Parse port
                string portStr = ini.IniReadValue("CONFIG", "PORT");
                if (int.TryParse(portStr, out int port))
                {
                    _config.Network.Port = port;
                }

                _config.Network.AuthKey = ini.IniReadValue("CONFIG", "KEY");

                // Load network priority settings
                string priority = ini.IniReadValue("network", "priority");
                _config.Network.Priority = string.IsNullOrWhiteSpace(priority) ? "ipv4" : priority.ToLower();

                string fallback = ini.IniReadValue("network", "fallback");
                _config.Network.EnableFallback = string.IsNullOrWhiteSpace(fallback) ||
                                                  fallback.ToLower() == "true";

                string timeout = ini.IniReadValue("network", "connection_timeout");
                if (int.TryParse(timeout, out int timeoutMs))
                {
                    _config.Network.ConnectionTimeout = timeoutMs;
                }

                string retries = ini.IniReadValue("network", "retry_count");
                if (int.TryParse(retries, out int retryCount))
                {
                    _config.Network.MaxRetries = retryCount;
                }

                // Load stream viewer settings
                _config.StreamIPv4Host = ini.IniReadValue("server", "ipv4_host");
                _config.StreamIPv6Host = ini.IniReadValue("server", "ipv6_host");

                // Legacy stream host support
                if (string.IsNullOrWhiteSpace(_config.StreamIPv4Host) &&
                    string.IsNullOrWhiteSpace(_config.StreamIPv6Host))
                {
                    string legacyHost = ini.IniReadValue("server", "host");
                    if (!string.IsNullOrWhiteSpace(legacyHost))
                    {
                        if (legacyHost == "::" || (legacyHost.Contains(":") && legacyHost != "0.0.0.0"))
                            _config.StreamIPv6Host = legacyHost;
                        else
                            _config.StreamIPv4Host = legacyHost;
                    }
                }

                string streamPort = ini.IniReadValue("server", "port");
                if (int.TryParse(streamPort, out int sPort))
                {
                    _config.StreamPort = sPort;
                }

                Log("Configuration loaded successfully");
                LogConfigSummary();

                return true;
            }
            catch (Exception ex)
            {
                Log($"Error loading configuration: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Save HWID to configuration
        /// </summary>
        public bool SaveHwid(string hwid)
        {
            try
            {
                string configPath = Path.Combine(_basePath, _configFileName);
                INIFile ini = new INIFile(configPath);
                ini.IniWriteValue("CONFIG", "HWID", hwid);
                _config.HardwareId = hwid;
                return true;
            }
            catch (Exception ex)
            {
                Log($"Error saving HWID: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Validate the configuration
        /// </summary>
        public bool Validate(out string error)
        {
            error = null;

            if (string.IsNullOrWhiteSpace(_config.Network.IPv4Address) &&
                string.IsNullOrWhiteSpace(_config.Network.IPv6Address))
            {
                error = "No server IP address configured";
                return false;
            }

            if (_config.Network.Port <= 0 || _config.Network.Port > 65535)
            {
                error = "Invalid port number";
                return false;
            }

            if (string.IsNullOrWhiteSpace(_config.Network.AuthKey))
            {
                error = "No authentication key configured";
                return false;
            }

            return true;
        }

        private void LogConfigSummary()
        {
            Log($"  Network Priority: {_config.Network.Priority.ToUpper()}");
            Log($"  Fallback: {_config.Network.EnableFallback}");
            Log($"  IPv4: {_config.Network.IPv4Address ?? "Not configured"}");
            Log($"  IPv6: {_config.Network.IPv6Address ?? "Not configured"}");
            Log($"  Port: {_config.Network.Port}");
        }

        private void Log(string message)
        {
            OnLogMessage?.Invoke(this, message);
        }
    }

    /// <summary>
    /// INI file reader/writer (moved from Class folder)
    /// </summary>
    public class INIFile
    {
        private readonly string _path;

        [System.Runtime.InteropServices.DllImport("kernel32")]
        private static extern long WritePrivateProfileString(
            string section, string key, string val, string filePath);

        [System.Runtime.InteropServices.DllImport("kernel32")]
        private static extern int GetPrivateProfileString(
            string section, string key, string def,
            System.Text.StringBuilder retVal, int size, string filePath);

        public INIFile(string iniPath)
        {
            _path = iniPath;
        }

        public void IniWriteValue(string section, string key, string value)
        {
            WritePrivateProfileString(section, key, value, _path);
        }

        public string IniReadValue(string section, string key)
        {
            var temp = new System.Text.StringBuilder(255);
            GetPrivateProfileString(section, key, "", temp, 255, _path);
            return temp.ToString();
        }
    }
}
