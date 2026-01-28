/**
 * Logger - Centralized Logging Module
 * Handles all application logging
 */

using System;
using System.Diagnostics;
using System.IO;

namespace AntiCheat.Modules.Logging
{
    /// <summary>
    /// Log levels
    /// </summary>
    public enum LogLevel
    {
        Debug,
        Info,
        Warning,
        Error,
        Critical
    }

    /// <summary>
    /// Log entry
    /// </summary>
    public class LogEntry
    {
        public DateTime Timestamp { get; set; }
        public LogLevel Level { get; set; }
        public string Category { get; set; }
        public string Message { get; set; }
        public Exception Exception { get; set; }
    }

    /// <summary>
    /// Centralized logger for the application
    /// </summary>
    public static class Logger
    {
        private static string _logFilePath;
        private static LogLevel _minimumLevel = LogLevel.Info;
        private static readonly object _lock = new object();
        private static bool _initialized = false;

        public static event EventHandler<LogEntry> OnLogEntry;

        /// <summary>
        /// Initialize the logger
        /// </summary>
        public static void Initialize(string logFilePath = null, LogLevel minimumLevel = LogLevel.Info)
        {
            _logFilePath = logFilePath ?? Path.Combine(
                Directory.GetCurrentDirectory(), "anticheat.log");
            _minimumLevel = minimumLevel;
            _initialized = true;

            Info("Logger", "Logger initialized");
        }

        /// <summary>
        /// Log a debug message
        /// </summary>
        public static void Debug(string category, string message)
        {
            Log(LogLevel.Debug, category, message);
        }

        /// <summary>
        /// Log an info message
        /// </summary>
        public static void Info(string category, string message)
        {
            Log(LogLevel.Info, category, message);
        }

        /// <summary>
        /// Log a warning message
        /// </summary>
        public static void Warning(string category, string message)
        {
            Log(LogLevel.Warning, category, message);
        }

        /// <summary>
        /// Log an error message
        /// </summary>
        public static void Error(string category, string message, Exception ex = null)
        {
            Log(LogLevel.Error, category, message, ex);
        }

        /// <summary>
        /// Log a critical message
        /// </summary>
        public static void Critical(string category, string message, Exception ex = null)
        {
            Log(LogLevel.Critical, category, message, ex);
        }

        /// <summary>
        /// Log a message with specified level
        /// </summary>
        public static void Log(LogLevel level, string category, string message, Exception ex = null)
        {
            if (!_initialized || level < _minimumLevel)
                return;

            var entry = new LogEntry
            {
                Timestamp = DateTime.Now,
                Level = level,
                Category = category,
                Message = message,
                Exception = ex
            };

            // Write to debug output
            string logLine = FormatLogEntry(entry);
            System.Diagnostics.Debug.WriteLine(logLine);

            // Write to file
            WriteToFile(logLine);

            // Raise event
            OnLogEntry?.Invoke(null, entry);
        }

        /// <summary>
        /// Format a log entry as a string
        /// </summary>
        private static string FormatLogEntry(LogEntry entry)
        {
            string level = entry.Level.ToString().ToUpper().PadRight(8);
            string line = $"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss}] [{level}] [{entry.Category}] {entry.Message}";

            if (entry.Exception != null)
            {
                line += $"\n    Exception: {entry.Exception.GetType().Name}: {entry.Exception.Message}";
                if (entry.Exception.StackTrace != null)
                {
                    line += $"\n    StackTrace: {entry.Exception.StackTrace}";
                }
            }

            return line;
        }

        /// <summary>
        /// Write log entry to file
        /// </summary>
        private static void WriteToFile(string logLine)
        {
            if (string.IsNullOrEmpty(_logFilePath))
                return;

            try
            {
                lock (_lock)
                {
                    using (StreamWriter writer = new StreamWriter(_logFilePath, true))
                    {
                        writer.WriteLine(logLine);
                    }
                }
            }
            catch
            {
                // Ignore file write errors to prevent infinite loops
            }
        }

        /// <summary>
        /// Clear the log file
        /// </summary>
        public static void ClearLog()
        {
            try
            {
                lock (_lock)
                {
                    if (File.Exists(_logFilePath))
                    {
                        File.WriteAllText(_logFilePath, string.Empty);
                    }
                }
            }
            catch { }
        }

        /// <summary>
        /// Get recent log entries from file
        /// </summary>
        public static string[] GetRecentEntries(int count = 100)
        {
            try
            {
                if (!File.Exists(_logFilePath))
                    return Array.Empty<string>();

                var lines = File.ReadAllLines(_logFilePath);
                int start = Math.Max(0, lines.Length - count);
                int length = Math.Min(count, lines.Length);

                string[] result = new string[length];
                Array.Copy(lines, start, result, 0, length);
                return result;
            }
            catch
            {
                return Array.Empty<string>();
            }
        }
    }
}
