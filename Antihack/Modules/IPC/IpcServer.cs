/**
 * AntiCheat IPC Server Module
 * Receives real-time reports from the DLL injected in the game
 */

using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Antihack.Modules.Logging;

namespace Antihack.Modules.IPC
{
    /// <summary>
    /// Event arguments for IPC messages
    /// </summary>
    public class IpcMessageEventArgs : EventArgs
    {
        public string Action { get; set; }
        public string Message { get; set; }
        public DateTime Timestamp { get; set; }
        public string RawJson { get; set; }
    }

    /// <summary>
    /// Named Pipe server for receiving messages from injected DLL
    /// </summary>
    public class IpcServer : IDisposable
    {
        private const string PIPE_NAME = "AntiCheatPipe";
        private const int BUFFER_SIZE = 4096;

        private NamedPipeServerStream _pipeServer;
        private CancellationTokenSource _cts;
        private Task _listenTask;
        private bool _isRunning;
        private readonly object _lock = new object();

        // Events
        public event EventHandler<IpcMessageEventArgs> MessageReceived;
        public event EventHandler<IpcMessageEventArgs> DebuggerDetected;
        public event EventHandler<IpcMessageEventArgs> InjectionDetected;
        public event EventHandler<IpcMessageEventArgs> MemoryModified;
        public event EventHandler<IpcMessageEventArgs> SuspiciousDllLoaded;
        public event EventHandler<string> ClientConnected;
        public event EventHandler<string> ClientDisconnected;
        public event EventHandler<Exception> Error;

        public bool IsRunning => _isRunning;

        /// <summary>
        /// Start the IPC server
        /// </summary>
        public void Start()
        {
            lock (_lock)
            {
                if (_isRunning)
                {
                    Logger.Log("IPC", "Server already running");
                    return;
                }

                _cts = new CancellationTokenSource();
                _isRunning = true;
                _listenTask = Task.Run(() => ListenLoop(_cts.Token));

                Logger.Log("IPC", "Server started on pipe: " + PIPE_NAME);
            }
        }

        /// <summary>
        /// Stop the IPC server
        /// </summary>
        public void Stop()
        {
            lock (_lock)
            {
                if (!_isRunning) return;

                _isRunning = false;
                _cts?.Cancel();

                try
                {
                    _pipeServer?.Close();
                    _pipeServer?.Dispose();
                }
                catch { }

                _listenTask?.Wait(1000);
                Logger.Log("IPC", "Server stopped");
            }
        }

        /// <summary>
        /// Send a command to the connected DLL
        /// </summary>
        public bool SendCommand(string command)
        {
            try
            {
                if (_pipeServer != null && _pipeServer.IsConnected)
                {
                    byte[] buffer = Encoding.UTF8.GetBytes(command);
                    _pipeServer.Write(buffer, 0, buffer.Length);
                    _pipeServer.Flush();
                    return true;
                }
            }
            catch (Exception ex)
            {
                Logger.Log("IPC", "Error sending command: " + ex.Message);
            }
            return false;
        }

        /// <summary>
        /// Send scan request to DLL
        /// </summary>
        public bool RequestScan()
        {
            return SendCommand("{\"command\":\"SCAN\"}");
        }

        /// <summary>
        /// Request integrity check from DLL
        /// </summary>
        public bool RequestIntegrityCheck()
        {
            return SendCommand("{\"command\":\"CHECK_INTEGRITY\"}");
        }

        private async Task ListenLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested && _isRunning)
            {
                try
                {
                    // Create new pipe server instance
                    _pipeServer = new NamedPipeServerStream(
                        PIPE_NAME,
                        PipeDirection.InOut,
                        1,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous
                    );

                    Logger.Log("IPC", "Waiting for client connection...");

                    // Wait for connection
                    await _pipeServer.WaitForConnectionAsync(token);

                    ClientConnected?.Invoke(this, "DLL connected");
                    Logger.Log("IPC", "Client connected");

                    // Handle client messages
                    await HandleClientAsync(token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    if (_isRunning)
                    {
                        Error?.Invoke(this, ex);
                        Logger.Log("IPC", "Error in listen loop: " + ex.Message);
                    }
                }
                finally
                {
                    try
                    {
                        _pipeServer?.Close();
                        _pipeServer?.Dispose();
                    }
                    catch { }
                }
            }
        }

        private async Task HandleClientAsync(CancellationToken token)
        {
            byte[] buffer = new byte[BUFFER_SIZE];

            while (!token.IsCancellationRequested && _pipeServer.IsConnected)
            {
                try
                {
                    int bytesRead = await _pipeServer.ReadAsync(buffer, 0, buffer.Length, token);

                    if (bytesRead > 0)
                    {
                        string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                        ProcessMessage(message);
                    }
                    else
                    {
                        // Client disconnected
                        break;
                    }
                }
                catch (IOException)
                {
                    // Pipe broken
                    break;
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }

            ClientDisconnected?.Invoke(this, "DLL disconnected");
            Logger.Log("IPC", "Client disconnected");
        }

        private void ProcessMessage(string rawMessage)
        {
            try
            {
                var args = ParseMessage(rawMessage);
                args.RawJson = rawMessage;
                args.Timestamp = DateTime.Now;

                // Fire general event
                MessageReceived?.Invoke(this, args);

                // Fire specific events based on action
                switch (args.Action?.ToUpperInvariant())
                {
                    case "DEBUGGER_DETECTED":
                        Logger.Log("IPC", "ALERT: Debugger detected - " + args.Message);
                        DebuggerDetected?.Invoke(this, args);
                        break;

                    case "INJECTION_ALERT":
                        Logger.Log("IPC", "ALERT: DLL Injection - " + args.Message);
                        InjectionDetected?.Invoke(this, args);
                        break;

                    case "MEMORY_MODIFIED":
                        Logger.Log("IPC", "ALERT: Memory modification - " + args.Message);
                        MemoryModified?.Invoke(this, args);
                        break;

                    case "REPORT_DL":
                    case "SUSPICIOUS_DLL":
                        Logger.Log("IPC", "ALERT: Suspicious DLL - " + args.Message);
                        SuspiciousDllLoaded?.Invoke(this, args);
                        break;

                    case "HEARTBEAT":
                        // DLL is alive, just log
                        Logger.Log("IPC", "Heartbeat received");
                        break;

                    case "STATUS":
                        Logger.Log("IPC", "Status: " + args.Message);
                        break;

                    default:
                        Logger.Log("IPC", "Message: " + args.Action + " - " + args.Message);
                        break;
                }
            }
            catch (Exception ex)
            {
                Logger.Log("IPC", "Error processing message: " + ex.Message);
            }
        }

        private IpcMessageEventArgs ParseMessage(string json)
        {
            var args = new IpcMessageEventArgs();

            // Simple JSON parsing (avoid dependency on Newtonsoft)
            // Expected format: {"action":"TYPE","message":"details"}
            try
            {
                // Extract action
                int actionStart = json.IndexOf("\"action\"");
                if (actionStart >= 0)
                {
                    int valueStart = json.IndexOf(":", actionStart) + 1;
                    int valueEnd = json.IndexOf(",", valueStart);
                    if (valueEnd < 0) valueEnd = json.IndexOf("}", valueStart);

                    string actionValue = json.Substring(valueStart, valueEnd - valueStart)
                        .Trim().Trim('"');
                    args.Action = actionValue;
                }

                // Extract message
                int msgStart = json.IndexOf("\"message\"");
                if (msgStart >= 0)
                {
                    int valueStart = json.IndexOf(":", msgStart) + 1;
                    int valueEnd = json.IndexOf("}", valueStart);

                    string msgValue = json.Substring(valueStart, valueEnd - valueStart)
                        .Trim().Trim('"');
                    args.Message = msgValue;
                }
            }
            catch
            {
                // If parsing fails, use raw message
                args.Action = "UNKNOWN";
                args.Message = json;
            }

            return args;
        }

        public void Dispose()
        {
            Stop();
            _cts?.Dispose();
        }
    }
}
