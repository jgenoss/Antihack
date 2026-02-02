/**
 * AntiCheatCore - IPC Manager Module
 * Thread-safe Named Pipes communication with AntiCheat.exe
 */

#pragma once

#ifndef AC_IPC_MANAGER_H
#define AC_IPC_MANAGER_H

#include "common.h"
#include <queue>

namespace AntiCheat {

class IPCManager {
public:
    enum class MessageType : uint32_t {
        // Status messages
        Heartbeat = 0x0001,
        Status = 0x0002,
        Error = 0x0003,

        // Detection messages
        CheatDetected = 0x0100,
        HookDetected = 0x0101,
        MacroDetected = 0x0102,
        FileModified = 0x0103,
        DebuggerDetected = 0x0104,
        SuspiciousProcess = 0x0105,

        // Commands from server
        RequestScan = 0x0200,
        RequestStatus = 0x0201,
        UpdateConfig = 0x0202,
        Shutdown = 0x0203,

        // Responses
        ScanResult = 0x0300,
        ConfigAck = 0x0301
    };

    struct Message {
        MessageType type;
        uint32_t dataSize;
        ByteVector data;
        DWORD timestamp;

        Message() : type(MessageType::Heartbeat), dataSize(0), timestamp(0) {}
        Message(MessageType t) : type(t), dataSize(0), timestamp(GetTickCount()) {}
        Message(MessageType t, const ByteVector& d)
            : type(t), data(d), dataSize(static_cast<uint32_t>(d.size())),
              timestamp(GetTickCount()) {}
        Message(MessageType t, const std::string& str)
            : type(t), timestamp(GetTickCount()) {
            data.assign(str.begin(), str.end());
            dataSize = static_cast<uint32_t>(data.size());
        }
    };

    using MessageHandler = std::function<void(const Message&)>;

private:
    static const DWORD PIPE_BUFFER_SIZE = 4096;
    static const DWORD CONNECT_TIMEOUT = 5000;
    static const DWORD RECONNECT_DELAY = 1000;
    static const int MAX_RECONNECT_ATTEMPTS = 5;

    std::wstring m_pipeName;
    HANDLE m_hPipe;
    std::atomic<bool> m_connected{false};
    std::atomic<bool> m_running{false};

    HANDLE m_readThread;
    HANDLE m_writeThread;
    HANDLE m_heartbeatThread;

    std::queue<Message> m_outQueue;
    std::queue<Message> m_inQueue;
    std::mutex m_outMutex;
    std::mutex m_inMutex;
    HANDLE m_writeEvent;

    MessageHandler m_messageHandler;
    std::string m_lastError;
    int m_reconnectAttempts;
    DWORD m_lastHeartbeat;
    DWORD m_heartbeatInterval;

    // Thread procedures
    static DWORD WINAPI ReadThreadProc(LPVOID param);
    static DWORD WINAPI WriteThreadProc(LPVOID param);
    static DWORD WINAPI HeartbeatThreadProc(LPVOID param);

    void ReadLoop();
    void WriteLoop();
    void HeartbeatLoop();

    // Internal methods
    bool ConnectToPipe();
    void DisconnectPipe();
    bool SendRaw(const Message& msg);
    bool ReceiveRaw(Message& msg);

public:
    IPCManager();
    ~IPCManager();

    // Connection management
    bool Initialize(const std::wstring& pipeName = L"\\\\.\\pipe\\AntiCheatIPC");
    void Shutdown();
    bool Connect();
    void Disconnect();
    bool Reconnect();

    // Message sending
    bool SendMessage(const Message& msg);
    bool SendMessage(MessageType type, const std::string& data = "");
    bool SendMessage(MessageType type, const ByteVector& data);
    bool SendDetection(const DetectionEvent& event);
    bool SendHeartbeat();

    // Message receiving
    bool HasPendingMessages();
    Message PopMessage();
    void SetMessageHandler(MessageHandler handler);

    // Configuration
    void SetHeartbeatInterval(DWORD intervalMs) { m_heartbeatInterval = intervalMs; }
    void SetPipeName(const std::wstring& name) { m_pipeName = name; }

    // Status
    bool IsConnected() const { return m_connected; }
    bool IsRunning() const { return m_running; }
    DWORD GetLastHeartbeat() const { return m_lastHeartbeat; }
    const std::string& GetLastError() const { return m_lastError; }
};

} // namespace AntiCheat

#endif // AC_IPC_MANAGER_H
