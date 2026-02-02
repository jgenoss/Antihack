/**
 * AntiCheatCore - IPC Manager Implementation
 * Thread-safe Named Pipes communication with AntiCheat.exe
 */

#include "../include/internal/IPCManager.h"

namespace AntiCheat {

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

IPCManager::IPCManager()
    : m_hPipe(INVALID_HANDLE_VALUE),
      m_readThread(nullptr),
      m_writeThread(nullptr),
      m_heartbeatThread(nullptr),
      m_writeEvent(nullptr),
      m_reconnectAttempts(0),
      m_lastHeartbeat(0),
      m_heartbeatInterval(1000),
      m_pipeName(L"\\\\.\\pipe\\AntiCheatIPC") {
}

IPCManager::~IPCManager() {
    Shutdown();
}

// ============================================================================
// CONNECTION MANAGEMENT
// ============================================================================

bool IPCManager::Initialize(const std::wstring& pipeName) {
    m_pipeName = pipeName;
    m_writeEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!m_writeEvent) {
        m_lastError = "Failed to create write event";
        return false;
    }
    return true;
}

void IPCManager::Shutdown() {
    m_running = false;

    // Signal write thread
    if (m_writeEvent) {
        SetEvent(m_writeEvent);
    }

    // Wait for threads
    if (m_readThread) {
        WaitForSingleObject(m_readThread, 3000);
        CloseHandle(m_readThread);
        m_readThread = nullptr;
    }
    if (m_writeThread) {
        WaitForSingleObject(m_writeThread, 3000);
        CloseHandle(m_writeThread);
        m_writeThread = nullptr;
    }
    if (m_heartbeatThread) {
        WaitForSingleObject(m_heartbeatThread, 3000);
        CloseHandle(m_heartbeatThread);
        m_heartbeatThread = nullptr;
    }

    DisconnectPipe();

    if (m_writeEvent) {
        CloseHandle(m_writeEvent);
        m_writeEvent = nullptr;
    }

    // Clear queues
    {
        std::lock_guard<std::mutex> lock(m_outMutex);
        while (!m_outQueue.empty()) m_outQueue.pop();
    }
    {
        std::lock_guard<std::mutex> lock(m_inMutex);
        while (!m_inQueue.empty()) m_inQueue.pop();
    }
}

bool IPCManager::Connect() {
    if (m_connected) return true;

    if (!ConnectToPipe()) {
        return false;
    }

    m_running = true;
    m_reconnectAttempts = 0;

    // Start threads
    m_readThread = CreateThread(nullptr, 0, ReadThreadProc, this, 0, nullptr);
    m_writeThread = CreateThread(nullptr, 0, WriteThreadProc, this, 0, nullptr);
    m_heartbeatThread = CreateThread(nullptr, 0, HeartbeatThreadProc, this, 0, nullptr);

    if (!m_readThread || !m_writeThread || !m_heartbeatThread) {
        m_lastError = "Failed to create IPC threads";
        Shutdown();
        return false;
    }

    return true;
}

void IPCManager::Disconnect() {
    m_running = false;
    DisconnectPipe();
}

bool IPCManager::Reconnect() {
    if (m_reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        m_lastError = "Max reconnection attempts exceeded";
        return false;
    }

    DisconnectPipe();
    Sleep(RECONNECT_DELAY);

    m_reconnectAttempts++;

    if (ConnectToPipe()) {
        m_reconnectAttempts = 0;
        return true;
    }

    return false;
}

bool IPCManager::ConnectToPipe() {
    // Try to connect to the server's named pipe
    DWORD startTime = GetTickCount();

    while (GetTickCount() - startTime < CONNECT_TIMEOUT) {
        m_hPipe = CreateFileW(
            m_pipeName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );

        if (m_hPipe != INVALID_HANDLE_VALUE) {
            // Set pipe to message mode
            DWORD mode = PIPE_READMODE_MESSAGE;
            if (SetNamedPipeHandleState(m_hPipe, &mode, nullptr, nullptr)) {
                m_connected = true;
                m_lastHeartbeat = GetTickCount();
                return true;
            } else {
                CloseHandle(m_hPipe);
                m_hPipe = INVALID_HANDLE_VALUE;
            }
        }

        DWORD error = GetLastError();
        if (error == ERROR_PIPE_BUSY) {
            // Wait for pipe to become available
            if (!WaitNamedPipeW(m_pipeName.c_str(), 1000)) {
                continue;
            }
        } else {
            Sleep(100);
        }
    }

    m_lastError = "Connection timeout";
    return false;
}

void IPCManager::DisconnectPipe() {
    m_connected = false;

    if (m_hPipe != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(m_hPipe);
        DisconnectNamedPipe(m_hPipe);
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
    }
}

// ============================================================================
// MESSAGE SENDING
// ============================================================================

bool IPCManager::SendMessage(const Message& msg) {
    std::lock_guard<std::mutex> lock(m_outMutex);
    m_outQueue.push(msg);
    SetEvent(m_writeEvent);
    return true;
}

bool IPCManager::SendMessage(MessageType type, const std::string& data) {
    Message msg(type, data);
    return SendMessage(msg);
}

bool IPCManager::SendMessage(MessageType type, const ByteVector& data) {
    Message msg(type, data);
    return SendMessage(msg);
}

bool IPCManager::SendDetection(const DetectionEvent& event) {
    // Serialize detection event
    std::string data;
    data += std::to_string(static_cast<int>(event.type)) + "|";
    data += std::to_string(static_cast<int>(event.severity)) + "|";
    data += event.description + "|";
    data += event.moduleName + "|";
    data += std::to_string(reinterpret_cast<uintptr_t>(event.address));

    MessageType msgType;
    switch (event.type) {
        case DetectionType::HookDetected:
            msgType = MessageType::HookDetected;
            break;
        case DetectionType::MacroDetected:
            msgType = MessageType::MacroDetected;
            break;
        case DetectionType::FileModified:
            msgType = MessageType::FileModified;
            break;
        case DetectionType::DebuggerAttached:
            msgType = MessageType::DebuggerDetected;
            break;
        default:
            msgType = MessageType::CheatDetected;
            break;
    }

    return SendMessage(msgType, data);
}

bool IPCManager::SendHeartbeat() {
    return SendMessage(MessageType::Heartbeat);
}

bool IPCManager::SendRaw(const Message& msg) {
    if (!m_connected || m_hPipe == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Build packet: [type:4][size:4][data:N]
    ByteVector packet;
    packet.resize(8 + msg.data.size());

    *reinterpret_cast<uint32_t*>(&packet[0]) = static_cast<uint32_t>(msg.type);
    *reinterpret_cast<uint32_t*>(&packet[4]) = msg.dataSize;

    if (!msg.data.empty()) {
        memcpy(&packet[8], msg.data.data(), msg.data.size());
    }

    DWORD bytesWritten;
    if (!WriteFile(m_hPipe, packet.data(), static_cast<DWORD>(packet.size()),
                   &bytesWritten, nullptr)) {
        m_lastError = "Write failed";
        return false;
    }

    return bytesWritten == packet.size();
}

// ============================================================================
// MESSAGE RECEIVING
// ============================================================================

bool IPCManager::HasPendingMessages() {
    std::lock_guard<std::mutex> lock(m_inMutex);
    return !m_inQueue.empty();
}

IPCManager::Message IPCManager::PopMessage() {
    std::lock_guard<std::mutex> lock(m_inMutex);
    if (m_inQueue.empty()) {
        return Message();
    }

    Message msg = m_inQueue.front();
    m_inQueue.pop();
    return msg;
}

void IPCManager::SetMessageHandler(MessageHandler handler) {
    m_messageHandler = handler;
}

bool IPCManager::ReceiveRaw(Message& msg) {
    if (!m_connected || m_hPipe == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Read header
    uint8_t header[8];
    DWORD bytesRead;

    if (!ReadFile(m_hPipe, header, 8, &bytesRead, nullptr) || bytesRead != 8) {
        return false;
    }

    msg.type = static_cast<MessageType>(*reinterpret_cast<uint32_t*>(&header[0]));
    msg.dataSize = *reinterpret_cast<uint32_t*>(&header[4]);
    msg.timestamp = GetTickCount();

    // Read data if any
    if (msg.dataSize > 0) {
        if (msg.dataSize > PIPE_BUFFER_SIZE) {
            m_lastError = "Message too large";
            return false;
        }

        msg.data.resize(msg.dataSize);
        if (!ReadFile(m_hPipe, msg.data.data(), msg.dataSize, &bytesRead, nullptr) ||
            bytesRead != msg.dataSize) {
            return false;
        }
    }

    return true;
}

// ============================================================================
// THREAD PROCEDURES
// ============================================================================

DWORD WINAPI IPCManager::ReadThreadProc(LPVOID param) {
    IPCManager* self = static_cast<IPCManager*>(param);
    self->ReadLoop();
    return 0;
}

DWORD WINAPI IPCManager::WriteThreadProc(LPVOID param) {
    IPCManager* self = static_cast<IPCManager*>(param);
    self->WriteLoop();
    return 0;
}

DWORD WINAPI IPCManager::HeartbeatThreadProc(LPVOID param) {
    IPCManager* self = static_cast<IPCManager*>(param);
    self->HeartbeatLoop();
    return 0;
}

void IPCManager::ReadLoop() {
    while (m_running) {
        if (!m_connected) {
            Sleep(100);
            continue;
        }

        Message msg;
        if (ReceiveRaw(msg)) {
            // Handle special messages
            if (msg.type == MessageType::Shutdown) {
                m_running = false;
                break;
            }

            // Queue message
            {
                std::lock_guard<std::mutex> lock(m_inMutex);
                m_inQueue.push(msg);
            }

            // Call handler if set
            if (m_messageHandler) {
                m_messageHandler(msg);
            }
        } else {
            DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED) {
                m_connected = false;
                if (m_running) {
                    Reconnect();
                }
            }
        }
    }
}

void IPCManager::WriteLoop() {
    while (m_running) {
        // Wait for messages or shutdown
        DWORD result = WaitForSingleObject(m_writeEvent, 1000);

        if (!m_running) break;

        if (result == WAIT_OBJECT_0 || result == WAIT_TIMEOUT) {
            // Send all queued messages
            while (m_running && m_connected) {
                Message msg;
                {
                    std::lock_guard<std::mutex> lock(m_outMutex);
                    if (m_outQueue.empty()) break;
                    msg = m_outQueue.front();
                    m_outQueue.pop();
                }

                if (!SendRaw(msg)) {
                    DWORD error = GetLastError();
                    if (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED) {
                        m_connected = false;
                        // Re-queue the message
                        std::lock_guard<std::mutex> lock(m_outMutex);
                        m_outQueue.push(msg);
                        break;
                    }
                }
            }
        }
    }
}

void IPCManager::HeartbeatLoop() {
    while (m_running) {
        Sleep(m_heartbeatInterval);

        if (m_running && m_connected) {
            SendHeartbeat();
            m_lastHeartbeat = GetTickCount();
        }
    }
}

} // namespace AntiCheat
