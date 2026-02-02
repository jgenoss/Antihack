/**
 * AntiCheatCore - IPC Manager Implementation
 * Thread-safe Named Pipes communication with AntiCheat.exe
 *
 * Protocol: JSON over Named Pipes (Byte mode)
 * Pipe Name: \\.\pipe\AntiCheatPipe
 * Format: {"action":"TYPE","message":"details"}
 */

#include "stdafx.h"
#include "../include/internal/IPCManager.h"
#include <cstdio>

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
      m_pipeName(L"\\\\.\\pipe\\AntiCheatPipe") {  // Match C# pipe name
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
            // Use byte mode to match C# PipeTransmissionMode.Byte
            DWORD mode = PIPE_READMODE_BYTE;
            SetNamedPipeHandleState(m_hPipe, &mode, nullptr, nullptr);

            m_connected = true;
            m_lastHeartbeat = GetTickCount();
            return true;
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

// Helper to escape JSON strings
static std::string EscapeJson(const std::string& str) {
    std::string result;
    result.reserve(str.size() + 16);
    for (char c : str) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:   result += c; break;
        }
    }
    return result;
}

// Helper to create JSON message
static std::string CreateJsonMessage(const std::string& action, const std::string& message) {
    return "{\"action\":\"" + action + "\",\"message\":\"" + EscapeJson(message) + "\"}";
}

bool IPCManager::SendDetection(const DetectionEvent& event) {
    // Map detection type to C# expected action strings
    std::string action;
    switch (event.type) {
        case DetectionType::HookDetected:
        case DetectionType::HookedAPI:
            action = "HOOK_DETECTED";
            break;
        case DetectionType::MacroDetected:
            action = "MACRO_DETECTED";
            break;
        case DetectionType::FileModified:
            action = "FILE_MODIFIED";
            break;
        case DetectionType::DebuggerAttached:
            action = "DEBUGGER_DETECTED";
            break;
        case DetectionType::InjectedDLL:
            action = "INJECTION_ALERT";
            break;
        case DetectionType::ModifiedMemory:
            action = "MEMORY_MODIFIED";
            break;
        case DetectionType::SuspiciousProcess:
        case DetectionType::SuspiciousModule:
            action = "SUSPICIOUS_DLL";
            break;
        case DetectionType::CheatSignature:
            action = "CHEAT_DETECTED";
            break;
        default:
            action = "THREAT";
            break;
    }

    // Build detailed message
    std::string details = event.description;
    if (!event.moduleName.empty()) {
        details += " [Module: " + event.moduleName + "]";
    }
    if (event.address != nullptr) {
        char addrBuf[32];
        sprintf_s(addrBuf, "0x%p", event.address);
        details += " [Addr: " + std::string(addrBuf) + "]";
    }

    // Create JSON and send
    std::string json = CreateJsonMessage(action, details);
    return SendMessage(MessageType::CheatDetected, json);
}

bool IPCManager::SendHeartbeat() {
    std::string json = CreateJsonMessage("HEARTBEAT", "alive");
    return SendMessage(MessageType::Heartbeat, json);
}

bool IPCManager::SendRaw(const Message& msg) {
    if (!m_connected || m_hPipe == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Send JSON string directly (C# expects raw JSON, not binary header)
    // If data is empty, send a minimal JSON based on message type
    const uint8_t* dataPtr;
    DWORD dataSize;

    if (msg.data.empty()) {
        // Create minimal JSON for message types without data
        static const char* heartbeatJson = "{\"action\":\"HEARTBEAT\",\"message\":\"alive\"}";
        static const char* statusJson = "{\"action\":\"STATUS\",\"message\":\"ok\"}";

        if (msg.type == MessageType::Heartbeat) {
            dataPtr = reinterpret_cast<const uint8_t*>(heartbeatJson);
            dataSize = static_cast<DWORD>(strlen(heartbeatJson));
        } else {
            dataPtr = reinterpret_cast<const uint8_t*>(statusJson);
            dataSize = static_cast<DWORD>(strlen(statusJson));
        }
    } else {
        dataPtr = msg.data.data();
        dataSize = static_cast<DWORD>(msg.data.size());
    }

    DWORD bytesWritten;
    if (!WriteFile(m_hPipe, dataPtr, dataSize, &bytesWritten, nullptr)) {
        m_lastError = "Write failed: " + std::to_string(GetLastError());
        return false;
    }

    return bytesWritten == dataSize;
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

    // Read JSON string from pipe (C# sends raw JSON)
    uint8_t buffer[PIPE_BUFFER_SIZE];
    DWORD bytesRead;

    if (!ReadFile(m_hPipe, buffer, PIPE_BUFFER_SIZE - 1, &bytesRead, nullptr)) {
        return false;
    }

    if (bytesRead == 0) {
        return false;
    }

    // Null-terminate and parse
    buffer[bytesRead] = '\0';
    std::string json(reinterpret_cast<char*>(buffer), bytesRead);

    msg.timestamp = GetTickCount();
    msg.data.assign(buffer, buffer + bytesRead);
    msg.dataSize = bytesRead;

    // Parse command from JSON to determine message type
    // Expected format: {"command":"SCAN"} or {"command":"CHECK_INTEGRITY"}
    if (json.find("\"SCAN\"") != std::string::npos) {
        msg.type = MessageType::RequestScan;
    } else if (json.find("\"CHECK_INTEGRITY\"") != std::string::npos) {
        msg.type = MessageType::RequestStatus;
    } else if (json.find("\"SHUTDOWN\"") != std::string::npos) {
        msg.type = MessageType::Shutdown;
    } else if (json.find("\"UPDATE_CONFIG\"") != std::string::npos) {
        msg.type = MessageType::UpdateConfig;
    } else {
        msg.type = MessageType::Status;
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
