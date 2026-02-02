/**
 * AntiCheatCore - Unified AntiCheat Engine Implementation
 * Main orchestrator that manages all security modules
 */

#include "../include/internal/AntiCheatEngine.h"
#include <sstream>

namespace AntiCheat {

// Singleton instance
static AntiCheatEngine* g_instance = nullptr;

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

AntiCheatEngine::AntiCheatEngine()
    : m_monitorThread(nullptr),
      m_startTime(0),
      m_totalDetections(0),
      m_criticalDetections(0) {
}

AntiCheatEngine::~AntiCheatEngine() {
    Shutdown();
}

AntiCheatEngine& AntiCheatEngine::GetInstance() {
    if (!g_instance) {
        g_instance = new AntiCheatEngine();
    }
    return *g_instance;
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool AntiCheatEngine::Initialize(const Config& config) {
    if (m_initialized) return true;

    std::lock_guard<std::mutex> lock(m_mutex);

    m_config = config;
    Log("Initializing AntiCheat Engine...");

    // Create modules
    m_fileProtection = std::make_unique<FileProtection>();
    m_encryption = std::make_unique<EncryptionLib>();
    m_macroDetector = std::make_unique<MacroDetector>();
    m_hookDetector = std::make_unique<HookDetector>();
    m_signatures = std::make_unique<CheatSignatures>();
    m_ipcManager = std::make_unique<IPCManager>();

    // Initialize modules
    bool success = true;

    if (config.enableFileProtection) {
        if (!m_fileProtection->Initialize()) {
            LogError("Failed to initialize FileProtection");
            success = false;
        }
    }

    if (config.enableMacroDetection) {
        if (!m_macroDetector->Initialize()) {
            LogError("Failed to initialize MacroDetector");
            success = false;
        }
    }

    if (config.enableHookDetection) {
        if (!m_hookDetector->Initialize()) {
            LogError("Failed to initialize HookDetector");
            success = false;
        }
        // Store original function prologues for later comparison
        m_hookDetector->StoreCriticalPrologues();
    }

    if (config.enableMemoryScan) {
        if (!m_signatures->Initialize()) {
            LogError("Failed to initialize CheatSignatures");
            success = false;
        }
    }

    // Initialize IPC
    if (!m_ipcManager->Initialize(config.pipeName)) {
        LogError("Failed to initialize IPC");
        success = false;
    }

    // Set callbacks
    if (m_macroDetector) {
        m_macroDetector->SetDetectionCallback([this](const DetectionEvent& e) {
            OnDetection(e);
        });
    }

    if (m_hookDetector) {
        m_hookDetector->SetDetectionCallback([this](const DetectionEvent& e) {
            OnDetection(e);
        });
    }

    if (m_fileProtection) {
        m_fileProtection->SetViolationCallback([this](const FileProtection::VerificationResult& r) {
            DetectionEvent event;
            event.type = DetectionType::FileModified;
            event.severity = Severity::Critical;
            event.description = "File integrity violation: " + WStringToString(r.path);
            event.timestamp = GetTickCount();
            OnDetection(event);
        });
    }

    m_ipcManager->SetMessageHandler([this](const IPCManager::Message& msg) {
        OnIPCMessage(msg);
    });

    m_startTime = GetTickCount();
    m_initialized = success;

    Log("AntiCheat Engine initialized " + std::string(success ? "successfully" : "with errors"));

    return success;
}

bool AntiCheatEngine::Start() {
    if (!m_initialized) {
        m_lastError = "Engine not initialized";
        return false;
    }

    if (m_running) return true;

    Log("Starting AntiCheat Engine...");

    // Connect to server
    if (!m_ipcManager->Connect()) {
        LogError("Failed to connect to AntiCheat server");
        // Continue anyway - we can run standalone
    }

    // Start file monitoring
    if (m_config.enableFileProtection && m_fileProtection) {
        m_fileProtection->StartMonitoring(m_config.fileScanInterval);
    }

    // Enable macro detection
    if (m_config.enableMacroDetection && m_macroDetector) {
        m_macroDetector->Enable();
    }

    // Start monitor thread
    m_running = true;
    m_monitorThread = CreateThread(nullptr, 0, MonitorThreadProc, this, 0, nullptr);

    if (!m_monitorThread) {
        m_lastError = "Failed to create monitor thread";
        m_running = false;
        return false;
    }

    Log("AntiCheat Engine started");
    return true;
}

void AntiCheatEngine::Stop() {
    if (!m_running) return;

    Log("Stopping AntiCheat Engine...");

    m_running = false;

    // Wait for monitor thread
    if (m_monitorThread) {
        WaitForSingleObject(m_monitorThread, 5000);
        CloseHandle(m_monitorThread);
        m_monitorThread = nullptr;
    }

    // Stop modules
    if (m_fileProtection) {
        m_fileProtection->StopMonitoring();
    }

    if (m_macroDetector) {
        m_macroDetector->Disable();
    }

    // Disconnect IPC
    if (m_ipcManager) {
        m_ipcManager->Disconnect();
    }

    Log("AntiCheat Engine stopped");
}

void AntiCheatEngine::Shutdown() {
    Stop();

    std::lock_guard<std::mutex> lock(m_mutex);

    // Shutdown modules
    if (m_fileProtection) m_fileProtection->Shutdown();
    if (m_macroDetector) m_macroDetector->Shutdown();
    if (m_hookDetector) m_hookDetector->Shutdown();
    if (m_signatures) m_signatures->Shutdown();
    if (m_ipcManager) m_ipcManager->Shutdown();

    // Reset modules
    m_fileProtection.reset();
    m_encryption.reset();
    m_macroDetector.reset();
    m_hookDetector.reset();
    m_signatures.reset();
    m_ipcManager.reset();

    m_initialized = false;

    if (g_instance == this) {
        g_instance = nullptr;
    }
}

// ============================================================================
// CONFIGURATION
// ============================================================================

bool AntiCheatEngine::LoadConfig(const std::wstring& path) {
    // TODO: Implement config file loading
    return true;
}

bool AntiCheatEngine::SaveConfig(const std::wstring& path) {
    // TODO: Implement config file saving
    return true;
}

void AntiCheatEngine::SetConfig(const Config& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_config = config;
}

// ============================================================================
// CALLBACKS
// ============================================================================

void AntiCheatEngine::SetDetectionCallback(DetectionCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_detectionCallback = callback;
}

void AntiCheatEngine::SetLogCallback(MessageCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_logCallback = callback;
}

// ============================================================================
// MANUAL OPERATIONS
// ============================================================================

bool AntiCheatEngine::ForceMemoryScan() {
    if (!m_initialized || !m_signatures) return false;

    Log("Performing memory scan...");
    PerformMemoryScan();
    return true;
}

bool AntiCheatEngine::ForceHookScan() {
    if (!m_initialized || !m_hookDetector) return false;

    Log("Performing hook scan...");
    PerformHookScan();
    return true;
}

bool AntiCheatEngine::ForceFileScan() {
    if (!m_initialized || !m_fileProtection) return false;

    Log("Performing file scan...");
    PerformFileScan();
    return true;
}

bool AntiCheatEngine::ForceProcessScan() {
    if (!m_initialized || !m_signatures) return false;

    Log("Performing process scan...");
    PerformProcessScan();
    return true;
}

bool AntiCheatEngine::ForceFullScan() {
    bool success = true;
    success &= ForceMemoryScan();
    success &= ForceHookScan();
    success &= ForceFileScan();
    success &= ForceProcessScan();
    return success;
}

// ============================================================================
// STATUS
// ============================================================================

AntiCheatEngine::EngineStatus AntiCheatEngine::GetStatus() const {
    EngineStatus status;
    status.isRunning = m_running;
    status.isConnected = m_ipcManager ? m_ipcManager->IsConnected() : false;
    status.totalDetections = m_totalDetections;
    status.criticalDetections = m_criticalDetections;
    status.uptime = m_running ? (GetTickCount() - m_startTime) : 0;
    status.lastScanTime = 0; // TODO: Track this
    status.statusMessage = m_running ? "Running" : "Stopped";
    return status;
}

// ============================================================================
// MONITOR THREAD
// ============================================================================

DWORD WINAPI AntiCheatEngine::MonitorThreadProc(LPVOID param) {
    AntiCheatEngine* self = static_cast<AntiCheatEngine*>(param);
    self->MonitorLoop();
    return 0;
}

void AntiCheatEngine::MonitorLoop() {
    DWORD lastMemoryScan = 0;
    DWORD lastHookScan = 0;
    DWORD lastProcessScan = 0;
    DWORD lastAntiDebug = 0;

    while (m_running) {
        DWORD now = GetTickCount();

        // Memory scan
        if (m_config.enableMemoryScan && (now - lastMemoryScan >= m_config.memoryScanInterval)) {
            PerformMemoryScan();
            lastMemoryScan = now;
        }

        // Hook scan
        if (m_config.enableHookDetection && (now - lastHookScan >= m_config.hookScanInterval)) {
            PerformHookScan();
            lastHookScan = now;
        }

        // Process scan
        if (m_config.enableProcessMonitoring && (now - lastProcessScan >= m_config.processScanInterval)) {
            PerformProcessScan();
            lastProcessScan = now;
        }

        // Anti-debug checks
        if (m_config.enableAntiDebug && (now - lastAntiDebug >= 1000)) {
            PerformAntiDebugCheck();
            lastAntiDebug = now;
        }

        Sleep(100);
    }
}

// ============================================================================
// SCAN METHODS
// ============================================================================

void AntiCheatEngine::PerformMemoryScan() {
    if (!m_signatures) return;

    auto results = m_signatures->ScanProcess(GetCurrentProcess());

    for (const auto& result : results) {
        if (result.found) {
            DetectionEvent event;
            event.type = DetectionType::CheatSignature;
            event.severity = result.severity;
            event.description = "Cheat signature detected: " + result.signatureName;
            event.address = result.address;
            event.timestamp = GetTickCount();
            OnDetection(event);
        }
    }
}

void AntiCheatEngine::PerformHookScan() {
    if (!m_hookDetector) return;

    // Verify stored prologues
    if (!m_hookDetector->VerifyStoredPrologues()) {
        DetectionEvent event;
        event.type = DetectionType::HookDetected;
        event.severity = Severity::Critical;
        event.description = "Critical API hook detected";
        event.timestamp = GetTickCount();
        OnDetection(event);
    }

    // Full hook scan
    auto result = m_hookDetector->ScanCriticalAPIs();
    // Results are reported via callback
}

void AntiCheatEngine::PerformFileScan() {
    if (!m_fileProtection) return;

    std::vector<FileProtection::VerificationResult> results;
    m_fileProtection->VerifyAllFiles(results);
    // Results are reported via callback
}

void AntiCheatEngine::PerformProcessScan() {
    if (!m_signatures) return;

    auto results = m_signatures->ScanRunningProcesses();

    for (const auto& result : results) {
        if (result.found) {
            DetectionEvent event;
            event.type = DetectionType::SuspiciousProcess;
            event.severity = result.severity;
            event.description = result.details;
            event.timestamp = GetTickCount();
            OnDetection(event);
        }
    }
}

void AntiCheatEngine::PerformAntiDebugCheck() {
    if (!m_hookDetector) return;

    if (m_hookDetector->IsDebuggerPresent() || m_hookDetector->IsRemoteDebuggerPresent()) {
        DetectionEvent event;
        event.type = DetectionType::DebuggerAttached;
        event.severity = Severity::Critical;
        event.description = "Debugger detected";
        event.timestamp = GetTickCount();
        OnDetection(event);
    }

    if (m_hookDetector->CheckDebugRegisters()) {
        DetectionEvent event;
        event.type = DetectionType::DebuggerAttached;
        event.severity = Severity::Warning;
        event.description = "Hardware breakpoints detected";
        event.timestamp = GetTickCount();
        OnDetection(event);
    }
}

// ============================================================================
// EVENT HANDLING
// ============================================================================

void AntiCheatEngine::OnDetection(const DetectionEvent& event) {
    m_totalDetections++;
    if (event.severity == Severity::Critical || event.severity == Severity::Fatal) {
        m_criticalDetections++;
    }

    // Log the detection
    std::stringstream ss;
    ss << "DETECTION [" << static_cast<int>(event.severity) << "]: " << event.description;
    Log(ss.str());

    // Send to server
    if (m_ipcManager && m_ipcManager->IsConnected()) {
        m_ipcManager->SendDetection(event);
    }

    // Call user callback
    if (m_detectionCallback) {
        m_detectionCallback(event);
    }
}

void AntiCheatEngine::OnIPCMessage(const IPCManager::Message& msg) {
    switch (msg.type) {
        case IPCManager::MessageType::RequestScan:
            ForceFullScan();
            break;

        case IPCManager::MessageType::RequestStatus:
            // Send status back
            if (m_ipcManager) {
                auto status = GetStatus();
                std::string statusStr = status.statusMessage;
                m_ipcManager->SendMessage(IPCManager::MessageType::Status, statusStr);
            }
            break;

        case IPCManager::MessageType::UpdateConfig:
            // TODO: Parse config from message data
            break;

        case IPCManager::MessageType::Shutdown:
            Stop();
            break;

        default:
            break;
    }
}

// ============================================================================
// LOGGING
// ============================================================================

void AntiCheatEngine::Log(const std::string& message) {
    if (m_logCallback) {
        m_logCallback(message);
    }
}

void AntiCheatEngine::LogError(const std::string& message) {
    m_lastError = message;
    Log("ERROR: " + message);
}

} // namespace AntiCheat
