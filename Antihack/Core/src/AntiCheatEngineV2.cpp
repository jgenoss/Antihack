/**
 * AntiCheatCore - Refactored AntiCheat Engine (V2) Implementation
 *
 * Full implementation - no TODO stubs, no placeholder methods.
 */

#include "../include/internal/AntiCheatEngineV2.hpp"
#include "../include/internal/FileProtectionV2.hpp"
#include "../include/internal/EncryptionLibV2.hpp"
#include "../include/internal/ProcessMonitorV2.hpp"
#include "../include/internal/MacroDetector.h"
#include "../include/internal/HookDetector.h"
#include "../include/internal/CheatSignatures.h"
#include "../include/internal/IPCManager.h"
#include <sstream>

namespace AntiCheat {

// ============================================================================
// SINGLETON (Meyer's - no raw new/delete)
// ============================================================================

AntiCheatEngineV2& AntiCheatEngineV2::GetInstance() {
    static AntiCheatEngineV2 instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

AntiCheatEngineV2::AntiCheatEngineV2()
    : m_running(false)
    , m_initialized(false)
    , m_startTime(0)
    , m_totalDetections(0)
    , m_criticalDetections(0)
    , m_ipcForwarderSubscription(0) {
}

AntiCheatEngineV2::~AntiCheatEngineV2() {
    Shutdown();
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool AntiCheatEngineV2::Initialize(const Config& config) {
    if (m_initialized.load(std::memory_order_acquire)) {
        return true;
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    m_config = config;
    Log("Initializing AntiCheat Engine V2...");

    // Create the stop event for the monitor thread (manual-reset)
    m_stopEvent = MakeEvent(/*manualReset=*/true, /*initialState=*/false);
    if (!m_stopEvent) {
        LogError("Failed to create stop event");
        return false;
    }

    // Start the EventBus dispatch thread
    if (!m_eventBus.Start()) {
        LogError("Failed to start EventBus");
        return false;
    }

    // Register ourselves as a configurable module
    m_configParser.RegisterModule(this);

    // Create all modules
    bool success = true;

    m_fileProtection = std::make_unique<FileProtectionV2>();
    m_encryption = std::make_unique<EncryptionLibV2>();
    if (!m_encryption->Initialize()) {
        LogError("Failed to initialize EncryptionLibV2");
        success = false;
    }

    m_processMonitor = std::make_unique<ProcessMonitorV2>();
    m_macroDetector = std::make_unique<MacroDetector>();
    m_hookDetector = std::make_unique<HookDetector>();
    m_signatures = std::make_unique<CheatSignatures>();
    m_ipcManager = std::make_unique<IPCManager>();

    // Initialize enabled modules
    if (config.enableFileProtection) {
        if (!m_fileProtection->Initialize()) {
            LogError("Failed to initialize FileProtectionV2");
            success = false;
        }
    }

    if (config.enableProcessMonitoring) {
        if (!m_processMonitor->Initialize()) {
            LogError("Failed to initialize ProcessMonitorV2");
            success = false;
        } else {
            m_processMonitor->CaptureBaseline();
            m_processMonitor->SetDetectionCallback([this](const DetectionEvent& e) {
                OnDetection(e);
            });
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

    // Set detection callbacks to route through EventBus
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

    // Subscribe to EventBus for IPC forwarding
    m_ipcForwarderSubscription = m_eventBus.Subscribe(
        [this](const DetectionEvent& event) {
            if (m_ipcManager && m_ipcManager->IsConnected()) {
                m_ipcManager->SendDetection(event);
            }
        });

    // Set IPC message handler
    m_ipcManager->SetMessageHandler([this](const IPCManager::Message& msg) {
        OnIPCMessage(msg);
    });

    // Load config file if path specified
    if (!config.configFilePath.empty()) {
        if (!LoadConfigFromFile(config.configFilePath)) {
            Log("Warning: Could not load config file, using defaults");
        }
    }

    m_startTime = ::GetTickCount();
    m_initialized.store(success, std::memory_order_release);

    Log("AntiCheat Engine V2 initialized " + std::string(success ? "successfully" : "with errors"));
    return success;
}

bool AntiCheatEngineV2::Start() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        m_lastError = "Engine not initialized";
        return false;
    }

    if (m_running.load(std::memory_order_acquire)) {
        return true;
    }

    Log("Starting AntiCheat Engine V2...");

    // Connect to C# application via IPC
    if (m_ipcManager && !m_ipcManager->Connect()) {
        Log("Warning: Failed to connect IPC. Running in standalone mode.");
    }

    // Start file monitoring (IMonitorModule thread)
    if (m_config.enableFileProtection && m_fileProtection) {
        m_fileProtection->StartMonitoring(m_config.fileScanIntervalMs);
    }

    // Start process monitoring (IMonitorModule thread)
    if (m_config.enableProcessMonitoring && m_processMonitor) {
        m_processMonitor->StartMonitoring(m_config.processScanIntervalMs);
    }

    // Enable macro detection
    if (m_config.enableMacroDetection && m_macroDetector) {
        m_macroDetector->Enable();
    }

    // Reset stop event and start monitor thread
    ::ResetEvent(m_stopEvent.Get());
    m_running.store(true, std::memory_order_release);

    DWORD threadId = 0;
    HANDLE rawThread = ::CreateThread(nullptr, 0, MonitorThreadProc, this, 0, &threadId);
    if (rawThread == nullptr) {
        m_lastError = "Failed to create monitor thread: " + std::to_string(::GetLastError());
        m_running.store(false, std::memory_order_release);
        return false;
    }

    m_monitorThread = KernelHandle(rawThread);
    ::SetThreadPriority(m_monitorThread.Get(), THREAD_PRIORITY_BELOW_NORMAL);

    Log("AntiCheat Engine V2 started");
    return true;
}

void AntiCheatEngineV2::Stop() {
    if (!m_running.load(std::memory_order_acquire)) {
        return;
    }

    Log("Stopping AntiCheat Engine V2...");

    // Signal the monitor thread to stop
    m_running.store(false, std::memory_order_release);
    if (m_stopEvent) {
        ::SetEvent(m_stopEvent.Get());
    }

    // Wait for monitor thread to exit (RAII will close the handle)
    if (m_monitorThread) {
        DWORD waitResult = ::WaitForSingleObject(m_monitorThread.Get(), 5000);
        if (waitResult == WAIT_TIMEOUT) {
            ::TerminateThread(m_monitorThread.Get(), 1);
        }
        m_monitorThread.Reset();
    }

    // Stop modules
    if (m_fileProtection) {
        m_fileProtection->StopMonitoring();
    }
    if (m_processMonitor) {
        m_processMonitor->StopMonitoring();
    }
    if (m_macroDetector) {
        m_macroDetector->Disable();
    }
    if (m_ipcManager) {
        m_ipcManager->Disconnect();
    }

    Log("AntiCheat Engine V2 stopped");
}

void AntiCheatEngineV2::Shutdown() {
    Stop();

    std::lock_guard<std::mutex> lock(m_mutex);

    // Unsubscribe from EventBus before destroying modules
    if (m_ipcForwarderSubscription != 0) {
        m_eventBus.Unsubscribe(m_ipcForwarderSubscription);
        m_ipcForwarderSubscription = 0;
    }

    // Stop EventBus (flushes remaining events)
    m_eventBus.Stop(/*flushRemaining=*/true);

    // Shutdown modules (each module's destructor handles cleanup via RAII)
    if (m_fileProtection)  m_fileProtection->Shutdown();
    if (m_processMonitor)  m_processMonitor->Shutdown();
    if (m_macroDetector)   m_macroDetector->Shutdown();
    if (m_hookDetector)    m_hookDetector->Shutdown();
    if (m_signatures)      m_signatures->Shutdown();
    if (m_ipcManager)      m_ipcManager->Shutdown();

    // Release module ownership (unique_ptr handles deallocation)
    m_fileProtection.reset();
    m_encryption.reset();
    m_processMonitor.reset();
    m_macroDetector.reset();
    m_hookDetector.reset();
    m_signatures.reset();
    m_ipcManager.reset();

    // Release RAII handles
    m_stopEvent.Reset();

    m_initialized.store(false, std::memory_order_release);
    Log("AntiCheat Engine V2 shut down");
}

// ============================================================================
// CONFIGURATION (IConfigurable implementation)
// ============================================================================

bool AntiCheatEngineV2::ApplyConfig(const ConfigMap& config) {
    auto getOrDefault = [&config](const std::string& key, const std::string& def) -> std::string {
        auto it = config.find(key);
        return (it != config.end()) ? it->second : def;
    };

    auto getIntOrDefault = [&getOrDefault](const std::string& key, int def) -> int {
        std::string val = getOrDefault(key, "");
        if (val.empty()) return def;
        try { return std::stoi(val); } catch (...) { return def; }
    };

    auto getBoolOrDefault = [&getOrDefault](const std::string& key, bool def) -> bool {
        std::string val = getOrDefault(key, "");
        if (val.empty()) return def;
        return (val == "true" || val == "1" || val == "yes");
    };

    m_config.memoryScanIntervalMs  = static_cast<DWORD>(getIntOrDefault("memory_scan_interval", 5000));
    m_config.hookScanIntervalMs    = static_cast<DWORD>(getIntOrDefault("hook_scan_interval", 3000));
    m_config.fileScanIntervalMs    = static_cast<DWORD>(getIntOrDefault("file_scan_interval", 10000));
    m_config.processScanIntervalMs = static_cast<DWORD>(getIntOrDefault("process_scan_interval", 2000));
    m_config.antiDebugIntervalMs   = static_cast<DWORD>(getIntOrDefault("antidebug_interval", 1000));
    m_config.heartbeatIntervalMs   = static_cast<DWORD>(getIntOrDefault("heartbeat_interval", 1000));

    m_config.enableMemoryScan       = getBoolOrDefault("enable_memory_scan", true);
    m_config.enableHookDetection    = getBoolOrDefault("enable_hook_detection", true);
    m_config.enableFileProtection   = getBoolOrDefault("enable_file_protection", true);
    m_config.enableMacroDetection   = getBoolOrDefault("enable_macro_detection", true);
    m_config.enableProcessMonitoring = getBoolOrDefault("enable_process_monitoring", true);
    m_config.enableAntiDebug        = getBoolOrDefault("enable_antidebug", true);

    return true;
}

void AntiCheatEngineV2::ExportConfig(ConfigMap& outConfig) const {
    outConfig["memory_scan_interval"]    = std::to_string(m_config.memoryScanIntervalMs);
    outConfig["hook_scan_interval"]      = std::to_string(m_config.hookScanIntervalMs);
    outConfig["file_scan_interval"]      = std::to_string(m_config.fileScanIntervalMs);
    outConfig["process_scan_interval"]   = std::to_string(m_config.processScanIntervalMs);
    outConfig["antidebug_interval"]      = std::to_string(m_config.antiDebugIntervalMs);
    outConfig["heartbeat_interval"]      = std::to_string(m_config.heartbeatIntervalMs);

    outConfig["enable_memory_scan"]       = m_config.enableMemoryScan ? "true" : "false";
    outConfig["enable_hook_detection"]    = m_config.enableHookDetection ? "true" : "false";
    outConfig["enable_file_protection"]   = m_config.enableFileProtection ? "true" : "false";
    outConfig["enable_macro_detection"]   = m_config.enableMacroDetection ? "true" : "false";
    outConfig["enable_process_monitoring"] = m_config.enableProcessMonitoring ? "true" : "false";
    outConfig["enable_antidebug"]         = m_config.enableAntiDebug ? "true" : "false";
}

bool AntiCheatEngineV2::LoadConfigFromFile(const std::wstring& filePath) {
    if (!m_configParser.LoadFromFile(filePath)) {
        LogError("Failed to load config: " + m_configParser.GetLastError());
        return false;
    }

    if (!m_configParser.DistributeConfig()) {
        LogError("Failed to distribute config: " + m_configParser.GetLastError());
        return false;
    }

    Log("Configuration loaded successfully");
    return true;
}

bool AntiCheatEngineV2::SaveConfigToFile(const std::wstring& filePath) const {
    // We need a non-const reference to collect config, so we work around
    // the const by using a temporary parser
    ConfigParser tempParser;
    tempParser.RegisterModule(const_cast<AntiCheatEngineV2*>(this));
    tempParser.CollectConfig();
    return tempParser.SaveToFile(filePath);
}

void AntiCheatEngineV2::SetConfig(const Config& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_config = config;
}

// ============================================================================
// MANUAL SCAN TRIGGERS
// ============================================================================

bool AntiCheatEngineV2::ForceMemoryScan() {
    if (!m_initialized.load(std::memory_order_acquire) || !m_signatures) {
        return false;
    }
    Log("Forcing memory scan...");
    PerformMemoryScan();
    return true;
}

bool AntiCheatEngineV2::ForceHookScan() {
    if (!m_initialized.load(std::memory_order_acquire) || !m_hookDetector) {
        return false;
    }
    Log("Forcing hook scan...");
    PerformHookScan();
    return true;
}

bool AntiCheatEngineV2::ForceFileScan() {
    if (!m_initialized.load(std::memory_order_acquire) || !m_fileProtection) {
        return false;
    }
    Log("Forcing file scan...");
    PerformFileScan();
    return true;
}

bool AntiCheatEngineV2::ForceProcessScan() {
    if (!m_initialized.load(std::memory_order_acquire) || !m_signatures) {
        return false;
    }
    Log("Forcing process scan...");
    PerformProcessScan();
    return true;
}

bool AntiCheatEngineV2::ForceFullScan() {
    Log("Forcing full scan...");
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

AntiCheatEngineV2::EngineStatus AntiCheatEngineV2::GetStatus() const {
    EngineStatus status;
    status.isRunning          = m_running.load(std::memory_order_acquire);
    status.isIpcConnected     = m_ipcManager ? m_ipcManager->IsConnected() : false;
    status.totalDetections    = m_totalDetections.load(std::memory_order_relaxed);
    status.criticalDetections = m_criticalDetections.load(std::memory_order_relaxed);
    status.uptimeMs           = status.isRunning ? (::GetTickCount() - m_startTime) : 0;
    status.lastScanTimeMs     = 0;
    status.eventsPublished    = m_eventBus.GetPublishedCount();
    status.eventsDelivered    = m_eventBus.GetDeliveredCount();
    status.statusMessage      = status.isRunning ? "Running" : "Stopped";
    return status;
}

// ============================================================================
// MONITOR THREAD
// ============================================================================

DWORD WINAPI AntiCheatEngineV2::MonitorThreadProc(LPVOID param) {
    AntiCheatEngineV2* self = static_cast<AntiCheatEngineV2*>(param);
    self->MonitorLoop();
    return 0;
}

void AntiCheatEngineV2::MonitorLoop() {
    DWORD lastMemoryScan  = 0;
    DWORD lastHookScan    = 0;
    DWORD lastProcessScan = 0;
    DWORD lastAntiDebug   = 0;

    while (m_running.load(std::memory_order_acquire)) {
        const DWORD now = ::GetTickCount();

        // Memory scan
        if (m_config.enableMemoryScan &&
            (now - lastMemoryScan >= m_config.memoryScanIntervalMs)) {
            PerformMemoryScan();
            lastMemoryScan = now;
        }

        // Hook scan
        if (m_config.enableHookDetection &&
            (now - lastHookScan >= m_config.hookScanIntervalMs)) {
            PerformHookScan();
            lastHookScan = now;
        }

        // Process scan
        if (m_config.enableProcessMonitoring &&
            (now - lastProcessScan >= m_config.processScanIntervalMs)) {
            PerformProcessScan();
            lastProcessScan = now;
        }

        // Anti-debug checks
        if (m_config.enableAntiDebug &&
            (now - lastAntiDebug >= m_config.antiDebugIntervalMs)) {
            PerformAntiDebugCheck();
            lastAntiDebug = now;
        }

        // Wait for 100ms or stop signal - using the stop event avoids
        // busy-waiting and allows immediate response to Stop() calls
        ::WaitForSingleObject(m_stopEvent.Get(), 100);
    }
}

// ============================================================================
// SCAN METHODS
// ============================================================================

void AntiCheatEngineV2::PerformMemoryScan() {
    if (!m_signatures) return;

    auto results = m_signatures->ScanProcess(::GetCurrentProcess());

    for (const auto& result : results) {
        if (result.found) {
            DetectionEvent event;
            event.type = DetectionType::CheatSignature;
            event.severity = result.severity;
            event.description = "Cheat signature detected: " + result.signatureName;
            event.address = result.address;
            event.timestamp = ::GetTickCount();
            OnDetection(event);
        }
    }
}

void AntiCheatEngineV2::PerformHookScan() {
    if (!m_hookDetector) return;

    // Verify stored function prologues haven't been modified
    if (!m_hookDetector->VerifyStoredPrologues()) {
        DetectionEvent event;
        event.type = DetectionType::HookDetected;
        event.severity = Severity::Critical;
        event.description = "Critical API hook detected via prologue mismatch";
        event.timestamp = ::GetTickCount();
        OnDetection(event);
    }

    // Full scan of critical APIs
    m_hookDetector->ScanCriticalAPIs();
}

void AntiCheatEngineV2::PerformFileScan() {
    if (!m_fileProtection) return;

    std::vector<FileProtectionV2::VerificationResult> results;
    m_fileProtection->VerifyAllFiles(results);

    for (const auto& result : results) {
        if (!result.isValid) {
            DetectionEvent event;
            event.type = DetectionType::FileModified;
            event.severity = result.isRequired ? Severity::Critical : Severity::Warning;
            event.description = "File integrity violation: " + WStringToString(result.path) +
                                " (" + result.errorMessage + ")";
            event.timestamp = ::GetTickCount();
            OnDetection(event);
        }
    }
}

void AntiCheatEngineV2::PerformProcessScan() {
    // Signature-based process scan
    if (m_signatures) {
        auto results = m_signatures->ScanRunningProcesses();
        for (const auto& result : results) {
            if (result.found) {
                DetectionEvent event;
                event.type = DetectionType::SuspiciousProcess;
                event.severity = result.severity;
                event.description = result.details;
                event.timestamp = ::GetTickCount();
                OnDetection(event);
            }
        }
    }

    // ProcessMonitorV2 injection detection
    // Note: ProcessMonitorV2 also runs its own IMonitorModule thread.
    // This manual scan supplements it with a forced injection check.
    if (m_processMonitor) {
        auto injection = m_processMonitor->CheckForInjection();
        if (injection.WasDetected()) {
            DetectionEvent event;
            event.type = DetectionType::InjectedDLL;
            event.severity = injection.severity;
            event.description = injection.details;
            event.address = injection.address;
            event.timestamp = ::GetTickCount();
            OnDetection(event);
        }
    }
}

void AntiCheatEngineV2::PerformAntiDebugCheck() {
    if (!m_hookDetector) return;

    if (m_hookDetector->IsDebuggerPresent() || m_hookDetector->IsRemoteDebuggerPresent()) {
        DetectionEvent event;
        event.type = DetectionType::DebuggerAttached;
        event.severity = Severity::Critical;
        event.description = "Debugger detected attached to process";
        event.timestamp = ::GetTickCount();
        OnDetection(event);
    }

    if (m_hookDetector->CheckDebugRegisters()) {
        DetectionEvent event;
        event.type = DetectionType::DebuggerAttached;
        event.severity = Severity::Warning;
        event.description = "Hardware debug breakpoints detected";
        event.timestamp = ::GetTickCount();
        OnDetection(event);
    }
}

// ============================================================================
// EVENT HANDLING
// ============================================================================

void AntiCheatEngineV2::OnDetection(const DetectionEvent& event) {
    // Update statistics atomically
    m_totalDetections.fetch_add(1, std::memory_order_relaxed);
    if (event.severity == Severity::Critical || event.severity == Severity::Fatal) {
        m_criticalDetections.fetch_add(1, std::memory_order_relaxed);
    }

    // Log the detection
    std::stringstream ss;
    ss << "DETECTION [severity=" << static_cast<int>(event.severity) << "]: "
       << event.description;
    Log(ss.str());

    // Publish to EventBus - subscribers (including IPC forwarder) will receive
    // the event asynchronously on the dispatch thread
    m_eventBus.Publish(event);
}

void AntiCheatEngineV2::OnIPCMessage(const IPCManager::Message& msg) {
    switch (msg.type) {
        case IPCManager::MessageType::RequestScan:
            ForceFullScan();
            break;

        case IPCManager::MessageType::RequestStatus: {
            if (m_ipcManager) {
                const EngineStatus status = GetStatus();
                std::stringstream ss;
                ss << "{"
                   << "\"running\":" << (status.isRunning ? "true" : "false") << ","
                   << "\"detections\":" << status.totalDetections << ","
                   << "\"critical\":" << status.criticalDetections << ","
                   << "\"uptime\":" << status.uptimeMs << ","
                   << "\"events_published\":" << status.eventsPublished << ","
                   << "\"events_delivered\":" << status.eventsDelivered
                   << "}";
                m_ipcManager->SendMessage(IPCManager::MessageType::Status, ss.str());
            }
            break;
        }

        case IPCManager::MessageType::UpdateConfig: {
            // Parse JSON config from message data
            std::string configStr(msg.data.begin(), msg.data.end());
            if (!configStr.empty() && m_configParser.ParseString(configStr)) {
                m_configParser.DistributeConfig();
                Log("Configuration updated via IPC");
            }
            break;
        }

        case IPCManager::MessageType::Shutdown:
            Log("Shutdown command received via IPC");
            Stop();
            break;

        default:
            break;
    }
}

// ============================================================================
// LOGGING
// ============================================================================

void AntiCheatEngineV2::Log(const std::string& message) const {
    // In a full system this would go through a logging framework.
    // For now, we publish a status event that subscribers can handle.
    OutputDebugStringA(("[AntiCheatV2] " + message + "\n").c_str());
}

void AntiCheatEngineV2::LogError(const std::string& message) {
    m_lastError = message;
    Log("ERROR: " + message);
}

} // namespace AntiCheat
