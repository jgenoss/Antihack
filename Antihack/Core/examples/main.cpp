/**
 * AntiCheatCore V2 - Usage Example
 *
 * Demonstrates the refactored architecture:
 *   - Meyer's Singleton for AntiCheatEngineV2
 *   - EventBus subscription for detection notifications
 *   - IConfigurable modules with ConfigParser
 *   - FileProtectionV2 with IMonitorModule integration
 *   - EncryptionLibV2 with RAII CryptoAPI
 *   - ProcessMonitorV2 with proper IMonitorModule inheritance
 *   - HandleGuard RAII for Windows handles
 *
 * Build: cl /std:c++17 /EHsc main.cpp ../src/*.cpp /I../include
 *        /link kernel32.lib user32.lib advapi32.lib psapi.lib
 *        wintrust.lib shlwapi.lib crypt32.lib
 */

#include <Windows.h>
#include <iostream>
#include <string>

// V2 Architecture headers
#include "../include/internal/AntiCheatEngineV2.hpp"
#include "../include/internal/ProcessMonitorV2.hpp"
#include "../include/internal/FileProtectionV2.hpp"
#include "../include/internal/EncryptionLibV2.hpp"
#include "../include/internal/EventBus.hpp"
#include "../include/internal/ConfigParser.hpp"
#include "../include/internal/HandleGuard.hpp"

using namespace AntiCheat;

// ============================================================================
// HELPER: Print a detection event to the console
// ============================================================================

static void PrintDetection(const DetectionEvent& event) {
    const char* severityStr = "UNKNOWN";
    switch (event.severity) {
        case Severity::Info:     severityStr = "INFO";     break;
        case Severity::Warning:  severityStr = "WARNING";  break;
        case Severity::Critical: severityStr = "CRITICAL"; break;
        case Severity::Fatal:    severityStr = "FATAL";    break;
    }

    std::cout << "[" << severityStr << "] " << event.description << std::endl;
}

// ============================================================================
// EXAMPLE 1: HandleGuard RAII demonstration
// ============================================================================

static void DemoHandleGuard() {
    std::cout << "\n=== HandleGuard RAII Demo ===" << std::endl;

    // Create an event handle - automatically cleaned up when it goes out of scope
    {
        KernelHandle event = MakeEvent(true, false);
        if (event) {
            std::cout << "  Event handle created successfully (RAII managed)" << std::endl;
            ::SetEvent(event.Get());
            std::cout << "  Event signaled" << std::endl;
        }
        // Handle is automatically closed here - no CloseHandle needed
    }
    std::cout << "  Handle automatically released on scope exit" << std::endl;

    // Snapshot handle with FileHandle policy
    {
        FileHandle snapshot = MakeSnapshot(TH32CS_SNAPPROCESS);
        if (snapshot) {
            std::cout << "  Process snapshot created (RAII managed)" << std::endl;
        }
        // Snapshot closed automatically
    }
    std::cout << "  Snapshot released automatically" << std::endl;
}

// ============================================================================
// EXAMPLE 2: EventBus pub/sub demonstration
// ============================================================================

static void DemoEventBus() {
    std::cout << "\n=== EventBus Demo ===" << std::endl;

    EventBus bus;
    bus.Start();

    // Subscribe a logger
    auto logSubId = bus.Subscribe([](const DetectionEvent& e) {
        std::cout << "  [Logger] Received: " << e.description << std::endl;
    });

    // Subscribe a counter
    int detectionCount = 0;
    auto countSubId = bus.Subscribe([&detectionCount](const DetectionEvent& e) {
        detectionCount++;
    });

    // Publish some events
    DetectionEvent evt1;
    evt1.type = DetectionType::SuspiciousProcess;
    evt1.severity = Severity::Warning;
    evt1.description = "Test process detection";
    evt1.timestamp = ::GetTickCount();

    DetectionEvent evt2;
    evt2.type = DetectionType::HookDetected;
    evt2.severity = Severity::Critical;
    evt2.description = "Test hook detection";
    evt2.timestamp = ::GetTickCount();

    bus.Publish(evt1);
    bus.Publish(evt2);

    // Give the dispatch thread a moment to deliver
    ::Sleep(200);

    std::cout << "  Published: " << bus.GetPublishedCount()
              << ", Delivered: " << bus.GetDeliveredCount() << std::endl;

    // Unsubscribe and stop
    bus.Unsubscribe(logSubId);
    bus.Unsubscribe(countSubId);
    bus.Stop(true);

    std::cout << "  Total detections counted: " << detectionCount << std::endl;
}

// ============================================================================
// EXAMPLE 3: ConfigParser demonstration
// ============================================================================

static void DemoConfigParser() {
    std::cout << "\n=== ConfigParser Demo ===" << std::endl;

    ConfigParser parser;

    // Parse INI content from string
    const std::string iniContent =
        "[Engine]\n"
        "memory_scan_interval = 5000\n"
        "hook_scan_interval = 3000\n"
        "enable_memory_scan = true\n"
        "enable_antidebug = true\n"
        "\n"
        "[ProcessMonitor]\n"
        "scan_interval = 2000\n"
        "suspicious_patterns = inject,hook,cheat,trainer\n"
        "\n"
        "[FileProtection]\n"
        "scan_interval = 10000\n"
        "base_path = C:\\Games\\MyGame\n";

    if (parser.ParseString(iniContent)) {
        std::cout << "  Parsed successfully" << std::endl;
        std::cout << "  Engine.memory_scan_interval = "
                  << parser.GetInt("Engine", "memory_scan_interval", 0) << std::endl;
        std::cout << "  Engine.enable_antidebug = "
                  << (parser.GetBool("Engine", "enable_antidebug", false) ? "true" : "false")
                  << std::endl;
        std::cout << "  ProcessMonitor.scan_interval = "
                  << parser.GetInt("ProcessMonitor", "scan_interval", 0) << std::endl;
    }
}

// ============================================================================
// EXAMPLE 4: EncryptionLibV2 RAII demonstration
// ============================================================================

static void DemoEncryption() {
    std::cout << "\n=== EncryptionLibV2 Demo ===" << std::endl;

    EncryptionLibV2 crypto;

    if (!crypto.Initialize()) {
        std::cout << "  ERROR: " << crypto.GetLastError() << std::endl;
        return;
    }
    std::cout << "  CryptoAPI provider initialized (RAII managed)" << std::endl;

    // Generate a secure random key
    ByteVector key;
    if (!crypto.GenerateKey(key)) {
        std::cout << "  ERROR: Key generation failed" << std::endl;
        return;
    }
    std::cout << "  Generated AES-256 key (" << key.size() << " bytes)" << std::endl;

    // Set the key
    if (!crypto.SetKey(key)) {
        std::cout << "  ERROR: " << crypto.GetLastError() << std::endl;
        return;
    }
    std::cout << "  Key imported into CryptoAPI" << std::endl;

    // Encrypt some data
    std::string message = "Hello from AntiCheatCore V2! This is a test message.";
    ByteVector plaintext(message.begin(), message.end());
    ByteVector encrypted;

    if (crypto.Encrypt(plaintext, encrypted)) {
        std::cout << "  Encrypted " << plaintext.size() << " bytes -> "
                  << encrypted.size() << " bytes" << std::endl;
    }

    // Decrypt it back
    ByteVector decrypted;
    if (crypto.Decrypt(encrypted, decrypted)) {
        std::string result(decrypted.begin(), decrypted.end());
        std::cout << "  Decrypted: \"" << result << "\"" << std::endl;
        std::cout << "  Match: " << (result == message ? "YES" : "NO") << std::endl;
    }

    // RAII: crypto handles released automatically when crypto goes out of scope
    std::cout << "  CryptoAPI handles will be released automatically" << std::endl;
}

// ============================================================================
// EXAMPLE 5: ProcessMonitorV2 with IMonitorModule
// ============================================================================

static void DemoProcessMonitor() {
    std::cout << "\n=== ProcessMonitorV2 Demo ===" << std::endl;

    ProcessMonitorV2 monitor;

    if (!monitor.Initialize()) {
        std::cout << "  ERROR: " << monitor.GetLastError() << std::endl;
        return;
    }
    std::cout << "  ProcessMonitorV2 initialized" << std::endl;

    // Capture baseline
    monitor.CaptureBaseline();
    std::cout << "  Baseline captured: "
              << monitor.GetBaselineModuleCount() << " modules, "
              << monitor.GetBaselineThreadCount() << " threads" << std::endl;

    // Set detection callback (integrated with IMonitorModule's QueueEvent)
    monitor.SetDetectionCallback([](const DetectionEvent& e) {
        PrintDetection(e);
    });

    // List loaded modules
    auto modules = monitor.GetLoadedModules();
    std::cout << "  Loaded modules:" << std::endl;
    int shown = 0;
    for (const auto& mod : modules) {
        if (shown >= 5) {
            std::cout << "  ... and " << (modules.size() - 5) << " more" << std::endl;
            break;
        }
        std::wcout << L"    - " << mod.name
                   << (mod.isTrusted ? L" [trusted]" : L"")
                   << (mod.isSigned ? L" [signed]" : L"") << std::endl;
        shown++;
    }

    // Start monitoring (uses IMonitorModule's thread management)
    if (monitor.StartMonitoring(2000)) {
        std::cout << "  Monitoring started (2s interval, below-normal priority)" << std::endl;
        std::cout << "  Module state: " << static_cast<int>(monitor.GetState()) << std::endl;

        // Let it run for a few seconds
        ::Sleep(3000);

        monitor.StopMonitoring();
        std::cout << "  Monitoring stopped" << std::endl;
    }

    monitor.Shutdown();
    std::cout << "  ProcessMonitorV2 shut down cleanly" << std::endl;
}

// ============================================================================
// EXAMPLE 6: Full engine integration
// ============================================================================

static void DemoFullEngine() {
    std::cout << "\n=== AntiCheatEngineV2 Full Demo ===" << std::endl;

    // Get singleton instance (Meyer's - no raw new/delete)
    auto& engine = AntiCheatEngineV2::GetInstance();

    // Subscribe to EventBus for detection notifications
    auto subId = engine.GetEventBus().Subscribe([](const DetectionEvent& e) {
        std::cout << "  [EventBus] ";
        PrintDetection(e);
    });

    // Configure the engine
    AntiCheatEngineV2::Config config;
    config.memoryScanIntervalMs  = 5000;
    config.hookScanIntervalMs    = 3000;
    config.processScanIntervalMs = 2000;
    config.enableFileProtection  = false;  // No game files to protect in demo
    config.enableMacroDetection  = false;  // No input hooks in console demo

    // Initialize
    if (!engine.Initialize(config)) {
        std::cout << "  ERROR: " << engine.GetLastError() << std::endl;
        return;
    }
    std::cout << "  Engine initialized" << std::endl;

    // Start the engine
    if (!engine.Start()) {
        std::cout << "  ERROR: " << engine.GetLastError() << std::endl;
        return;
    }
    std::cout << "  Engine started" << std::endl;

    // Let it run for a few seconds
    std::cout << "  Running for 5 seconds..." << std::endl;
    ::Sleep(5000);

    // Query status
    auto status = engine.GetStatus();
    std::cout << "  Status: " << status.statusMessage << std::endl;
    std::cout << "  Uptime: " << status.uptimeMs << " ms" << std::endl;
    std::cout << "  Detections: " << status.totalDetections
              << " (critical: " << status.criticalDetections << ")" << std::endl;
    std::cout << "  Events published: " << status.eventsPublished
              << ", delivered: " << status.eventsDelivered << std::endl;

    // Stop and shutdown
    engine.Stop();
    std::cout << "  Engine stopped" << std::endl;

    engine.GetEventBus().Unsubscribe(subId);
    engine.Shutdown();
    std::cout << "  Engine shut down cleanly" << std::endl;
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << " AntiCheatCore V2 Architecture Examples" << std::endl;
    std::cout << "========================================" << std::endl;

    // Individual component demonstrations
    DemoHandleGuard();
    DemoEventBus();
    DemoConfigParser();
    DemoEncryption();
    DemoProcessMonitor();

    // Full integration
    DemoFullEngine();

    std::cout << "\n========================================" << std::endl;
    std::cout << " All demos completed successfully" << std::endl;
    std::cout << "========================================" << std::endl;

    return 0;
}
