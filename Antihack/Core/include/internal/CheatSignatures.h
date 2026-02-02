/**
 * AntiCheatCore - Cheat Signatures Database
 * Pattern-based detection of known cheats and hacks
 */

#pragma once

#ifndef AC_CHEAT_SIGNATURES_H
#define AC_CHEAT_SIGNATURES_H

#include "common.h"

namespace AntiCheat {

class CheatSignatures {
public:
    struct Signature {
        std::string name;
        std::string category;      // "aimbot", "wallhack", "speedhack", etc.
        ByteVector pattern;
        ByteVector mask;           // 0xFF = must match, 0x00 = wildcard
        Severity severity;
        std::string description;
        bool enabled;

        Signature() : severity(Severity::Critical), enabled(true) {}
    };

    struct ProcessSignature {
        std::string name;
        std::wstring processName;
        std::wstring windowClass;
        std::wstring windowTitle;
        Severity severity;
        bool enabled;

        ProcessSignature() : severity(Severity::Warning), enabled(true) {}
    };

    struct ModuleSignature {
        std::string name;
        std::wstring moduleName;
        uint32_t expectedSize;     // 0 = any size
        uint32_t crcHash;          // 0 = don't check
        Severity severity;
        bool enabled;

        ModuleSignature() : expectedSize(0), crcHash(0), severity(Severity::Critical), enabled(true) {}
    };

    struct MatchResult {
        bool found;
        std::string signatureName;
        std::string category;
        Severity severity;
        void* address;
        std::string moduleName;
        std::string details;
    };

private:
    std::vector<Signature> m_memorySignatures;
    std::vector<ProcessSignature> m_processSignatures;
    std::vector<ModuleSignature> m_moduleSignatures;
    std::mutex m_mutex;
    std::string m_lastError;
    bool m_initialized;

    // Pattern matching
    bool MatchPattern(const uint8_t* data, size_t dataSize,
                      const ByteVector& pattern, const ByteVector& mask);
    void* FindPatternInRange(void* start, size_t size,
                             const ByteVector& pattern, const ByteVector& mask);

    // Signature parsing
    ByteVector ParsePatternString(const std::string& pattern);
    ByteVector GenerateMaskFromPattern(const std::string& pattern);

public:
    CheatSignatures();
    ~CheatSignatures();

    // Initialization
    bool Initialize();
    void Shutdown();

    // Memory signatures
    void AddSignature(const Signature& sig);
    void AddSignature(const std::string& name, const std::string& category,
                      const std::string& pattern, Severity severity = Severity::Critical);
    void AddSignatureHex(const std::string& name, const std::string& category,
                         const ByteVector& pattern, const ByteVector& mask,
                         Severity severity = Severity::Critical);

    // Process signatures
    void AddProcessSignature(const ProcessSignature& sig);
    void AddProcessSignature(const std::string& name, const std::wstring& processName,
                             Severity severity = Severity::Warning);

    // Module signatures
    void AddModuleSignature(const ModuleSignature& sig);
    void AddModuleSignature(const std::string& name, const std::wstring& moduleName,
                            Severity severity = Severity::Critical);

    // Scanning
    std::vector<MatchResult> ScanMemory(void* address, size_t size);
    std::vector<MatchResult> ScanProcess(HANDLE process = nullptr);
    std::vector<MatchResult> ScanModules();
    std::vector<MatchResult> ScanRunningProcesses();
    std::vector<MatchResult> ScanAll();

    // Individual checks
    MatchResult CheckMemoryForSignature(void* address, size_t size, const Signature& sig);
    MatchResult CheckProcess(DWORD processId);
    MatchResult CheckModule(HMODULE module);

    // Signature management
    bool LoadSignaturesFromFile(const std::wstring& path);
    bool SaveSignaturesToFile(const std::wstring& path);
    void ClearAllSignatures();
    void EnableSignature(const std::string& name, bool enable = true);
    void EnableCategory(const std::string& category, bool enable = true);

    // Built-in signatures (common cheats)
    void LoadDefaultSignatures();

    // Getters
    int GetMemorySignatureCount() const { return static_cast<int>(m_memorySignatures.size()); }
    int GetProcessSignatureCount() const { return static_cast<int>(m_processSignatures.size()); }
    int GetModuleSignatureCount() const { return static_cast<int>(m_moduleSignatures.size()); }
    const std::string& GetLastError() const { return m_lastError; }
    bool IsInitialized() const { return m_initialized; }
};

} // namespace AntiCheat

#endif // AC_CHEAT_SIGNATURES_H
