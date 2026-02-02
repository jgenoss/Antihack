/**
 * AntiCheatCore - Cheat Signatures Implementation
 * Pattern-based detection of known cheats and hacks
 */

#include "../include/internal/CheatSignatures.h"
#include <fstream>
#include <sstream>
#include <TlHelp32.h>

namespace AntiCheat {

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

CheatSignatures::CheatSignatures()
    : m_initialized(false) {
}

CheatSignatures::~CheatSignatures() {
    Shutdown();
}

// ============================================================================
// INITIALIZATION
// ============================================================================

bool CheatSignatures::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_initialized = true;
    LoadDefaultSignatures();
    return true;
}

void CheatSignatures::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    ClearAllSignatures();
    m_initialized = false;
}

// ============================================================================
// SIGNATURE MANAGEMENT
// ============================================================================

void CheatSignatures::AddSignature(const Signature& sig) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_memorySignatures.push_back(sig);
}

void CheatSignatures::AddSignature(const std::string& name, const std::string& category,
                                    const std::string& pattern, Severity severity) {
    Signature sig;
    sig.name = name;
    sig.category = category;
    sig.pattern = ParsePatternString(pattern);
    sig.mask = GenerateMaskFromPattern(pattern);
    sig.severity = severity;
    sig.enabled = true;

    AddSignature(sig);
}

void CheatSignatures::AddSignatureHex(const std::string& name, const std::string& category,
                                       const ByteVector& pattern, const ByteVector& mask,
                                       Severity severity) {
    Signature sig;
    sig.name = name;
    sig.category = category;
    sig.pattern = pattern;
    sig.mask = mask;
    sig.severity = severity;
    sig.enabled = true;

    AddSignature(sig);
}

void CheatSignatures::AddProcessSignature(const ProcessSignature& sig) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_processSignatures.push_back(sig);
}

void CheatSignatures::AddProcessSignature(const std::string& name, const std::wstring& processName,
                                           Severity severity) {
    ProcessSignature sig;
    sig.name = name;
    sig.processName = processName;
    sig.severity = severity;
    sig.enabled = true;

    AddProcessSignature(sig);
}

void CheatSignatures::AddModuleSignature(const ModuleSignature& sig) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_moduleSignatures.push_back(sig);
}

void CheatSignatures::AddModuleSignature(const std::string& name, const std::wstring& moduleName,
                                          Severity severity) {
    ModuleSignature sig;
    sig.name = name;
    sig.moduleName = moduleName;
    sig.severity = severity;
    sig.enabled = true;

    AddModuleSignature(sig);
}

void CheatSignatures::ClearAllSignatures() {
    m_memorySignatures.clear();
    m_processSignatures.clear();
    m_moduleSignatures.clear();
}

void CheatSignatures::EnableSignature(const std::string& name, bool enable) {
    std::lock_guard<std::mutex> lock(m_mutex);

    for (auto& sig : m_memorySignatures) {
        if (sig.name == name) sig.enabled = enable;
    }
    for (auto& sig : m_processSignatures) {
        if (sig.name == name) sig.enabled = enable;
    }
    for (auto& sig : m_moduleSignatures) {
        if (sig.name == name) sig.enabled = enable;
    }
}

void CheatSignatures::EnableCategory(const std::string& category, bool enable) {
    std::lock_guard<std::mutex> lock(m_mutex);

    for (auto& sig : m_memorySignatures) {
        if (sig.category == category) sig.enabled = enable;
    }
}

// ============================================================================
// PATTERN PARSING
// ============================================================================

ByteVector CheatSignatures::ParsePatternString(const std::string& pattern) {
    ByteVector bytes;
    std::istringstream iss(pattern);
    std::string token;

    while (iss >> token) {
        if (token == "?" || token == "??") {
            bytes.push_back(0x00);
        } else {
            bytes.push_back(static_cast<uint8_t>(std::stoul(token, nullptr, 16)));
        }
    }

    return bytes;
}

ByteVector CheatSignatures::GenerateMaskFromPattern(const std::string& pattern) {
    ByteVector mask;
    std::istringstream iss(pattern);
    std::string token;

    while (iss >> token) {
        if (token == "?" || token == "??") {
            mask.push_back(0x00);
        } else {
            mask.push_back(0xFF);
        }
    }

    return mask;
}

// ============================================================================
// PATTERN MATCHING
// ============================================================================

bool CheatSignatures::MatchPattern(const uint8_t* data, size_t dataSize,
                                    const ByteVector& pattern, const ByteVector& mask) {
    if (dataSize < pattern.size()) return false;

    for (size_t i = 0; i < pattern.size(); i++) {
        if (mask[i] != 0x00 && (data[i] & mask[i]) != (pattern[i] & mask[i])) {
            return false;
        }
    }

    return true;
}

void* CheatSignatures::FindPatternInRange(void* start, size_t size,
                                           const ByteVector& pattern, const ByteVector& mask) {
    if (!start || size == 0 || pattern.empty()) return nullptr;

    uint8_t* data = static_cast<uint8_t*>(start);
    size_t scanEnd = size - pattern.size();

    for (size_t i = 0; i <= scanEnd; i++) {
        if (MatchPattern(data + i, pattern.size(), pattern, mask)) {
            return data + i;
        }
    }

    return nullptr;
}

// ============================================================================
// SCANNING
// ============================================================================

CheatSignatures::MatchResult CheatSignatures::CheckMemoryForSignature(
    void* address, size_t size, const Signature& sig) {

    MatchResult result = {};
    result.found = false;

    if (!sig.enabled) return result;

    void* match = FindPatternInRange(address, size, sig.pattern, sig.mask);
    if (match) {
        result.found = true;
        result.signatureName = sig.name;
        result.category = sig.category;
        result.severity = sig.severity;
        result.address = match;
        result.details = "Pattern matched at address";
    }

    return result;
}

std::vector<CheatSignatures::MatchResult> CheatSignatures::ScanMemory(void* address, size_t size) {
    std::vector<MatchResult> results;

    std::lock_guard<std::mutex> lock(m_mutex);

    for (const Signature& sig : m_memorySignatures) {
        if (!sig.enabled) continue;

        MatchResult result = CheckMemoryForSignature(address, size, sig);
        if (result.found) {
            results.push_back(result);
        }
    }

    return results;
}

std::vector<CheatSignatures::MatchResult> CheatSignatures::ScanProcess(HANDLE process) {
    std::vector<MatchResult> results;

    if (!process) process = GetCurrentProcess();

    MEMORY_BASIC_INFORMATION mbi;
    void* address = nullptr;

    while (VirtualQueryEx(process, address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READWRITE))) {

            std::vector<uint8_t> buffer(mbi.RegionSize);
            SIZE_T bytesRead;

            if (ReadProcessMemory(process, mbi.BaseAddress, buffer.data(),
                                  mbi.RegionSize, &bytesRead)) {

                auto regionResults = ScanMemory(buffer.data(), bytesRead);
                for (auto& r : regionResults) {
                    // Adjust address to actual process address
                    r.address = reinterpret_cast<void*>(
                        reinterpret_cast<uintptr_t>(mbi.BaseAddress) +
                        (reinterpret_cast<uintptr_t>(r.address) -
                         reinterpret_cast<uintptr_t>(buffer.data())));
                    results.push_back(r);
                }
            }
        }

        address = reinterpret_cast<void*>(
            reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize);
    }

    return results;
}

std::vector<CheatSignatures::MatchResult> CheatSignatures::ScanModules() {
    std::vector<MatchResult> results;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return results;

    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);

    std::lock_guard<std::mutex> lock(m_mutex);

    if (Module32FirstW(snapshot, &me32)) {
        do {
            std::wstring moduleName = me32.szModule;
            std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::towlower);

            for (const ModuleSignature& sig : m_moduleSignatures) {
                if (!sig.enabled) continue;

                std::wstring sigName = sig.moduleName;
                std::transform(sigName.begin(), sigName.end(), sigName.begin(), ::towlower);

                if (moduleName.find(sigName) != std::wstring::npos) {
                    MatchResult result;
                    result.found = true;
                    result.signatureName = sig.name;
                    result.category = "module";
                    result.severity = sig.severity;
                    result.address = me32.modBaseAddr;
                    result.moduleName = WStringToString(me32.szModule);
                    result.details = "Suspicious module loaded";
                    results.push_back(result);
                }
            }
        } while (Module32NextW(snapshot, &me32));
    }

    CloseHandle(snapshot);
    return results;
}

std::vector<CheatSignatures::MatchResult> CheatSignatures::ScanRunningProcesses() {
    std::vector<MatchResult> results;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return results;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    std::lock_guard<std::mutex> lock(m_mutex);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            std::wstring processName = pe32.szExeFile;
            std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);

            for (const ProcessSignature& sig : m_processSignatures) {
                if (!sig.enabled) continue;

                std::wstring sigName = sig.processName;
                std::transform(sigName.begin(), sigName.end(), sigName.begin(), ::towlower);

                if (processName.find(sigName) != std::wstring::npos) {
                    MatchResult result;
                    result.found = true;
                    result.signatureName = sig.name;
                    result.category = "process";
                    result.severity = sig.severity;
                    result.address = nullptr;
                    result.details = "Suspicious process running: " + WStringToString(pe32.szExeFile);
                    results.push_back(result);
                }
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return results;
}

std::vector<CheatSignatures::MatchResult> CheatSignatures::ScanAll() {
    std::vector<MatchResult> results;

    // Scan processes
    auto procResults = ScanRunningProcesses();
    results.insert(results.end(), procResults.begin(), procResults.end());

    // Scan modules
    auto modResults = ScanModules();
    results.insert(results.end(), modResults.begin(), modResults.end());

    // Scan current process memory
    auto memResults = ScanProcess(GetCurrentProcess());
    results.insert(results.end(), memResults.begin(), memResults.end());

    return results;
}

CheatSignatures::MatchResult CheatSignatures::CheckProcess(DWORD processId) {
    MatchResult result = {};

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == processId) {
                std::wstring processName = pe32.szExeFile;
                std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);

                std::lock_guard<std::mutex> lock(m_mutex);
                for (const ProcessSignature& sig : m_processSignatures) {
                    if (!sig.enabled) continue;

                    std::wstring sigName = sig.processName;
                    std::transform(sigName.begin(), sigName.end(), sigName.begin(), ::towlower);

                    if (processName.find(sigName) != std::wstring::npos) {
                        result.found = true;
                        result.signatureName = sig.name;
                        result.severity = sig.severity;
                        break;
                    }
                }
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return result;
}

CheatSignatures::MatchResult CheatSignatures::CheckModule(HMODULE module) {
    MatchResult result = {};

    wchar_t modulePath[MAX_PATH];
    if (!GetModuleFileNameW(module, modulePath, MAX_PATH)) return result;

    std::wstring moduleName = modulePath;
    std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::towlower);

    std::lock_guard<std::mutex> lock(m_mutex);
    for (const ModuleSignature& sig : m_moduleSignatures) {
        if (!sig.enabled) continue;

        std::wstring sigName = sig.moduleName;
        std::transform(sigName.begin(), sigName.end(), sigName.begin(), ::towlower);

        if (moduleName.find(sigName) != std::wstring::npos) {
            result.found = true;
            result.signatureName = sig.name;
            result.severity = sig.severity;
            result.moduleName = WStringToString(modulePath);
            break;
        }
    }

    return result;
}

// ============================================================================
// CONFIG FILE
// ============================================================================

bool CheatSignatures::LoadSignaturesFromFile(const std::wstring& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        m_lastError = "Cannot open signatures file";
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::istringstream iss(line);
        std::string type, name, category, pattern;

        if (std::getline(iss, type, '|') &&
            std::getline(iss, name, '|') &&
            std::getline(iss, category, '|') &&
            std::getline(iss, pattern)) {

            if (type == "memory") {
                AddSignature(name, category, pattern, Severity::Critical);
            } else if (type == "process") {
                AddProcessSignature(name, StringToWString(pattern), Severity::Warning);
            } else if (type == "module") {
                AddModuleSignature(name, StringToWString(pattern), Severity::Critical);
            }
        }
    }

    return true;
}

bool CheatSignatures::SaveSignaturesToFile(const std::wstring& path) {
    std::ofstream file(path);
    if (!file.is_open()) {
        m_lastError = "Cannot create signatures file";
        return false;
    }

    file << "# AntiCheat Signatures Database\n";
    file << "# Format: type|name|category|pattern\n\n";

    std::lock_guard<std::mutex> lock(m_mutex);

    for (const auto& sig : m_memorySignatures) {
        file << "memory|" << sig.name << "|" << sig.category << "|";
        for (size_t i = 0; i < sig.pattern.size(); i++) {
            if (sig.mask[i] == 0x00) {
                file << "?? ";
            } else {
                file << std::hex << std::uppercase << static_cast<int>(sig.pattern[i]) << " ";
            }
        }
        file << "\n";
    }

    for (const auto& sig : m_processSignatures) {
        file << "process|" << sig.name << "|process|" << WStringToString(sig.processName) << "\n";
    }

    for (const auto& sig : m_moduleSignatures) {
        file << "module|" << sig.name << "|module|" << WStringToString(sig.moduleName) << "\n";
    }

    return file.good();
}

// ============================================================================
// DEFAULT SIGNATURES
// ============================================================================

void CheatSignatures::LoadDefaultSignatures() {
    // Common cheat tool processes
    AddProcessSignature("Cheat Engine", L"cheatengine", Severity::Critical);
    AddProcessSignature("Cheat Engine", L"ce-x64.exe", Severity::Critical);
    AddProcessSignature("Cheat Engine", L"ce-x32.exe", Severity::Critical);
    AddProcessSignature("ArtMoney", L"artmoney", Severity::Critical);
    AddProcessSignature("WPE Pro", L"wpe pro", Severity::Critical);
    AddProcessSignature("OllyDbg", L"ollydbg", Severity::Warning);
    AddProcessSignature("x64dbg", L"x64dbg", Severity::Warning);
    AddProcessSignature("x32dbg", L"x32dbg", Severity::Warning);
    AddProcessSignature("IDA Pro", L"ida", Severity::Warning);
    AddProcessSignature("Wireshark", L"wireshark", Severity::Info);

    // Common injection DLLs
    AddModuleSignature("Generic Injector", L"inject", Severity::Warning);
    AddModuleSignature("Hook Library", L"hook", Severity::Warning);
    AddModuleSignature("Trainer Module", L"trainer", Severity::Critical);

    // Memory patterns for common cheats
    // Aimbot pattern (generic targeting loop)
    AddSignature("Generic Aimbot", "aimbot",
                 "8B 45 ? 8B 4D ? 2B C1 89 45 ? 8B 55 ? 8B 45 ? 2B D0",
                 Severity::Critical);

    // Speed hack (time manipulation)
    AddSignature("Speed Hack", "speedhack",
                 "C7 05 ? ? ? ? ? ? ? ? E9 ? ? ? ?",
                 Severity::Critical);

    // Wallhack (depth buffer manipulation)
    AddSignature("Wallhack Pattern", "wallhack",
                 "8B ? ? 83 ? ? 0F 84 ? ? ? ? 8B",
                 Severity::Critical);
}

} // namespace AntiCheat
