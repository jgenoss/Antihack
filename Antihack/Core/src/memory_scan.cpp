/**
 * Memory Pattern Scanner Module
 * Detects cheat signatures and memory modifications
 */

#include "../include/anticheat_core.h"
#include <Windows.h>
#include <vector>
#include <string>
#include <algorithm>

// Pattern structure
struct MemoryPattern {
    std::string name;
    std::vector<BYTE> pattern;
    std::vector<bool> mask;  // true = must match, false = wildcard
};

// Known cheat patterns database
static std::vector<MemoryPattern> g_cheatPatterns;
static char g_lastPatternError[256] = "";

// Common cheat signatures (obfuscated for security)
static void InitDefaultPatterns() {
    // Cheat Engine signature patterns
    MemoryPattern ce;
    ce.name = "CheatEngine";
    ce.pattern = { 0x43, 0x68, 0x65, 0x61, 0x74, 0x45, 0x6E, 0x67, 0x69, 0x6E, 0x65 };
    ce.mask = std::vector<bool>(ce.pattern.size(), true);
    g_cheatPatterns.push_back(ce);

    // Speed hack pattern (common timer manipulation)
    MemoryPattern speedhack;
    speedhack.name = "SpeedHack";
    speedhack.pattern = { 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x15 };
    speedhack.mask = { true, true, false, false, false, false, true, true };
    g_cheatPatterns.push_back(speedhack);

    // ArtMoney signature
    MemoryPattern artmoney;
    artmoney.name = "ArtMoney";
    artmoney.pattern = { 0x41, 0x72, 0x74, 0x4D, 0x6F, 0x6E, 0x65, 0x79 };
    artmoney.mask = std::vector<bool>(artmoney.pattern.size(), true);
    g_cheatPatterns.push_back(artmoney);

    // Trainer pattern (common NOP sled)
    MemoryPattern trainer;
    trainer.name = "TrainerNOP";
    trainer.pattern = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    trainer.mask = std::vector<bool>(trainer.pattern.size(), true);
    g_cheatPatterns.push_back(trainer);
}

// Compare memory with pattern
static bool MatchPattern(const BYTE* memory, const MemoryPattern& pattern) {
    for (size_t i = 0; i < pattern.pattern.size(); i++) {
        if (pattern.mask[i] && memory[i] != pattern.pattern[i]) {
            return false;
        }
    }
    return true;
}

// Scan a memory region for patterns
static bool ScanRegion(HANDLE process, LPCVOID baseAddress, SIZE_T regionSize,
                       char* detectedPattern, int bufferSize) {
    std::vector<BYTE> buffer(regionSize);
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(process, baseAddress, buffer.data(), regionSize, &bytesRead)) {
        return false;
    }

    for (const auto& pattern : g_cheatPatterns) {
        if (bytesRead < pattern.pattern.size()) continue;

        for (SIZE_T i = 0; i <= bytesRead - pattern.pattern.size(); i++) {
            if (MatchPattern(&buffer[i], pattern)) {
                if (detectedPattern && bufferSize > 0) {
                    strncpy_s(detectedPattern, bufferSize, pattern.name.c_str(), _TRUNCATE);
                }
                return true;
            }
        }
    }

    return false;
}

// ============================================================================
// EXPORTED FUNCTIONS
// ============================================================================

AC_API bool AC_CALL AC_MemoryScanInit(void) {
    g_cheatPatterns.clear();
    InitDefaultPatterns();
    return true;
}

AC_API bool AC_CALL AC_AddCheatPattern(const char* name, const BYTE* pattern,
                                        const bool* mask, int length) {
    if (!name || !pattern || length <= 0 || length > 256) {
        strcpy_s(g_lastPatternError, "Invalid pattern parameters");
        return false;
    }

    MemoryPattern p;
    p.name = name;
    p.pattern.assign(pattern, pattern + length);

    if (mask) {
        p.mask.assign(mask, mask + length);
    } else {
        p.mask = std::vector<bool>(length, true);
    }

    g_cheatPatterns.push_back(p);
    return true;
}

AC_API bool AC_CALL AC_ScanProcessMemory(DWORD processId, char* detectedPattern, int bufferSize) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) {
        strcpy_s(g_lastPatternError, "Failed to open process");
        return false;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    LPVOID address = sysInfo.lpMinimumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    bool found = false;

    while (address < sysInfo.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == 0) {
            break;
        }

        // Only scan committed, readable memory
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {

            if (ScanRegion(hProcess, mbi.BaseAddress, mbi.RegionSize, detectedPattern, bufferSize)) {
                found = true;
                break;
            }
        }

        address = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    CloseHandle(hProcess);
    return found;
}

AC_API bool AC_CALL AC_ScanCurrentProcess(char* detectedPattern, int bufferSize) {
    return AC_ScanProcessMemory(GetCurrentProcessId(), detectedPattern, bufferSize);
}

AC_API bool AC_CALL AC_ScanMemoryRegion(void* address, size_t size,
                                         char* detectedPattern, int bufferSize) {
    if (!address || size == 0) {
        strcpy_s(g_lastPatternError, "Invalid memory region");
        return false;
    }

    __try {
        const BYTE* mem = static_cast<const BYTE*>(address);

        for (const auto& pattern : g_cheatPatterns) {
            if (size < pattern.pattern.size()) continue;

            for (size_t i = 0; i <= size - pattern.pattern.size(); i++) {
                if (MatchPattern(&mem[i], pattern)) {
                    if (detectedPattern && bufferSize > 0) {
                        strncpy_s(detectedPattern, bufferSize, pattern.name.c_str(), _TRUNCATE);
                    }
                    return true;
                }
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        strcpy_s(g_lastPatternError, "Access violation during scan");
        return false;
    }

    return false;
}

AC_API int AC_CALL AC_GetPatternCount(void) {
    return static_cast<int>(g_cheatPatterns.size());
}

AC_API void AC_CALL AC_ClearPatterns(void) {
    g_cheatPatterns.clear();
}

AC_API const char* AC_CALL AC_GetPatternError(void) {
    return g_lastPatternError;
}

// Detect memory modifications (code patches)
AC_API bool AC_CALL AC_DetectCodeModification(void* codeStart, size_t codeSize,
                                               uint32_t originalHash) {
    if (!codeStart || codeSize == 0) return false;

    uint32_t currentHash = AC_HashMemory(codeStart, codeSize);
    return currentHash != originalHash;
}

// Scan for injected code caves
AC_API bool AC_CALL AC_DetectCodeCaves(char* details, int bufferSize) {
    HANDLE hProcess = GetCurrentProcess();
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    LPVOID address = sysInfo.lpMinimumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;

    while (address < sysInfo.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == 0) {
            break;
        }

        // Look for executable memory that's not backed by a module
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
            mbi.Type == MEM_PRIVATE) {

            // Suspicious: executable private memory
            if (details && bufferSize > 0) {
                snprintf(details, bufferSize, "CodeCave at 0x%p, Size: %zu",
                         mbi.BaseAddress, mbi.RegionSize);
            }
            return true;
        }

        address = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    return false;
}
