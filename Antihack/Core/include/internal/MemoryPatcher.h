/**
 * AntiCheatCore - Memory Patcher Module
 * Utility class for safe memory read/write operations
 */

#pragma once

#ifndef AC_MEMORY_PATCHER_H
#define AC_MEMORY_PATCHER_H

#include "common.h"

namespace AntiCheat {

class MemoryPatcher {
public:
    MemoryPatcher() = default;
    ~MemoryPatcher() = default;

    // Command line parsing
    static void CommandLineToArg(char* Command, char*** argv);

    // Core memory operations
    DWORD WriteMemory(const LPVOID lpAddress, const LPVOID lpBuf, const UINT uSize);
    DWORD ReadMemory(const LPVOID lpAddress, LPVOID lpBuf, const UINT uSize);

    // Type-specific operations
    DWORD SetByte(const LPVOID dwOffset, const BYTE btValue);
    DWORD GetByte(const LPVOID dwOffset, BYTE& btValue);

    DWORD SetWord(const LPVOID dwOffset, const WORD wValue);
    DWORD GetWord(const LPVOID dwOffset, WORD& wValue);

    DWORD SetDword(const LPVOID dwOffset, const DWORD dwValue);
    DWORD GetDword(const LPVOID dwOffset, DWORD& dwValue);

    DWORD SetFloat(const LPVOID dwOffset, float fValue);
    DWORD GetFloat(const LPVOID dwOffset, float& fValue);

    DWORD SetDouble(const LPVOID dwOffset, double dValue);

    // Jump/Hook operations
    DWORD SetJmp(const LPVOID dwEnterFunction, const LPVOID dwJMPAddress);
    DWORD SetJg(const LPVOID dwEnterFunction, const LPVOID dwJMPAddress);
    DWORD SetJa(const LPVOID dwEnterFunction, const LPVOID dwJMPAddress);
    DWORD SetOp(const LPVOID dwEnterFunction, const LPVOID dwJMPAddress, const BYTE cmd);
    DWORD SetRange(const LPVOID dwAddress, const USHORT wCount, const BYTE btValue);
    DWORD SetHook(const LPVOID dwMyFuncOffset, const LPVOID dwJmpOffset, const BYTE cmd);
};

// Global instance
extern MemoryPatcher gMemory;

} // namespace AntiCheat

#endif // AC_MEMORY_PATCHER_H
