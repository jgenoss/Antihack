/**
 * AntiCheatCore - Self Protection Implementation
 * Protects anticheat from being suspended/terminated by tools like Process Hacker
 */

#include "stdafx.h"
#include "../include/internal/SelfProtection.h"
#include <winternl.h>

namespace AntiCheat {

// NtSetInformationThread to hide from debugger
typedef NTSTATUS(NTAPI* pNtSetInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

// NtQueryInformationThread
typedef NTSTATUS(NTAPI* pNtQueryInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

// RtlSetProcessIsCritical
typedef NTSTATUS(NTAPI* pRtlSetProcessIsCritical)(
    BOOLEAN NewValue,
    PBOOLEAN OldValue,
    BOOLEAN CheckFlag
);

// Thread information classes
#define ThreadHideFromDebugger 0x11
#define ThreadBreakOnTermination 0x12

// CRC32 table for code integrity
static uint32_t s_CRC32Table[256];
static bool s_CRC32Initialized = false;

static void InitCRC32Table() {
    if (s_CRC32Initialized) return;

    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        s_CRC32Table[i] = crc;
    }
    s_CRC32Initialized = true;
}

static uint32_t CalculateCRC32(const void* data, size_t size) {
    InitCRC32Table();
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < size; i++) {
        crc = s_CRC32Table[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }

    return crc ^ 0xFFFFFFFF;
}

SelfProtection::SelfProtection()
    : m_watchdogThread(NULL)
    , m_checkInterval(100)
    , m_processId(GetCurrentProcessId())
    , m_processHandle(GetCurrentProcess())
    , m_codeBaseAddress(nullptr)
    , m_codeSize(0)
    , m_originalCodeCRC(0) {
}

SelfProtection::~SelfProtection() {
    Shutdown();
}

bool SelfProtection::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Get module info for integrity checks
    HMODULE hModule = GetModuleHandle(NULL);
    if (hModule) {
        MODULEINFO modInfo;
        if (GetModuleInformation(m_processHandle, hModule, &modInfo, sizeof(modInfo))) {
            m_codeBaseAddress = modInfo.lpBaseOfDll;
            m_codeSize = modInfo.SizeOfImage;

            // Calculate initial CRC
            IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)m_codeBaseAddress;
            IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)m_codeBaseAddress + dosHeader->e_lfanew);
            IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);

            // Find .text section
            for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
                if (strcmp((char*)section[i].Name, ".text") == 0) {
                    void* textBase = (BYTE*)m_codeBaseAddress + section[i].VirtualAddress;
                    m_originalCodeCRC = CalculateCRC32(textBase, section[i].Misc.VirtualSize);
                    break;
                }
            }
        }
    }

    // Enable DEP
    SetProcessDEP();

    return true;
}

void SelfProtection::Shutdown() {
    StopWatchdog();

    // Disable critical process if it was enabled
    DisableCriticalProcess();

    std::lock_guard<std::mutex> lock(m_mutex);
    m_protectedThreads.clear();
}

bool SelfProtection::RegisterThread(DWORD threadId, bool critical) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Check if already registered
    for (auto& thread : m_protectedThreads) {
        if (thread.threadId == threadId) {
            thread.isCritical = critical;
            return true;
        }
    }

    // Open thread handle
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
    if (!hThread) {
        m_lastError = "Failed to open thread: " + std::to_string(::GetLastError());
        return false;
    }

    ThreadInfo info;
    info.threadId = threadId;
    info.handle = hThread;
    info.lastCheckTime = GetTickCount();
    info.isCritical = critical;
    info.wasSuspended = false;

    m_protectedThreads.push_back(info);

    // Hide thread from debugger if critical
    if (critical) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            pNtSetInformationThread NtSetInformationThread =
                (pNtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");

            if (NtSetInformationThread) {
                NtSetInformationThread(hThread, ThreadHideFromDebugger, NULL, 0);
            }
        }
    }

    return true;
}

bool SelfProtection::RegisterCurrentThread(bool critical) {
    return RegisterThread(GetCurrentThreadId(), critical);
}

bool SelfProtection::UnregisterThread(DWORD threadId) {
    std::lock_guard<std::mutex> lock(m_mutex);

    for (auto it = m_protectedThreads.begin(); it != m_protectedThreads.end(); ++it) {
        if (it->threadId == threadId) {
            if (it->handle) {
                CloseHandle(it->handle);
            }
            m_protectedThreads.erase(it);
            return true;
        }
    }

    return false;
}

void SelfProtection::ProtectAllThreads() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == m_processId) {
                RegisterThread(te.th32ThreadID, true);
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
}

bool SelfProtection::IsThreadSuspended(HANDLE hThread) {
    // Try to suspend - if already suspended, count > 0
    DWORD suspendCount = SuspendThread(hThread);
    if (suspendCount == (DWORD)-1) {
        return false;
    }

    // Resume immediately
    ResumeThread(hThread);

    // If suspend count was > 0, thread was suspended
    return suspendCount > 0;
}

bool SelfProtection::ResumeProtectedThread(ThreadInfo& thread) {
    DWORD count = 0;
    DWORD maxAttempts = 100;

    // Resume until thread is running
    while (count < maxAttempts) {
        DWORD result = ResumeThread(thread.handle);
        if (result == (DWORD)-1) {
            break;
        }
        if (result == 0) {
            // Thread is running
            break;
        }
        count++;
    }

    thread.wasSuspended = false;
    thread.lastCheckTime = GetTickCount();

    return count > 0;
}

void SelfProtection::CheckAndRecoverThreads() {
    std::lock_guard<std::mutex> lock(m_mutex);

    for (auto& thread : m_protectedThreads) {
        if (IsThreadSuspended(thread.handle)) {
            thread.wasSuspended = true;

            // Fire callback
            if (m_onSuspendAttempt) {
                ProtectionEvent event;
                event.timestamp = GetTickCount();
                event.eventType = "ThreadSuspended";
                event.description = "Protected thread was suspended: " + std::to_string(thread.threadId);
                event.processId = 0;
                m_onSuspendAttempt(event);
            }

            // Resume the thread
            ResumeProtectedThread(thread);
        }
    }
}

bool SelfProtection::SetCriticalProcess(bool critical) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    pRtlSetProcessIsCritical RtlSetProcessIsCritical =
        (pRtlSetProcessIsCritical)GetProcAddress(hNtdll, "RtlSetProcessIsCritical");

    if (!RtlSetProcessIsCritical) {
        m_lastError = "RtlSetProcessIsCritical not found";
        return false;
    }

    // Need SE_DEBUG_PRIVILEGE
    HANDLE hToken;
    if (OpenProcessToken(m_processHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
        CloseHandle(hToken);
    }

    NTSTATUS status = RtlSetProcessIsCritical(critical ? TRUE : FALSE, NULL, FALSE);
    return status == 0;
}

bool SelfProtection::SetProcessDEP() {
    typedef BOOL(WINAPI* pSetProcessDEPPolicy)(DWORD);

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32) {
        pSetProcessDEPPolicy SetProcessDEPPolicy =
            (pSetProcessDEPPolicy)GetProcAddress(hKernel32, "SetProcessDEPPolicy");

        if (SetProcessDEPPolicy) {
            return SetProcessDEPPolicy(PROCESS_DEP_ENABLE | PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION) != FALSE;
        }
    }
    return false;
}

bool SelfProtection::EnableCriticalProcess() {
    return SetCriticalProcess(true);
}

bool SelfProtection::DisableCriticalProcess() {
    return SetCriticalProcess(false);
}

bool SelfProtection::ProtectProcessMemory() {
    // Make critical sections non-writable
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = (BYTE*)m_codeBaseAddress;

    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
            DWORD oldProtect;
            VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READ, &oldProtect);
        }
        addr += mbi.RegionSize;
        if (addr >= (BYTE*)m_codeBaseAddress + m_codeSize) break;
    }

    return true;
}

bool SelfProtection::HideThreadsFromDebugger() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    pNtSetInformationThread NtSetInformationThread =
        (pNtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");

    if (!NtSetInformationThread) return false;

    std::lock_guard<std::mutex> lock(m_mutex);
    bool success = true;

    for (auto& thread : m_protectedThreads) {
        NTSTATUS status = NtSetInformationThread(thread.handle, ThreadHideFromDebugger, NULL, 0);
        if (status != 0) {
            success = false;
        }
    }

    return success;
}

DWORD WINAPI SelfProtection::WatchdogThreadProc(LPVOID param) {
    SelfProtection* self = static_cast<SelfProtection*>(param);
    self->WatchdogLoop();
    return 0;
}

void SelfProtection::WatchdogLoop() {
    while (m_monitoring) {
        // Check and recover suspended threads
        CheckAndRecoverThreads();

        // Check code integrity if enabled
        if (m_integrityCheckEnabled && IsCodeModified()) {
            if (m_threatCallback) {
                ProtectionEvent event;
                event.timestamp = GetTickCount();
                event.eventType = "CodeModified";
                event.description = "Code section was modified";
                event.processId = 0;
                m_threatCallback(event);
            }
        }

        Sleep(m_checkInterval);
    }
}

bool SelfProtection::StartWatchdog(DWORD intervalMs) {
    if (m_monitoring) return true;

    m_checkInterval = intervalMs;
    m_monitoring = true;

    m_watchdogThread = CreateThread(NULL, 0, WatchdogThreadProc, this, 0, NULL);
    if (!m_watchdogThread) {
        m_monitoring = false;
        m_lastError = "Failed to create watchdog thread";
        return false;
    }

    // Register the watchdog thread for protection
    RegisterThread(GetThreadId(m_watchdogThread), true);

    return true;
}

void SelfProtection::StopWatchdog() {
    if (!m_monitoring) return;

    m_monitoring = false;

    if (m_watchdogThread) {
        WaitForSingleObject(m_watchdogThread, 5000);
        CloseHandle(m_watchdogThread);
        m_watchdogThread = NULL;
    }
}

std::wstring SelfProtection::GetProcessName(DWORD pid) {
    std::wstring name;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        wchar_t buffer[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, buffer, &size)) {
            name = buffer;
            size_t pos = name.rfind(L'\\');
            if (pos != std::wstring::npos) {
                name = name.substr(pos + 1);
            }
        }
        CloseHandle(hProcess);
    }
    return name;
}

bool SelfProtection::IsDebugToolProcess(DWORD pid) {
    std::wstring name = GetProcessName(pid);
    if (name.empty()) return false;

    // Convert to lowercase
    std::transform(name.begin(), name.end(), name.begin(), ::towlower);

    // Known debug/analysis tools
    const wchar_t* dangerousTools[] = {
        L"processhacker", L"procexp", L"procexp64", L"procmon",
        L"x64dbg", L"x32dbg", L"ollydbg", L"windbg",
        L"ida", L"ida64", L"idaq", L"idaq64",
        L"cheatengine", L"ce-", L"dnspy",
        L"apimonitor", L"wireshark",
        nullptr
    };

    for (int i = 0; dangerousTools[i]; i++) {
        if (name.find(dangerousTools[i]) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

std::vector<DWORD> SelfProtection::GetProcessesWithOurHandle() {
    std::vector<DWORD> result;

    // This would require NtQuerySystemInformation with SystemHandleInformation
    // which is complex and system-specific. For now, return empty.
    // A full implementation would enumerate all handles in the system.

    return result;
}

bool SelfProtection::DetectHandleOpens() {
    auto processes = GetProcessesWithOurHandle();

    for (DWORD pid : processes) {
        if (pid != m_processId && IsDebugToolProcess(pid)) {
            if (m_threatCallback) {
                ProtectionEvent event;
                event.timestamp = GetTickCount();
                event.eventType = "HandleOpened";
                event.description = "Debug tool opened handle to our process";
                event.processId = pid;
                event.processName = GetProcessName(pid);
                m_threatCallback(event);
            }
            return true;
        }
    }

    return false;
}

bool SelfProtection::IsAnyThreadSuspended() {
    std::lock_guard<std::mutex> lock(m_mutex);

    for (auto& thread : m_protectedThreads) {
        if (IsThreadSuspended(thread.handle)) {
            return true;
        }
    }

    return false;
}

int SelfProtection::RecoverSuspendedThreads() {
    std::lock_guard<std::mutex> lock(m_mutex);
    int recovered = 0;

    for (auto& thread : m_protectedThreads) {
        if (IsThreadSuspended(thread.handle)) {
            if (ResumeProtectedThread(thread)) {
                recovered++;
            }
        }
    }

    return recovered;
}

void SelfProtection::SetAutoRecovery(bool enabled) {
    if (enabled && !m_monitoring) {
        StartWatchdog();
    } else if (!enabled && m_monitoring) {
        StopWatchdog();
    }
}

uint32_t SelfProtection::CalculateCodeCRC() {
    if (!m_codeBaseAddress) return 0;

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)m_codeBaseAddress;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)m_codeBaseAddress + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section[i].Name, ".text") == 0) {
            void* textBase = (BYTE*)m_codeBaseAddress + section[i].VirtualAddress;
            return CalculateCRC32(textBase, section[i].Misc.VirtualSize);
        }
    }

    return 0;
}

bool SelfProtection::IsCodeModified() {
    if (m_originalCodeCRC == 0) return false;

    uint32_t currentCRC = CalculateCodeCRC();
    return currentCRC != m_originalCodeCRC;
}

bool SelfProtection::EnableIntegrityChecks() {
    m_integrityCheckEnabled = true;
    return true;
}

bool SelfProtection::DisableIntegrityChecks() {
    m_integrityCheckEnabled = false;
    return true;
}

bool SelfProtection::CloseExternalHandles() {
    // This would require NtQuerySystemInformation and NtDuplicateObject
    // to close handles in other processes. Complex implementation.
    return false;
}

} // namespace AntiCheat
