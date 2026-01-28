/**
 * AntiCheatCore - Anti-Debug Module
 * Detects debuggers and analysis tools
 */

#include "../include/anticheat_core.h"
#include <windows.h>
#include <winternl.h>

// NtQueryInformationProcess function pointer
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// Detection flags
#define DETECT_ISDEBUGGERPRESENT     0x01
#define DETECT_REMOTEDEBUGGERPRESENT 0x02
#define DETECT_NTQUERY               0x04
#define DETECT_HARDWARE_BP           0x08
#define DETECT_TIMING                0x10

extern "C" {

AC_API uint32_t AC_CALL AC_DetectDebugger(void) {
    uint32_t result = 0;

    // Method 1: IsDebuggerPresent
    if (IsDebuggerPresent()) {
        result |= DETECT_ISDEBUGGERPRESENT;
    }

    // Method 2: CheckRemoteDebuggerPresent
    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger)) {
        if (remoteDebugger) {
            result |= DETECT_REMOTEDEBUGGERPRESENT;
        }
    }

    // Method 3: NtQueryInformationProcess (ProcessDebugPort)
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        pNtQueryInformationProcess NtQueryInformationProcess =
            (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

        if (NtQueryInformationProcess) {
            DWORD_PTR debugPort = 0;
            NTSTATUS status = NtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugPort,  // 7
                &debugPort,
                sizeof(debugPort),
                nullptr
            );

            if (NT_SUCCESS(status) && debugPort != 0) {
                result |= DETECT_NTQUERY;
            }

            // Also check ProcessDebugFlags
            DWORD debugFlags = 0;
            status = NtQueryInformationProcess(
                GetCurrentProcess(),
                (PROCESSINFOCLASS)31,  // ProcessDebugFlags
                &debugFlags,
                sizeof(debugFlags),
                nullptr
            );

            if (NT_SUCCESS(status) && debugFlags == 0) {
                result |= DETECT_NTQUERY;
            }
        }
    }

    // Method 4: Check hardware breakpoints via thread context
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            result |= DETECT_HARDWARE_BP;
        }
    }

    // Method 5: Timing check (basic)
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    // Simple operation that shouldn't take long
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) {
        dummy += i;
    }

    QueryPerformanceCounter(&end);

    // If the simple loop took more than 100ms, something is slowing us down
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000.0;
    if (elapsed > 100.0) {
        result |= DETECT_TIMING;
    }

    return result;
}

// Additional PEB-based detection
static bool CheckPEB() {
#ifdef _WIN64
    // 64-bit PEB access
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    // 32-bit PEB access
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    if (pPeb) {
        // BeingDebugged flag
        if (pPeb->BeingDebugged) {
            return true;
        }

        // NtGlobalFlag check (0x70 = FLG_HEAP_ENABLE_TAIL_CHECK |
        //                           FLG_HEAP_ENABLE_FREE_CHECK |
        //                           FLG_HEAP_VALIDATE_PARAMETERS)
        DWORD ntGlobalFlag = *(DWORD*)((BYTE*)pPeb + 0xBC);  // Offset varies
        if (ntGlobalFlag & 0x70) {
            return true;
        }
    }

    return false;
}

} // extern "C"
