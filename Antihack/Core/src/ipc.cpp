/**
 * AntiCheatCore - IPC Module
 * Comunicacion con el proceso AntiCheat via Named Pipes
 */

#include "../include/anticheat_core.h"
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>

#define PIPE_NAME L"\\\\.\\pipe\\AntiCheatPipe"
#define PIPE_BUFFER_SIZE 4096

// Estado del IPC
static HANDLE g_hPipe = INVALID_HANDLE_VALUE;
static std::atomic<bool> g_IpcRunning(false);
static std::thread g_IpcThread;
static std::queue<std::string> g_MessageQueue;
static std::mutex g_QueueMutex;
static char g_IpcLastError[256] = {0};

// Callback para mensajes recibidos del AntiCheat
static AC_IpcMessageCallback g_IpcCallback = nullptr;

// Forward declarations
static void IpcThreadFunc();
static bool ConnectToPipe();
static bool SendMessageInternal(const char* message);

extern "C" {

/**
 * Inicializar comunicacion IPC con el AntiCheat
 */
AC_API bool AC_CALL AC_IpcInitialize(void) {
    if (g_IpcRunning.load()) {
        return true; // Ya inicializado
    }

    // Intentar conectar al pipe
    if (!ConnectToPipe()) {
        strcpy_s(g_IpcLastError, "Failed to connect to AntiCheat pipe");
        return false;
    }

    // Iniciar thread de lectura
    g_IpcRunning.store(true);
    g_IpcThread = std::thread(IpcThreadFunc);

    return true;
}

/**
 * Cerrar comunicacion IPC
 */
AC_API void AC_CALL AC_IpcShutdown(void) {
    g_IpcRunning.store(false);

    if (g_IpcThread.joinable()) {
        g_IpcThread.join();
    }

    if (g_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    }
}

/**
 * Verificar si IPC esta conectado
 */
AC_API bool AC_CALL AC_IpcIsConnected(void) {
    return g_hPipe != INVALID_HANDLE_VALUE && g_IpcRunning.load();
}

/**
 * Enviar mensaje al AntiCheat
 * Formato JSON: {"action": "TIPO", "message": "detalles"}
 */
AC_API bool AC_CALL AC_IpcSendMessage(const char* message) {
    if (!message || !AC_IpcIsConnected()) {
        return false;
    }

    return SendMessageInternal(message);
}

/**
 * Enviar reporte de deteccion al AntiCheat
 */
AC_API bool AC_CALL AC_IpcReportDetection(const char* detectionType, const char* details) {
    if (!detectionType || !AC_IpcIsConnected()) {
        return false;
    }

    // Construir JSON
    char jsonBuffer[1024];
    snprintf(jsonBuffer, sizeof(jsonBuffer),
        "{\"action\":\"%s\",\"message\":\"%s\"}",
        detectionType,
        details ? details : "");

    return SendMessageInternal(jsonBuffer);
}

/**
 * Reportar intento de inyeccion de DLL
 */
AC_API bool AC_CALL AC_IpcReportDllInjection(const char* dllPath) {
    return AC_IpcReportDetection("INJECTION_ALERT", dllPath);
}

/**
 * Reportar carga de DLL sospechosa
 */
AC_API bool AC_CALL AC_IpcReportSuspiciousDll(const char* dllName) {
    return AC_IpcReportDetection("REPORT_DL", dllName);
}

/**
 * Reportar debugger detectado
 */
AC_API bool AC_CALL AC_IpcReportDebugger(const char* debuggerInfo) {
    return AC_IpcReportDetection("DEBUGGER_DETECTED", debuggerInfo);
}

/**
 * Reportar modificacion de memoria
 */
AC_API bool AC_CALL AC_IpcReportMemoryModification(const char* details) {
    return AC_IpcReportDetection("MEMORY_MODIFIED", details);
}

/**
 * Establecer callback para mensajes del AntiCheat
 */
AC_API void AC_CALL AC_IpcSetMessageCallback(AC_IpcMessageCallback callback) {
    g_IpcCallback = callback;
}

/**
 * Obtener ultimo error de IPC
 */
AC_API const char* AC_CALL AC_IpcGetLastError(void) {
    return g_IpcLastError;
}

} // extern "C"

// ============================================================================
// Funciones internas
// ============================================================================

static bool ConnectToPipe() {
    // Intentar conectar al pipe del AntiCheat
    for (int retry = 0; retry < 5; retry++) {
        g_hPipe = CreateFileW(
            PIPE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );

        if (g_hPipe != INVALID_HANDLE_VALUE) {
            // Configurar modo del pipe
            DWORD mode = PIPE_READMODE_BYTE;
            SetNamedPipeHandleState(g_hPipe, &mode, nullptr, nullptr);
            return true;
        }

        // Si el pipe no existe aun, esperar
        if (GetLastError() == ERROR_PIPE_BUSY) {
            if (!WaitNamedPipeW(PIPE_NAME, 2000)) {
                continue;
            }
        }

        Sleep(500);
    }

    return false;
}

static bool SendMessageInternal(const char* message) {
    if (g_hPipe == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD bytesWritten = 0;
    BOOL success = WriteFile(
        g_hPipe,
        message,
        (DWORD)strlen(message),
        &bytesWritten,
        nullptr
    );

    if (!success) {
        DWORD error = GetLastError();
        if (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA) {
            // Pipe cerrado, intentar reconectar
            CloseHandle(g_hPipe);
            g_hPipe = INVALID_HANDLE_VALUE;

            if (ConnectToPipe()) {
                // Reintentar envio
                return WriteFile(g_hPipe, message, (DWORD)strlen(message), &bytesWritten, nullptr);
            }
        }
        return false;
    }

    return true;
}

static void IpcThreadFunc() {
    char buffer[PIPE_BUFFER_SIZE];

    while (g_IpcRunning.load()) {
        if (g_hPipe == INVALID_HANDLE_VALUE) {
            // Intentar reconectar
            if (!ConnectToPipe()) {
                Sleep(1000);
                continue;
            }
        }

        // Leer mensajes del AntiCheat (comandos)
        DWORD bytesRead = 0;
        BOOL success = ReadFile(
            g_hPipe,
            buffer,
            PIPE_BUFFER_SIZE - 1,
            &bytesRead,
            nullptr
        );

        if (success && bytesRead > 0) {
            buffer[bytesRead] = '\0';

            // Llamar callback si esta establecido
            if (g_IpcCallback) {
                g_IpcCallback(buffer);
            }
        }
        else {
            DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA) {
                // Pipe cerrado
                CloseHandle(g_hPipe);
                g_hPipe = INVALID_HANDLE_VALUE;
            }
        }

        Sleep(10); // Evitar busy-wait
    }
}
