# AntiCheat System - Documentacion Completa

## Tabla de Contenidos

1. [Arquitectura General](#1-arquitectura-general)
2. [Componentes del Sistema](#2-componentes-del-sistema)
3. [Flujo de Comunicacion](#3-flujo-de-comunicacion)
4. [AntiCheatCore (C++ DLL)](#4-anticheatcore-c-dll)
5. [Antihack (C# Cliente)](#5-antihack-c-cliente)
6. [ServerTCP (C# Servidor)](#6-servertcp-c-servidor)
7. [Protocolo IPC](#7-protocolo-ipc)
8. [API Reference](#8-api-reference)
9. [Guia de Uso](#9-guia-de-uso)
10. [Configuracion](#10-configuracion)

---

## 1. Arquitectura General

```
+------------------+     Named Pipe      +------------------+     TCP/IP      +------------------+
|                  |   (AntiCheatPipe)   |                  |    (JSON)       |                  |
|  GAME PROCESS    | <=================> |  ANTIHACK.EXE    | <=============> |  SERVERTCP       |
|  + DLL Injected  |                     |  (C# Cliente)    |                 |  (C# Servidor)   |
|                  |                     |                  |                 |                  |
+------------------+                     +------------------+                 +------------------+
        |                                        |                                    |
        |                                        |                                    |
   AntiCheatCore.dll                      NativeInterop.cs                     Server.cs
   (Monitoreo nativo)                    (P/Invoke wrappers)              (Gestion clientes)
```

### Descripcion de Capas

| Capa | Componente | Lenguaje | Responsabilidad |
|------|------------|----------|-----------------|
| **Kernel** | AntiCheatCore.dll | C++ | Deteccion a bajo nivel, hooks, memoria |
| **Cliente** | Antihack.exe | C# | Coordinacion, UI, comunicacion servidor |
| **Servidor** | ServerTCP | C# | Autenticacion, comandos, logs |

---

## 2. Componentes del Sistema

### 2.1 Estructura de Directorios

```
Antihack/
├── Antihack/                    # Cliente C#
│   ├── Core/                    # DLL C++ nativa
│   │   ├── include/
│   │   │   ├── anticheat_core.h        # API publica exportada
│   │   │   └── internal/
│   │   │       ├── IMonitorModule.h    # Base class para modulos
│   │   │       ├── AntiCheatEngine.h   # Motor principal
│   │   │       ├── IPCManager.h        # Comunicacion IPC
│   │   │       ├── ProcessMonitor.h    # Monitor de procesos
│   │   │       ├── HookDetector.h      # Detector de hooks
│   │   │       ├── MacroDetector.h     # Detector de macros
│   │   │       ├── OverlayDetector.h   # Detector de overlays
│   │   │       ├── FileProtection.h    # Proteccion de archivos
│   │   │       ├── EncryptionLib.h     # Libreria de cifrado
│   │   │       ├── HWIDCollector.h     # Colector de HWID
│   │   │       ├── SelfProtection.h    # Auto-proteccion
│   │   │       └── common.h            # Definiciones comunes
│   │   └── src/
│   │       └── [implementaciones .cpp]
│   │
│   ├── Modules/                 # Modulos C#
│   │   ├── IPC/
│   │   │   └── IpcServer.cs            # Servidor Named Pipe
│   │   ├── Security/
│   │   │   └── NativeInterop.cs        # Wrappers P/Invoke
│   │   ├── Logging/
│   │   │   └── Logger.cs
│   │   └── Config/
│   │       └── ConfigManager.cs
│   │
│   └── AntiCheatForm.cs         # UI principal
│
└── ServerTCP/                   # Servidor C#
    └── Server.cs                # Logica del servidor
```

---

## 3. Flujo de Comunicacion

### 3.1 Diagrama de Secuencia - Inicio del Sistema

```
┌─────────┐          ┌─────────────┐          ┌──────────┐          ┌────────────┐
│  User   │          │ Antihack.exe│          │ ServerTCP│          │ Game + DLL │
└────┬────┘          └──────┬──────┘          └────┬─────┘          └─────┬──────┘
     │                      │                      │                      │
     │ 1. Ejecuta cliente   │                      │                      │
     │─────────────────────>│                      │                      │
     │                      │                      │                      │
     │                      │ 2. Carga config      │                      │
     │                      │─────────┐            │                      │
     │                      │         │            │                      │
     │                      │<────────┘            │                      │
     │                      │                      │                      │
     │                      │ 3. Inicia IpcServer  │                      │
     │                      │ (AntiCheatPipe)      │                      │
     │                      │─────────┐            │                      │
     │                      │         │            │                      │
     │                      │<────────┘            │                      │
     │                      │                      │                      │
     │                      │ 4. TCP Connect       │                      │
     │                      │─────────────────────>│                      │
     │                      │                      │                      │
     │                      │ 5. AUTH {key, hwid}  │                      │
     │                      │─────────────────────>│                      │
     │                      │                      │                      │
     │                      │ 6. AUTH_OK           │                      │
     │                      │<─────────────────────│                      │
     │                      │                      │                      │
     │                      │ 7. INIT {hwid, user} │                      │
     │                      │─────────────────────>│                      │
     │                      │                      │                      │
     │                      │ 8. Lanza juego       │                      │
     │                      │─────────────────────────────────────────────>│
     │                      │                      │                      │
     │                      │                      │      9. DLL conecta  │
     │                      │<─────────────────────────────────────────────│
     │                      │         (Named Pipe)                        │
     │                      │                      │                      │
```

### 3.2 Diagrama de Secuencia - Deteccion de Cheat

```
┌────────────┐          ┌─────────────┐          ┌──────────┐
│ Game + DLL │          │ Antihack.exe│          │ ServerTCP│
└─────┬──────┘          └──────┬──────┘          └────┬─────┘
      │                        │                      │
      │ 1. Detecta injection   │                      │
      │───────────┐            │                      │
      │           │            │                      │
      │<──────────┘            │                      │
      │                        │                      │
      │ 2. IPC: INJECTION_ALERT│                      │
      │───────────────────────>│                      │
      │    {action, message}   │                      │
      │                        │                      │
      │                        │ 3. Log evento        │
      │                        │───────────┐          │
      │                        │           │          │
      │                        │<──────────┘          │
      │                        │                      │
      │                        │ 4. TCP: THREAT       │
      │                        │─────────────────────>│
      │                        │  {type, details}     │
      │                        │                      │
      │                        │                      │ 5. Log + Accion
      │                        │                      │───────────┐
      │                        │                      │           │
      │                        │                      │<──────────┘
      │                        │                      │
      │                        │ 6. disconnect        │
      │                        │<─────────────────────│
      │                        │                      │
      │ 7. Termina proceso     │                      │
      │<───────────────────────│                      │
      │                        │                      │
```

### 3.3 Ciclo de Monitoreo (Thread Loop)

```
┌─────────────────────────────────────────────────────────────────┐
│                    CICLO DE MONITOREO (DLL)                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌──────────────┐                                              │
│   │    START     │                                              │
│   └──────┬───────┘                                              │
│          │                                                      │
│          ▼                                                      │
│   ┌──────────────┐     ┌─────────────────┐                      │
│   │ Wait(100ms)  │────>│ Check Debugger  │──── Detected ───┐    │
│   └──────────────┘     └────────┬────────┘                 │    │
│          ▲                      │ OK                       │    │
│          │                      ▼                          │    │
│          │             ┌─────────────────┐                 │    │
│          │             │  Scan Hooks     │──── Detected ───┤    │
│          │             └────────┬────────┘                 │    │
│          │                      │ OK                       │    │
│          │                      ▼                          │    │
│          │             ┌─────────────────┐                 │    │
│          │             │ Check Memory    │──── Detected ───┤    │
│          │             └────────┬────────┘                 │    │
│          │                      │ OK                       │    │
│          │                      ▼                          │    │
│          │             ┌─────────────────┐                 │    │
│          │             │ Scan Processes  │──── Detected ───┤    │
│          │             └────────┬────────┘                 │    │
│          │                      │ OK                       │    │
│          │                      ▼                          │    │
│          │             ┌─────────────────┐                 │    │
│          │             │ Check Files     │──── Detected ───┤    │
│          │             └────────┬────────┘                 │    │
│          │                      │ OK                       │    │
│          │                      ▼                          ▼    │
│          │             ┌─────────────────┐         ┌────────────┤
│          └─────────────│  Send Heartbeat │         │Send Report ││
│                        └─────────────────┘         │  via IPC   ││
│                                                    └────────────┤│
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. AntiCheatCore (C++ DLL)

### 4.1 Modulos y Responsabilidades

| Modulo | Archivo | Descripcion |
|--------|---------|-------------|
| **IMonitorModule** | IMonitorModule.h | Clase base abstracta para todos los modulos de monitoreo |
| **AntiCheatEngine** | AntiCheatEngine.cpp | Orquestador principal, inicializa y coordina modulos |
| **ProcessMonitor** | ProcessMonitor.cpp | Detecta procesos blacklisteados e inyeccion de DLLs |
| **HookDetector** | HookDetector.cpp | Detecta hooks inline, IAT, VEH, hardware breakpoints |
| **MacroDetector** | MacroDetector.cpp | Analiza patrones de input para detectar auto-clickers |
| **OverlayDetector** | OverlayDetector.cpp | Detecta overlays de cheats (ESP, wallhacks) |
| **MemoryPatcher** | MemoryPatcher.cpp | Verifica integridad de memoria del proceso |
| **FileProtection** | FileProtection.cpp | Monitorea integridad de archivos del juego |
| **HWIDCollector** | HWIDCollector.cpp | Genera identificador unico de hardware |
| **EncryptionLib** | EncryptionLib.cpp | Cifrado XOR, RC4, ofuscacion de datos |
| **SelfProtection** | SelfProtection.cpp | Protege el anticheat de manipulacion |
| **IPCManager** | IPCManager.cpp | Comunicacion via Named Pipes con el cliente C# |

### 4.2 IMonitorModule - Arquitectura Base

```cpp
// Clase base para modulos de monitoreo thread-safe
class IMonitorModule {
protected:
    enum class ModuleState { Stopped, Starting, Running, Stopping };

    std::atomic<ModuleState> m_state{ModuleState::Stopped};
    mutable std::mutex m_dataMutex;           // Protege datos internos
    mutable std::mutex m_callbackMutex;       // Protege callbacks
    std::vector<DetectionEvent> m_pendingEvents;
    HANDLE m_stopEvent;
    HANDLE m_monitorThread;

    // Metodos abstractos - implementar en clases derivadas
    virtual void DoMonitorCycle() = 0;

    // Metodos thread-safe para eventos
    void QueueEvent(const DetectionEvent& event);
    void DispatchPendingEvents();  // Ejecuta callbacks FUERA del lock

public:
    bool Start();
    void Stop();
    bool IsRunning() const;
    void SetCallback(DetectionCallback cb);
};
```

### 4.3 Tipos de Deteccion (DetectionType)

```cpp
enum class DetectionType {
    None = 0,
    CheatSignature,      // Patron de cheat conocido
    DebuggerAttached,    // Debugger detectado
    InjectedDLL,         // DLL inyectada
    HookedAPI,           // API hookeada
    HookDetected,        // Hook generico
    ModifiedMemory,      // Memoria modificada
    MacroDetected,       // Macro/auto-clicker
    FileModified,        // Archivo alterado
    SuspiciousProcess,   // Proceso sospechoso
    SuspiciousModule,    // Modulo sospechoso
    SuspiciousThread     // Thread sospechoso
};
```

### 4.4 Estructura DetectionEvent

```cpp
struct DetectionEvent {
    DetectionType type;
    Severity severity;      // Info, Warning, Critical
    std::string module;     // Modulo que detecto
    std::string details;    // Descripcion
    void* address;          // Direccion de memoria (si aplica)
    DWORD timestamp;        // Tiempo de deteccion
};
```

---

## 5. Antihack (C# Cliente)

### 5.1 Flujo de Inicializacion

```csharp
// AntiCheatForm.cs - Secuencia de inicio
public AntiCheatForm() {
    1. InitializeComponent();
    2. LoadConfiguration();        // Carga ext11c.dll (INI cifrado)
    3. InitializeIpcServer();      // Inicia Named Pipe server
    4. InitializeNetworkClient();  // Prepara TCP client
    5. GenerateHWID();             // Obtiene hardware ID
    6. ConnectToServer();          // Conecta a ServerTCP
    7. Authenticate();             // Envia AUTH con key + hwid
    8. SendInit();                 // Envia INIT con info del cliente
    9. StartProcessMonitoring();   // Inicia escaneo de procesos
    10. LaunchGame();              // Ejecuta el juego
}
```

### 5.2 IpcServer - Servidor Named Pipe

```csharp
// Maneja comunicacion con la DLL inyectada en el juego
public class IpcServer : IDisposable {
    private const string PIPE_NAME = "AntiCheatPipe";

    // Eventos disponibles
    public event EventHandler<IpcMessageEventArgs> MessageReceived;
    public event EventHandler<IpcMessageEventArgs> DebuggerDetected;
    public event EventHandler<IpcMessageEventArgs> InjectionDetected;
    public event EventHandler<IpcMessageEventArgs> MemoryModified;
    public event EventHandler<IpcMessageEventArgs> SuspiciousDllLoaded;
    public event EventHandler<IpcMessageEventArgs> HookDetected;
    public event EventHandler<IpcMessageEventArgs> MacroDetected;
    public event EventHandler<IpcMessageEventArgs> FileModified;
    public event EventHandler<IpcMessageEventArgs> CheatDetected;

    // Metodos publicos
    public void Start();
    public void Stop();
    public bool SendCommand(string command);
    public bool RequestScan();
    public bool RequestIntegrityCheck();
}
```

### 5.3 NativeInterop - P/Invoke Wrappers

```csharp
// Wrapper completo para AntiCheatCore.dll
public static class NativeInterop {
    private const string DllName = "AntiCheatCore.dll";

    // === INICIALIZACION ===
    public static bool Initialize();
    public static void Shutdown();
    public static string GetVersion();

    // === DETECCION DE PROCESOS ===
    public static bool ScanProcesses(out string detectedProcess);
    public static bool AddToBlacklist(string processName);
    public static void ClearBlacklist();
    public static int GetBlacklistCount();

    // === ANTI-DEBUG ===
    public static DebuggerDetectionFlags DetectDebugger();
    public static bool DetectDebuggerProcess(out string debuggerName);

    // === INTEGRIDAD DE MEMORIA ===
    public static bool ScanForInjectedDlls(out string injectedDll);
    public static bool IsApiHooked(string moduleName, string functionName);

    // === HARDWARE ID ===
    public static string GenerateHWID();

    // === MEMORY PATTERN SCANNING ===
    public static bool MemoryScanInit();
    public static bool AddCheatPattern(string name, byte[] pattern, bool[] mask);
    public static bool ScanProcessMemory(uint processId, out string detectedPattern);
    public static bool ScanCurrentProcess(out string detectedPattern);
    public static bool DetectCodeModification(IntPtr codeStart, UIntPtr codeSize, uint originalHash);
    public static bool DetectCodeCaves(out string details);

    // === FILE PROTECTION ===
    public static bool FileProtectionInit();
    public static void FileProtectionShutdown();
    public static bool ProtectFile(string filePath);
    public static bool UnprotectFile(string filePath);
    public static bool VerifyFileIntegrity(string filePath);
    public static bool VerifyAllFiles(out string failedFile);
    public static bool StartFileMonitoring();
    public static void StopFileMonitoring();
    public static int GetProtectedFileCount();
    public static uint GetFileHash(string filePath);
    public static int ProtectDirectory(string dirPath, string pattern);

    // === ENCRYPTION ===
    public static bool EncryptionInit();
    public static bool GenerateSessionKey();
    public static bool SetSessionKey(byte[] key);
    public static byte[] GetSessionKey(int keySize = 32);
    public static bool XorEncrypt(byte[] data, byte[] key);
    public static bool XorDecrypt(byte[] data, byte[] key);
    public static bool RC4Encrypt(byte[] data, byte[] key);
    public static bool RC4Decrypt(byte[] data, byte[] key);
    public static bool EncryptWithSessionKey(byte[] data);
    public static bool DecryptWithSessionKey(byte[] data);
    public static byte[] GenerateRandom(int length);
    public static uint HashData(byte[] data);
    public static uint HashString(string str);
    public static void SecureClear(byte[] buffer);

    // === HOOK DETECTION ===
    public static bool HookDetectionInit();
    public static bool DetectInlineHook(string moduleName, string functionName, out string hookDetails);
    public static bool DetectIATHook(string targetModule, string importModule, string functionName, out string hookDetails);
    public static int ScanCommonHooks(out string report);
    public static int GetDetectedHookCount();
    public static bool DetectVEHHooks();
    public static bool DetectHardwareBreakpoints();

    // === ANTI-MACRO ===
    public static bool AntiMacroInit();
    public static void AntiMacroShutdown();
    public static bool StartInputMonitoring();
    public static void StopInputMonitoring();
    public static bool IsInputMonitoringActive();
    public static bool DetectAutoClicker(out string details);
    public static bool DetectKeyboardMacro(out string details);
    public static bool DetectInputAutomation(out string details);
    public static ClickStats GetClickStats();
    public static void ResetMacroStats();
    public static bool DetectMacroSoftware(out string detectedName);

    // === IPC ===
    public static bool IpcInitialize();
    public static void IpcShutdown();
    public static bool IpcIsConnected();
    public static bool IpcSendMessage(string message);
    public static bool IpcReportDetection(string detectionType, string details);
}
```

---

## 6. ServerTCP (C# Servidor)

### 6.1 Estructura del Servidor

```csharp
public partial class Server : Form {
    // Servidores TCP (IPv4 e IPv6)
    private SimpleTcpServer _serverIPv4;
    private SimpleTcpServer _serverIPv6;

    // Gestion de clientes
    private Dictionary<string, ClientInfo> _connectedClients;
    private Dictionary<string, bool> _authenticatedClients;

    // Configuracion
    private string _serverKey;      // Clave de autenticacion
    private int _serverPort;        // Puerto TCP
}
```

### 6.2 Protocolo de Mensajes

#### Mensajes Cliente -> Servidor

| Action | Descripcion | Campos |
|--------|-------------|--------|
| `AUTH` | Autenticacion inicial | `key`, `hwid` |
| `INIT` | Inicializacion del cliente | `hwid`, `user_id`, `game` |
| `HEARTBEAT` | Keep-alive | `timestamp` |
| `THREAT` | Reporte de amenaza | `type`, `details`, `hwid` |
| `REPORT_DL` | DLL sospechosa reportada | `dll_name`, `dll_path` |
| `CHEAT_REPORT` | Cheat detectado | `cheat_type`, `details` |

#### Mensajes Servidor -> Cliente

| Action | Descripcion | Campos |
|--------|-------------|--------|
| `AUTH_OK` | Autenticacion exitosa | `status` |
| `AUTH_FAIL` | Autenticacion fallida | `reason` |
| `disconnect` | Desconectar cliente | - |
| `shutdown` | Apagar sistema cliente | - |
| `streamviewer` | Lanzar visor de stream | `ip`, `port`, `executable` |

### 6.3 Manejo de Acciones

```csharp
private void HandleAction(string ipPort, string userId, dynamic packet) {
    string action = packet.action?.ToString().ToUpperInvariant();

    switch (action) {
        case "AUTH":
            // Valida key y registra cliente autenticado
            string authKey = packet.key?.ToString() ?? "";
            if (authKey == _serverKey) {
                _authenticatedClients[ipPort] = true;
                SendPayload(ipPort, "{\"action\":\"AUTH_OK\"}", "AUTH_OK");
            } else {
                DisconnectClient(ipPort);
            }
            break;

        case "INIT":
            // Registra informacion del cliente
            string hwid = packet.hwid?.ToString();
            LogSystemMessage($"INIT | HWID: {hwid} | IP: {ipPort}");
            break;

        case "HEARTBEAT":
            // Actualiza ultima actividad
            UpdateClientActivity(ipPort);
            break;

        case "THREAT":
        case "CHEAT_REPORT":
            // Procesa reporte de amenaza
            string threatType = packet.type?.ToString();
            string details = packet.details?.ToString();
            LogThreat(ipPort, threatType, details);
            // Puede desconectar o tomar accion
            break;

        case "REPORT_DL":
            // DLL injection detectada
            string dllName = packet.message?.ToString();
            LogInjection(ipPort, dllName);
            break;
    }
}
```

---

## 7. Protocolo IPC

### 7.1 Named Pipe Configuration

| Parametro | Valor |
|-----------|-------|
| **Pipe Name** | `\\.\pipe\AntiCheatPipe` |
| **Direction** | Bidireccional (InOut) |
| **Transmission Mode** | Byte |
| **Buffer Size** | 4096 bytes |

### 7.2 Formato de Mensaje JSON

```json
{
    "action": "DETECTION_TYPE",
    "message": "Detalles de la deteccion"
}
```

### 7.3 Tipos de Accion IPC

| Action (C++ -> C#) | Descripcion | Evento C# |
|--------------------|-------------|-----------|
| `DEBUGGER_DETECTED` | Debugger encontrado | `DebuggerDetected` |
| `INJECTION_ALERT` | DLL inyectada | `InjectionDetected` |
| `MEMORY_MODIFIED` | Memoria alterada | `MemoryModified` |
| `SUSPICIOUS_DLL` | DLL sospechosa | `SuspiciousDllLoaded` |
| `HOOK_DETECTED` | Hook detectado | `HookDetected` |
| `MACRO_DETECTED` | Macro/auto-click | `MacroDetected` |
| `FILE_MODIFIED` | Archivo alterado | `FileModified` |
| `CHEAT_DETECTED` | Cheat signature | `CheatDetected` |
| `HEARTBEAT` | Keep-alive | (solo log) |
| `STATUS` | Estado del DLL | (solo log) |

### 7.4 Mapeo DetectionType -> Action

```cpp
// IPCManager.cpp
std::string GetActionString(DetectionType type) {
    switch (type) {
        case DetectionType::DebuggerAttached: return "DEBUGGER_DETECTED";
        case DetectionType::InjectedDLL:      return "INJECTION_ALERT";
        case DetectionType::ModifiedMemory:   return "MEMORY_MODIFIED";
        case DetectionType::HookedAPI:
        case DetectionType::HookDetected:     return "HOOK_DETECTED";
        case DetectionType::MacroDetected:    return "MACRO_DETECTED";
        case DetectionType::FileModified:     return "FILE_MODIFIED";
        case DetectionType::CheatSignature:   return "CHEAT_DETECTED";
        case DetectionType::SuspiciousProcess:
        case DetectionType::SuspiciousModule: return "SUSPICIOUS_DLL";
        default:                              return "UNKNOWN";
    }
}
```

---

## 8. API Reference

### 8.1 Funciones Exportadas del DLL (anticheat_core.h)

#### Inicializacion
```cpp
ANTICHEAT_API bool AC_Initialize();
ANTICHEAT_API void AC_Shutdown();
ANTICHEAT_API const char* AC_GetVersion();
```

#### Deteccion de Procesos
```cpp
ANTICHEAT_API bool AC_ScanProcesses(char* detectedName, int bufferSize);
ANTICHEAT_API bool AC_AddToBlacklist(const char* processName);
ANTICHEAT_API void AC_ClearBlacklist();
ANTICHEAT_API int AC_GetBlacklistCount();
```

#### Anti-Debug
```cpp
ANTICHEAT_API uint32_t AC_DetectDebugger();  // Retorna flags
ANTICHEAT_API bool AC_DetectDebuggerProcess(char* debuggerName, int bufferSize);
```

#### Integridad de Memoria
```cpp
ANTICHEAT_API uint32_t AC_HashMemory(void* address, size_t size);
ANTICHEAT_API bool AC_VerifyModuleIntegrity(const char* moduleName, uint32_t expectedHash);
ANTICHEAT_API bool AC_ScanForInjectedDlls(char* injectedDll, int bufferSize);
ANTICHEAT_API bool AC_IsApiHooked(const char* moduleName, const char* functionName);
```

#### Memory Pattern Scanning
```cpp
ANTICHEAT_API bool AC_MemoryScanInit();
ANTICHEAT_API bool AC_AddCheatPattern(const char* name, const uint8_t* pattern,
                                       const bool* mask, int length);
ANTICHEAT_API bool AC_ScanProcessMemory(uint32_t processId, char* detectedPattern, int bufferSize);
ANTICHEAT_API bool AC_ScanCurrentProcess(char* detectedPattern, int bufferSize);
ANTICHEAT_API bool AC_DetectCodeModification(void* codeStart, size_t codeSize, uint32_t originalHash);
ANTICHEAT_API bool AC_DetectCodeCaves(char* details, int bufferSize);
```

#### File Protection
```cpp
ANTICHEAT_API bool AC_FileProtectionInit();
ANTICHEAT_API void AC_FileProtectionShutdown();
ANTICHEAT_API bool AC_ProtectFile(const wchar_t* filePath);
ANTICHEAT_API bool AC_ProtectFileA(const char* filePath);
ANTICHEAT_API bool AC_UnprotectFile(const wchar_t* filePath);
ANTICHEAT_API bool AC_VerifyFileIntegrity(const wchar_t* filePath);
ANTICHEAT_API bool AC_VerifyAllFiles(char* failedFile, int bufferSize);
ANTICHEAT_API bool AC_StartFileMonitoring();
ANTICHEAT_API void AC_StopFileMonitoring();
ANTICHEAT_API int AC_GetProtectedFileCount();
ANTICHEAT_API uint32_t AC_GetFileHash(const wchar_t* filePath);
ANTICHEAT_API int AC_ProtectDirectory(const wchar_t* dirPath, const wchar_t* pattern);
```

#### Encryption
```cpp
ANTICHEAT_API bool AC_EncryptionInit();
ANTICHEAT_API bool AC_GenerateSessionKey();
ANTICHEAT_API bool AC_SetSessionKey(const uint8_t* key, int keyLength);
ANTICHEAT_API bool AC_GetSessionKey(uint8_t* keyBuffer, int bufferSize);
ANTICHEAT_API bool AC_XorEncrypt(uint8_t* data, int dataLength, const uint8_t* key, int keyLength);
ANTICHEAT_API bool AC_XorDecrypt(uint8_t* data, int dataLength, const uint8_t* key, int keyLength);
ANTICHEAT_API bool AC_RC4Encrypt(uint8_t* data, int dataLength, const uint8_t* key, int keyLength);
ANTICHEAT_API bool AC_RC4Decrypt(uint8_t* data, int dataLength, const uint8_t* key, int keyLength);
ANTICHEAT_API bool AC_GenerateRandom(uint8_t* buffer, int length);
ANTICHEAT_API uint32_t AC_HashData(const uint8_t* data, int length);
ANTICHEAT_API uint32_t AC_HashString(const char* str);
ANTICHEAT_API void AC_SecureClear(uint8_t* buffer, size_t length);
```

#### Hook Detection
```cpp
ANTICHEAT_API bool AC_HookDetectionInit();
ANTICHEAT_API bool AC_DetectInlineHook(const char* moduleName, const char* functionName,
                                        char* hookDetails, int bufferSize);
ANTICHEAT_API bool AC_DetectIATHook(const char* targetModule, const char* importModule,
                                     const char* functionName, char* hookDetails, int bufferSize);
ANTICHEAT_API int AC_ScanCommonHooks(char* report, int reportSize);
ANTICHEAT_API bool AC_DetectVEHHooks();
ANTICHEAT_API bool AC_DetectHardwareBreakpoints();
```

#### Anti-Macro
```cpp
ANTICHEAT_API bool AC_AntiMacroInit();
ANTICHEAT_API void AC_AntiMacroShutdown();
ANTICHEAT_API bool AC_StartInputMonitoring();
ANTICHEAT_API void AC_StopInputMonitoring();
ANTICHEAT_API bool AC_IsInputMonitoringActive();
ANTICHEAT_API bool AC_DetectAutoClicker(char* details, int bufferSize);
ANTICHEAT_API bool AC_DetectKeyboardMacro(char* details, int bufferSize);
ANTICHEAT_API void AC_GetClickStats(int* totalClicks, double* avgInterval,
                                     double* variance, int* suspiciousCount);
ANTICHEAT_API bool AC_DetectMacroSoftware(char* detectedName, int bufferSize);
```

#### IPC
```cpp
ANTICHEAT_API bool AC_IpcInitialize();
ANTICHEAT_API void AC_IpcShutdown();
ANTICHEAT_API bool AC_IpcIsConnected();
ANTICHEAT_API bool AC_IpcSendMessage(const char* message);
ANTICHEAT_API bool AC_IpcReportDetection(const char* detectionType, const char* details);
ANTICHEAT_API bool AC_IpcReportDllInjection(const char* dllPath);
ANTICHEAT_API bool AC_IpcReportDebugger(const char* debuggerInfo);
```

---

## 9. Guia de Uso

### 9.1 Iniciar el Sistema

```bash
# 1. Compilar proyectos
# Abrir Antihack.sln en Visual Studio
# Build -> Build Solution

# 2. Iniciar servidor
./ServerTCP/bin/Release/ServerAntiCheat.exe

# 3. Iniciar cliente
./Antihack/bin/Release/AntiCheat.exe
```

### 9.2 Uso desde C# (Cliente)

```csharp
// Ejemplo de uso del sistema
public class AntiCheatManager {
    private IpcServer _ipcServer;

    public void Initialize() {
        // 1. Inicializar modulo nativo
        if (!NativeInterop.Initialize()) {
            throw new Exception("Failed to initialize native module");
        }

        // 2. Inicializar IPC Server
        _ipcServer = new IpcServer();
        _ipcServer.DebuggerDetected += OnDebuggerDetected;
        _ipcServer.InjectionDetected += OnInjectionDetected;
        _ipcServer.HookDetected += OnHookDetected;
        _ipcServer.MacroDetected += OnMacroDetected;
        _ipcServer.Start();

        // 3. Inicializar proteccion de archivos
        NativeInterop.FileProtectionInit();
        NativeInterop.ProtectDirectory(@"C:\Game\Data", "*.pak");
        NativeInterop.StartFileMonitoring();

        // 4. Inicializar deteccion de macros
        NativeInterop.AntiMacroInit();
        NativeInterop.StartInputMonitoring();

        // 5. Inicializar deteccion de hooks
        NativeInterop.HookDetectionInit();
    }

    private void OnDebuggerDetected(object sender, IpcMessageEventArgs e) {
        Console.WriteLine($"ALERT: Debugger detected - {e.Message}");
        // Reportar al servidor y/o terminar aplicacion
    }

    private void OnInjectionDetected(object sender, IpcMessageEventArgs e) {
        Console.WriteLine($"ALERT: DLL Injection - {e.Message}");
    }

    private void OnHookDetected(object sender, IpcMessageEventArgs e) {
        Console.WriteLine($"ALERT: Hook detected - {e.Message}");
    }

    private void OnMacroDetected(object sender, IpcMessageEventArgs e) {
        Console.WriteLine($"ALERT: Macro detected - {e.Message}");
    }

    public void RunSecurityChecks() {
        // Verificar debugger
        var debugFlags = NativeInterop.DetectDebugger();
        if (debugFlags != DebuggerDetectionFlags.None) {
            Console.WriteLine($"Debugger detected: {debugFlags}");
        }

        // Verificar DLLs inyectadas
        if (NativeInterop.ScanForInjectedDlls(out string injectedDll)) {
            Console.WriteLine($"Injected DLL found: {injectedDll}");
        }

        // Verificar hooks
        int hookCount = NativeInterop.ScanCommonHooks(out string hookReport);
        if (hookCount > 0) {
            Console.WriteLine($"Hooks detected: {hookCount}\n{hookReport}");
        }

        // Verificar integridad de archivos
        if (NativeInterop.VerifyAllFiles(out string failedFile)) {
            Console.WriteLine($"File integrity check failed: {failedFile}");
        }

        // Verificar macros
        if (NativeInterop.DetectAutoClicker(out string clickerDetails)) {
            Console.WriteLine($"Auto-clicker detected: {clickerDetails}");
        }
    }

    public void Shutdown() {
        NativeInterop.StopInputMonitoring();
        NativeInterop.AntiMacroShutdown();
        NativeInterop.StopFileMonitoring();
        NativeInterop.FileProtectionShutdown();
        _ipcServer.Stop();
        _ipcServer.Dispose();
        NativeInterop.Shutdown();
    }
}
```

### 9.3 Uso desde C++ (DLL inyectada en juego)

```cpp
#include "anticheat_core.h"

// Callback para detecciones
void OnDetection(const char* type, const char* details) {
    // Enviar via IPC al cliente
    AC_IpcReportDetection(type, details);
}

// Inicializacion del modulo
bool InitializeAntiCheat() {
    // 1. Inicializar core
    if (!AC_Initialize()) {
        return false;
    }

    // 2. Conectar IPC
    if (!AC_IpcInitialize()) {
        AC_Shutdown();
        return false;
    }

    // 3. Configurar callback
    AC_SetDetectionCallback(OnDetection);

    // 4. Inicializar modulos
    AC_HookDetectionInit();
    AC_FileProtectionInit();
    AC_AntiMacroInit();
    AC_MemoryScanInit();

    // 5. Proteger archivos del juego
    AC_ProtectFile(L"C:\\Game\\data.pak");
    AC_ProtectFile(L"C:\\Game\\config.ini");
    AC_StartFileMonitoring();

    // 6. Agregar patrones de cheat
    uint8_t cheatPattern[] = { 0x90, 0x90, 0x90, 0xE9 };
    bool mask[] = { true, true, true, true };
    AC_AddCheatPattern("SpeedHack", cheatPattern, mask, 4);

    // 7. Iniciar monitoreo de input
    AC_StartInputMonitoring();

    return true;
}

// Loop de monitoreo (ejecutar en thread separado)
void MonitorLoop() {
    while (running) {
        // Verificar debugger
        uint32_t debugFlags = AC_DetectDebugger();
        if (debugFlags != 0) {
            AC_IpcReportDebugger("Debugger attached");
        }

        // Verificar hooks
        char hookReport[4096];
        int hookCount = AC_ScanCommonHooks(hookReport, sizeof(hookReport));
        if (hookCount > 0) {
            AC_IpcReportDetection("HOOK_DETECTED", hookReport);
        }

        // Verificar integridad de archivos
        char failedFile[512];
        if (AC_VerifyAllFiles(failedFile, sizeof(failedFile))) {
            AC_IpcReportDetection("FILE_MODIFIED", failedFile);
        }

        // Verificar patrones de cheat en memoria
        char detectedPattern[256];
        if (AC_ScanCurrentProcess(detectedPattern, sizeof(detectedPattern))) {
            AC_IpcReportDetection("CHEAT_DETECTED", detectedPattern);
        }

        // Enviar heartbeat
        AC_IpcSendMessage("{\"action\":\"HEARTBEAT\"}");

        Sleep(100);  // 10 checks por segundo
    }
}

// Shutdown
void ShutdownAntiCheat() {
    AC_StopInputMonitoring();
    AC_AntiMacroShutdown();
    AC_StopFileMonitoring();
    AC_FileProtectionShutdown();
    AC_IpcShutdown();
    AC_Shutdown();
}
```

---

## 10. Configuracion

### 10.1 Archivo de Configuracion (config.ini / ext11c.dll)

```ini
[CONFIG]
GAME=PointBlank              ; Nombre del ejecutable del juego
IPV4=192.168.1.100           ; IP del servidor (IPv4)
IPV6=::1                     ; IP del servidor (IPv6)
PORT=8888                    ; Puerto TCP
KEY=your_secret_key          ; Clave de autenticacion

[network]
priority=ipv4                ; Prioridad: ipv4 o ipv6
fallback=true                ; Habilitar fallback a otro protocolo

[monitoring]
scan_interval=100            ; Intervalo de escaneo en ms
heartbeat_interval=120000    ; Intervalo de heartbeat en ms

[detection]
debugger=true                ; Detectar debuggers
hooks=true                   ; Detectar hooks
macros=true                  ; Detectar macros
files=true                   ; Monitorear archivos
memory=true                  ; Verificar integridad de memoria
```

### 10.2 Lista Negra de Procesos (Parcial)

```csharp
// AntiCheatForm.cs - Procesos detectados
private static readonly HashSet<string> BlacklistedProcesses = new HashSet<string> {
    // Debuggers
    "ollydbg", "x64dbg", "x32dbg", "windbg", "ida", "ida64",
    "radare2", "ghidra", "immunity debugger",

    // Cheat Engines
    "cheatengine", "cheat engine", "ce-x64", "ce-x32",

    // Injectors
    "extremeinjector", "xenos", "process hacker",

    // Macro Software
    "autohotkey", "autoit", "macro recorder",
    "razer synapse", "logitech gaming software",

    // Network Analysis
    "wireshark", "fiddler", "charles", "burpsuite",

    // Virtual Machines
    "vmware", "virtualbox", "vbox",

    // Reverse Engineering
    "dnspy", "de4dot", "ilspy", "dotpeek"

    // ... 925+ procesos en total
};
```

---

## Apendice A: Diagrama de Clases (C++)

```
                    ┌─────────────────────┐
                    │   IMonitorModule    │
                    │     (abstract)      │
                    ├─────────────────────┤
                    │ - m_state           │
                    │ - m_dataMutex       │
                    │ - m_callbackMutex   │
                    │ - m_pendingEvents   │
                    ├─────────────────────┤
                    │ + Start()           │
                    │ + Stop()            │
                    │ + SetCallback()     │
                    │ # DoMonitorCycle()  │
                    │ # QueueEvent()      │
                    └─────────┬───────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ ProcessMonitor  │ │  HookDetector   │ │  MacroDetector  │
├─────────────────┤ ├─────────────────┤ ├─────────────────┤
│ - m_blacklist   │ │ - m_detectedHooks│ │ - m_clickTimes │
│ - m_loadedDlls  │ │ - m_apiCache    │ │ - m_keyTimes   │
├─────────────────┤ ├─────────────────┤ ├─────────────────┤
│ + ScanProcesses │ │ + DetectInline  │ │ + DetectMacro  │
│ + DetectInjection│ │ + DetectIAT    │ │ + GetClickStats│
└─────────────────┘ └─────────────────┘ └─────────────────┘

          │                   │                   │
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ OverlayDetector │ │ FileProtection  │ │ SelfProtection  │
├─────────────────┤ ├─────────────────┤ ├─────────────────┤
│ - m_gameRect    │ │ - m_protectedFiles│ │ - m_threads   │
│ - m_overlays    │ │ - m_fileHashes  │ │ - m_watchdog   │
├─────────────────┤ ├─────────────────┤ ├─────────────────┤
│ + DetectOverlay │ │ + ProtectFile   │ │ + EnableProtection│
│ + EnumWindows   │ │ + VerifyIntegrity│ │ + RecoverThreads│
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

---

## Apendice B: Codigo de Error

| Codigo | Descripcion |
|--------|-------------|
| 0x0001 | Inicializacion fallida |
| 0x0002 | Pipe no disponible |
| 0x0003 | Conexion perdida |
| 0x0004 | Autenticacion fallida |
| 0x0005 | Timeout de heartbeat |
| 0x0006 | Archivo no encontrado |
| 0x0007 | Memoria no accesible |
| 0x0008 | Patron no encontrado |
| 0x0009 | Buffer insuficiente |
| 0x000A | Operacion no permitida |

---

## Apendice C: Checklist de Seguridad

- [ ] Verificar que el servidor esta ejecutandose
- [ ] Verificar conectividad TCP (IPv4/IPv6)
- [ ] Verificar que Named Pipe esta activo
- [ ] Verificar que la DLL esta inyectada
- [ ] Verificar autenticacion exitosa
- [ ] Verificar que heartbeat se envia regularmente
- [ ] Verificar que archivos del juego estan protegidos
- [ ] Verificar que monitoreo de input esta activo
- [ ] Verificar que deteccion de hooks esta activa
- [ ] Verificar logs del servidor

---

*Documentacion generada para AntiCheat System v1.0*
*Ultima actualizacion: 2026-02-03*
