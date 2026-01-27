// -----------------------------------------
// Código de la DLL que será inyectada
// Este código necesitaría ser compilado como una DLL separada
// -----------------------------------------

using System.IO;
using System.Runtime.InteropServices;
using System;
using System.Diagnostics;
using System.Threading;

namespace HookLibrary
{
    /// <summary>
    /// Punto de entrada de la DLL
    /// </summary>
    public class HookEntryPoint
    {
        // Constante para crear la consola de depuración
        private const int ATTACH_PARENT_PROCESS = -1;

        [DllImport("kernel32.dll")]
        private static extern bool AllocConsole();

        [DllImport("kernel32.dll")]
        private static extern bool AttachConsole(int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool FreeConsole();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetStdHandle(int nStdHandle, IntPtr handle);

        // DllMain equivalente gestionado
        public static bool DllMain(IntPtr hinstDLL, int fdwReason, IntPtr lpvReserved)
        {
            switch (fdwReason)
            {
                case 1: // DLL_PROCESS_ATTACH
                    // Crear consola para debug si es necesario
                    bool consoleAttached = AttachConsole(ATTACH_PARENT_PROCESS);
                    if (!consoleAttached)
                    {
                        AllocConsole();
                    }

                    // Iniciar una tarea para instalar los hooks
                    Thread hookThread = new Thread(InstallHooks);
                    hookThread.Start();
                    return true;
            }

            return true;
        }

        private static void InstallHooks()
        {
            try
            {
                // Configuración inicial
                Process currentProcess = Process.GetCurrentProcess();
                Console.WriteLine($"[HookLibrary] Iniciando hooks en proceso: {currentProcess.ProcessName} (ID: {currentProcess.Id})");

                // Instalar hooks
                WindowsApiHooks.InstallHooks();

                Console.WriteLine("[HookLibrary] Hooks instalados exitosamente");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[HookLibrary] Error al instalar hooks: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }
    }

    /// <summary>
    /// Implementación de hooks para funciones de Windows API
    /// </summary>
    public static class WindowsApiHooks
    {
        #region Delegates y punteros originales

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
        public delegate IntPtr LoadLibraryA_Delegate(string lpFileName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate IntPtr LoadLibraryW_Delegate(string lpFileName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool WriteProcessMemory_Delegate(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out UIntPtr lpNumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateRemoteThread_Delegate(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            out IntPtr lpThreadId);

        // Almacenamos los punteros a las funciones originales
        private static IntPtr pOrigLoadLibraryA;
        private static IntPtr pOrigLoadLibraryW;
        private static IntPtr pOrigWriteProcessMemory;
        private static IntPtr pOrigCreateRemoteThread;

        // Delegates para las funciones originales
        private static LoadLibraryA_Delegate OrigLoadLibraryA;
        private static LoadLibraryW_Delegate OrigLoadLibraryW;
        private static WriteProcessMemory_Delegate OrigWriteProcessMemory;
        private static CreateRemoteThread_Delegate OrigCreateRemoteThread;

        #endregion

        #region Imports

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibraryA(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibraryW(string lpFileName);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            out IntPtr lpThreadId);

        // Métodos para instalar/desinstalar hooks a nivel de función
        [DllImport("hook_engine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern bool InstallHook(IntPtr targetFunction, IntPtr hookFunction, out IntPtr originalFunction);

        [DllImport("hook_engine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern bool RemoveHook(IntPtr targetFunction);

        #endregion

        #region Hooks implementados

        // Hook para LoadLibraryA
        public static IntPtr Hook_LoadLibraryA(string lpFileName)
        {
            // Registro de la llamada
            LogHookCall("LoadLibraryA", $"Cargando biblioteca: {lpFileName}");

            // Verifica si la DLL está en una lista negra
            if (IsBlacklistedDll(lpFileName))
            {
                LogHookCall("LoadLibraryA", $"¡Bloqueando carga de biblioteca sospechosa!: {lpFileName}");
                return IntPtr.Zero;
            }

            // Llamar a la función original
            return OrigLoadLibraryA(lpFileName);
        }

        // Hook para LoadLibraryW
        public static IntPtr Hook_LoadLibraryW(string lpFileName)
        {
            LogHookCall("LoadLibraryW", $"Cargando biblioteca: {lpFileName}");

            if (IsBlacklistedDll(lpFileName))
            {
                LogHookCall("LoadLibraryW", $"¡Bloqueando carga de biblioteca sospechosa!: {lpFileName}");
                return IntPtr.Zero;
            }

            return OrigLoadLibraryW(lpFileName);
        }

        // Hook para WriteProcessMemory
        public static bool Hook_WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out UIntPtr lpNumberOfBytesWritten)
        {
            Process targetProcess = null;
            try
            {
                targetProcess = Process.GetProcessById(hProcess.ToInt32());
                LogHookCall("WriteProcessMemory", $"Escribiendo en proceso: {targetProcess.ProcessName} (ID: {targetProcess.Id})");
                LogHookCall("WriteProcessMemory", $"Dirección base: 0x{lpBaseAddress.ToInt64():X}, Tamaño: {nSize} bytes");
            }
            catch
            {
                LogHookCall("WriteProcessMemory", $"Escribiendo en proceso con handle: 0x{hProcess.ToInt64():X}");
            }

            // Análisis de buffer opcional
            AnalyzeBuffer(lpBuffer, nSize);

            // Podemos bloquear escrituras a ciertos procesos
            if (IsProtectedProcess(hProcess))
            {
                LogHookCall("WriteProcessMemory", "¡Bloqueando escritura a proceso protegido!");
                lpNumberOfBytesWritten = UIntPtr.Zero;
                return false;
            }

            // Llamar a la función original
            return OrigWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, out lpNumberOfBytesWritten);
        }

        // Hook para CreateRemoteThread
        public static IntPtr Hook_CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            out IntPtr lpThreadId)
        {
            Process targetProcess = null;
            try
            {
                targetProcess = Process.GetProcessById(hProcess.ToInt32());
                LogHookCall("CreateRemoteThread", $"Creando hilo en proceso: {targetProcess.ProcessName} (ID: {targetProcess.Id})");
            }
            catch
            {
                LogHookCall("CreateRemoteThread", $"Creando hilo en proceso con handle: 0x{hProcess.ToInt64():X}");
            }

            LogHookCall("CreateRemoteThread", $"Dirección de inicio: 0x{lpStartAddress.ToInt64():X}");

            // Verificar si es una inyección sospechosa
            bool isSuspicious = IsSuspiciousThreadCreation(hProcess, lpStartAddress);
            if (isSuspicious)
            {
                LogHookCall("CreateRemoteThread", "¡Bloqueando creación de hilo sospechosa!");
                lpThreadId = IntPtr.Zero;
                return IntPtr.Zero;
            }

            // Llamar a la función original
            return OrigCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, out lpThreadId);
        }

        #endregion

        #region Helpers

        private static bool IsBlacklistedDll(string dllName)
        {
            string lowerName = dllName.ToLower();
            string[] blacklist = {
                "malicious", "hacker", "keylogger", "stealer", "injector"
            };

            foreach (string term in blacklist)
            {
                if (lowerName.Contains(term))
                    return true;
            }

            return false;
        }

        private static bool IsProtectedProcess(IntPtr processHandle)
        {
            try
            {
                int processId = processHandle.ToInt32();
                Process process = Process.GetProcessById(processId);

                // Lista de procesos que queremos proteger
                string[] protectedProcesses = {
                    "explorer", "chrome", "firefox", "iexplore", "edge", "lsass"
                };

                foreach (string name in protectedProcesses)
                {
                    if (process.ProcessName.ToLower().Contains(name))
                        return true;
                }
            }
            catch { }

            return false;
        }

        private static bool IsSuspiciousThreadCreation(IntPtr processHandle, IntPtr startAddress)
        {
            // Verificar si la dirección de inicio parece sospechosa
            // (Este es un análisis simplificado - en producción sería más sofisticado)

            try
            {
                // Si la dirección está en una región de memoria recién asignada
                // esto podría ser sospechoso

                // En una implementación real, mantendríamos un registro de 
                // asignaciones de memoria recientes con VirtualAllocEx

                // Para este ejemplo, simplemente detectamos algunas regiones
                // comunes de inyección
                ulong addr = (ulong)startAddress.ToInt64();

                // Verificar si está en regiones típicas de inyección
                if (addr < 0x10000 || addr > 0x7FFFFFFF0000)
                {
                    return true;
                }
            }
            catch { }

            return false;
        }

        private static void AnalyzeBuffer(byte[] buffer, uint size)
        {
            if (buffer == null || size <= 0 || buffer.Length < size)
                return;

            // Buscar patrones sospechosos en el buffer
            // Por ejemplo, podríamos buscar shellcode conocido

            // Este es un ejemplo muy básico que busca MZ header (típico de DLLs/EXEs)
            if (size >= 2 && buffer[0] == 'M' && buffer[1] == 'Z')
            {
                LogHookCall("AnalyzeBuffer", "¡Detectado posible PE (DLL/EXE) en buffer!");
            }

            // Buscar secuencias de código comunes en shellcode
            SearchForShellcodePatterns(buffer, size);
        }

        private static void SearchForShellcodePatterns(byte[] buffer, uint size)
        {
            if (buffer == null || size < 10)
                return;

            // Buscar patrones comunes de shellcode
            // (Esto es simplificado; un detector real tendría más patrones)

            // Ejemplo: buscar "call dword ptr [eax]" (FF 10)
            for (int i = 0; i < size - 1; i++)
            {
                if (buffer[i] == 0xFF && buffer[i + 1] == 0x10)
                {
                    LogHookCall("SearchForShellcodePatterns", $"Posible shellcode detectado en offset {i}");
                    break;
                }
            }
        }

        private static void LogHookCall(string hookName, string message)
        {
            string logMessage = $"[{DateTime.Now:HH:mm:ss.fff}] [{hookName}] {message}";
            Console.WriteLine(logMessage);

            // Opcionalmente, guardar en archivo
            try
            {
                string logPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "HookLogs",
                    $"hook_log_{Process.GetCurrentProcess().Id}.txt");

                Directory.CreateDirectory(Path.GetDirectoryName(logPath));

                using (StreamWriter writer = File.AppendText(logPath))
                {
                    writer.WriteLine(logMessage);
                }
            }
            catch { }
        }

        #endregion

        #region Instalación / Desinstalación

        public static bool InstallHooks()
        {
            try
            {
                // Obtenemos los handles y punteros necesarios
                IntPtr kernel32 = GetModuleHandle("kernel32.dll");
                if (kernel32 == IntPtr.Zero)
                {
                    LogHookCall("InstallHooks", "No se pudo obtener handle de kernel32.dll");
                    return false;
                }

                // Obtenemos las direcciones de las funciones originales
                IntPtr pLoadLibraryA = GetProcAddress(kernel32, "LoadLibraryA");
                IntPtr pLoadLibraryW = GetProcAddress(kernel32, "LoadLibraryW");
                IntPtr pWriteProcessMemory = GetProcAddress(kernel32, "WriteProcessMemory");
                IntPtr pCreateRemoteThread = GetProcAddress(kernel32, "CreateRemoteThread");

                if (pLoadLibraryA == IntPtr.Zero || pLoadLibraryW == IntPtr.Zero ||
                    pWriteProcessMemory == IntPtr.Zero || pCreateRemoteThread == IntPtr.Zero)
                {
                    LogHookCall("InstallHooks", "No se pudieron obtener direcciones de funciones");
                    return false;
                }

                // Crear delegates para nuestros hooks
                LoadLibraryA_Delegate hookLoadLibraryA = new LoadLibraryA_Delegate(Hook_LoadLibraryA);
                LoadLibraryW_Delegate hookLoadLibraryW = new LoadLibraryW_Delegate(Hook_LoadLibraryW);
                WriteProcessMemory_Delegate hookWriteProcessMemory = new WriteProcessMemory_Delegate(Hook_WriteProcessMemory);
                CreateRemoteThread_Delegate hookCreateRemoteThread = new CreateRemoteThread_Delegate(Hook_CreateRemoteThread);

                // Obtener punteros a nuestros hooks
                IntPtr pHookLoadLibraryA = Marshal.GetFunctionPointerForDelegate(hookLoadLibraryA);
                IntPtr pHookLoadLibraryW = Marshal.GetFunctionPointerForDelegate(hookLoadLibraryW);
                IntPtr pHookWriteProcessMemory = Marshal.GetFunctionPointerForDelegate(hookWriteProcessMemory);
                IntPtr pHookCreateRemoteThread = Marshal.GetFunctionPointerForDelegate(hookCreateRemoteThread);

                // Instalar los hooks
                bool success = true;

                if (InstallHook(pLoadLibraryA, pHookLoadLibraryA, out pOrigLoadLibraryA))
                {
                    OrigLoadLibraryA = Marshal.GetDelegateForFunctionPointer<LoadLibraryA_Delegate>(pOrigLoadLibraryA);
                    LogHookCall("InstallHooks", "Hook de LoadLibraryA instalado");
                }
                else
                {
                    LogHookCall("InstallHooks", "Error al instalar hook de LoadLibraryA");
                    success = false;
                }

                if (InstallHook(pLoadLibraryW, pHookLoadLibraryW, out pOrigLoadLibraryW))
                {
                    OrigLoadLibraryW = Marshal.GetDelegateForFunctionPointer<LoadLibraryW_Delegate>(pOrigLoadLibraryW);
                    LogHookCall("InstallHooks", "Hook de LoadLibraryW instalado");
                }
                else
                {
                    LogHookCall("InstallHooks", "Error al instalar hook de LoadLibraryW");
                    success = false;
                }

                if (InstallHook(pWriteProcessMemory, pHookWriteProcessMemory, out pOrigWriteProcessMemory))
                {
                    OrigWriteProcessMemory = Marshal.GetDelegateForFunctionPointer<WriteProcessMemory_Delegate>(pOrigWriteProcessMemory);
                    LogHookCall("InstallHooks", "Hook de WriteProcessMemory instalado");
                }
                else
                {
                    LogHookCall("InstallHooks", "Error al instalar hook de WriteProcessMemory");
                    success = false;
                }

                if (InstallHook(pCreateRemoteThread, pHookCreateRemoteThread, out pOrigCreateRemoteThread))
                {
                    OrigCreateRemoteThread = Marshal.GetDelegateForFunctionPointer<CreateRemoteThread_Delegate>(pOrigCreateRemoteThread);
                    LogHookCall("InstallHooks", "Hook de CreateRemoteThread instalado");
                }
                else
                {
                    LogHookCall("InstallHooks", "Error al instalar hook de CreateRemoteThread");
                    success = false;
                }

                return success;
            }
            catch (Exception ex)
            {
                LogHookCall("InstallHooks", $"Excepción: {ex.Message}");
                LogHookCall("InstallHooks", ex.StackTrace);
                return false;
            }
        }
        #endregion
    }
}