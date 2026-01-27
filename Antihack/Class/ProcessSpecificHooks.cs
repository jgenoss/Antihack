using System.Runtime.InteropServices;
using System.Text;
using System;
using System.Diagnostics;
using System.IO;

namespace ProcessSpecificHooks
{
    /// <summary>
    /// Clase principal para inyectar hooks en un proceso específico
    /// </summary>
    public class ProcessInjector
    {
        #region Estructuras y Constantes

        private const int PROCESS_CREATE_THREAD = 0x0002;
        private const int PROCESS_QUERY_INFORMATION = 0x0400;
        private const int PROCESS_VM_OPERATION = 0x0008;
        private const int PROCESS_VM_WRITE = 0x0020;
        private const int PROCESS_VM_READ = 0x0010;
        private const int MEM_COMMIT = 0x00001000;
        private const int MEM_RESERVE = 0x00002000;
        private const int PAGE_READWRITE = 0x04;
        private const int PAGE_EXECUTE_READWRITE = 0x40;

        #endregion

        #region DLL Imports

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

        #endregion

        /// <summary>
        /// Inyecta la DLL de hooks en un proceso específico por nombre
        /// </summary>
        /// <param name="processName">Nombre del proceso objetivo (sin .exe)</param>
        /// <param name="dllPath">Ruta completa a la DLL que contiene los hooks</param>
        /// <returns>True si la inyección fue exitosa</returns>
        public static bool InjectHookDll(string processName, string dllPath)
        {
            if (!File.Exists(dllPath))
            {
                Console.WriteLine($"Error: No se encontró la DLL en la ruta: {dllPath}");
                return false;
            }

            Process[] processes = Process.GetProcessesByName(processName);
            if (processes.Length == 0)
            {
                Console.WriteLine($"Error: No se encontró ningún proceso con el nombre: {processName}");
                return false;
            }

            // Si hay múltiples procesos con el mismo nombre, permitir al usuario elegir
            Process targetProcess = null;
            if (processes.Length > 1)
            {
                Console.WriteLine($"Se encontraron {processes.Length} procesos con el nombre {processName}:");
                for (int i = 0; i < processes.Length; i++)
                {
                    Console.WriteLine($"[{i}] ID: {processes[i].Id}, Título de ventana: {processes[i].MainWindowTitle}");
                }

                Console.Write("Seleccione el número del proceso al que desea inyectar: ");
                if (int.TryParse(Console.ReadLine(), out int selection) && selection >= 0 && selection < processes.Length)
                {
                    targetProcess = processes[selection];
                }
                else
                {
                    Console.WriteLine("Selección inválida. Usando el primer proceso.");
                    targetProcess = processes[0];
                }
            }
            else
            {
                targetProcess = processes[0];
            }

            Console.WriteLine($"Inyectando en proceso: {targetProcess.ProcessName} (ID: {targetProcess.Id})");
            return InjectDll(targetProcess.Id, dllPath);
        }

        /// <summary>
        /// Inyecta una DLL en un proceso específico por ID
        /// </summary>
        /// <param name="processId">ID del proceso objetivo</param>
        /// <param name="dllPath">Ruta completa a la DLL</param>
        /// <returns>True si la inyección fue exitosa</returns>
        private static bool InjectDll(int processId, string dllPath)
        {
            try
            {
                // Abrir el proceso con los permisos necesarios
                IntPtr processHandle = OpenProcess(
                    PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                    false, processId);

                if (processHandle == IntPtr.Zero)
                {
                    Console.WriteLine($"Error: No se pudo abrir el proceso. Código de error: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                try
                {
                    // Asignar memoria en el proceso objetivo para almacenar la ruta de la DLL
                    IntPtr dllPathAddress = VirtualAllocEx(
                        processHandle, IntPtr.Zero, (uint)(dllPath.Length + 1), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                    if (dllPathAddress == IntPtr.Zero)
                    {
                        Console.WriteLine($"Error: No se pudo asignar memoria en el proceso. Código de error: {Marshal.GetLastWin32Error()}");
                        return false;
                    }

                    // Escribir la ruta de la DLL en la memoria del proceso
                    byte[] dllPathBytes = Encoding.ASCII.GetBytes(dllPath);
                    if (!WriteProcessMemory(
                        processHandle, dllPathAddress, dllPathBytes, (uint)dllPathBytes.Length, out UIntPtr bytesWritten))
                    {
                        Console.WriteLine($"Error: No se pudo escribir en la memoria del proceso. Código de error: {Marshal.GetLastWin32Error()}");
                        VirtualFreeEx(processHandle, dllPathAddress, 0, 0x8000); // MEM_RELEASE
                        return false;
                    }

                    // Obtener la dirección de LoadLibraryA
                    IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                    if (loadLibraryAddr == IntPtr.Zero)
                    {
                        Console.WriteLine($"Error: No se pudo obtener la dirección de LoadLibraryA. Código de error: {Marshal.GetLastWin32Error()}");
                        VirtualFreeEx(processHandle, dllPathAddress, 0, 0x8000); // MEM_RELEASE
                        return false;
                    }

                    // Crear un hilo remoto que llame a LoadLibraryA con la ruta de nuestra DLL
                    IntPtr threadId;
                    IntPtr threadHandle = CreateRemoteThread(
                        processHandle, IntPtr.Zero, 0, loadLibraryAddr, dllPathAddress, 0, out threadId);

                    if (threadHandle == IntPtr.Zero)
                    {
                        Console.WriteLine($"Error: No se pudo crear el hilo remoto. Código de error: {Marshal.GetLastWin32Error()}");
                        VirtualFreeEx(processHandle, dllPathAddress, 0, 0x8000); // MEM_RELEASE
                        return false;
                    }

                    // Esperar a que el hilo termine (timeout de 5 segundos)
                    uint waitResult = WaitForSingleObject(threadHandle, 5000);
                    if (waitResult == 0) // WAIT_OBJECT_0
                    {
                        Console.WriteLine("DLL inyectada exitosamente");
                    }
                    else
                    {
                        Console.WriteLine($"Advertencia: Tiempo de espera agotado o error al esperar el hilo. Código: {waitResult}");
                    }

                    // Limpiar
                    CloseHandle(threadHandle);
                    VirtualFreeEx(processHandle, dllPathAddress, 0, 0x8000); // MEM_RELEASE
                    return true;
                }
                finally
                {
                    CloseHandle(processHandle);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error durante la inyección: {ex.Message}");
                return false;
            }
        }
    }
}