using System;
using System.Runtime.InteropServices;
using System.Reflection;
using DetoursLibrary;
using System.Reflection.Emit;

namespace WindowsApiDetours
{
    /// <summary>
    /// Clase para interceptar funciones específicas de la Windows API
    /// </summary>
    public static class WindowsApiHooks
    {
        #region Definiciones de tipos nativos y delegates

        // Delegates para las funciones originales
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

        // Referencias a las funciones originales que preservamos
        public static LoadLibraryA_Delegate Original_LoadLibraryA;
        public static LoadLibraryW_Delegate Original_LoadLibraryW;
        public static WriteProcessMemory_Delegate Original_WriteProcessMemory;
        public static CreateRemoteThread_Delegate Original_CreateRemoteThread;

        #endregion

        #region Importaciones de DLL

        // Importaciones de las funciones originales
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr LoadLibraryA(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr LoadLibraryW(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            out IntPtr lpThreadId);

        #endregion

        #region Implementaciones de Hook

        // Funciones de hook que reemplazarán a las originales
        public static IntPtr Hook_LoadLibraryA(string lpFileName)
        {
            Console.WriteLine($"[HOOK] LoadLibraryA llamada con: {lpFileName}");

            // Aquí puedes implementar cualquier lógica adicional
            // Por ejemplo, bloquear ciertas DLLs o modificar el nombre de archivo

            if (lpFileName.ToLower().Contains("malicious"))
            {
                Console.WriteLine("[HOOK] Bloqueando carga de biblioteca potencialmente maliciosa");
                return IntPtr.Zero;
            }

            // Llamar a la función original
            return Original_LoadLibraryA(lpFileName);
        }

        public static IntPtr Hook_LoadLibraryW(string lpFileName)
        {
            Console.WriteLine($"[HOOK] LoadLibraryW llamada con: {lpFileName}");

            if (lpFileName.ToLower().Contains("malicious"))
            {
                Console.WriteLine("[HOOK] Bloqueando carga de biblioteca potencialmente maliciosa");
                return IntPtr.Zero;
            }

            return Original_LoadLibraryW(lpFileName);
        }

        public static bool Hook_WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out UIntPtr lpNumberOfBytesWritten)
        {
            Console.WriteLine($"[HOOK] WriteProcessMemory llamada a proceso con handle: {hProcess}");
            Console.WriteLine($"[HOOK] Dirección base: 0x{lpBaseAddress.ToInt64():X}, Tamaño: {nSize} bytes");

            // Puedes analizar el buffer aquí o bloquear escrituras a ciertos procesos

            return Original_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, out lpNumberOfBytesWritten);
        }

        public static IntPtr Hook_CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            out IntPtr lpThreadId)
        {
            Console.WriteLine($"[HOOK] CreateRemoteThread llamada para proceso con handle: {hProcess}");
            Console.WriteLine($"[HOOK] Dirección de inicio: 0x{lpStartAddress.ToInt64():X}");

            // Puedes implementar lógica para bloquear ciertos procesos o direcciones sospechosas

            return Original_CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize,
                                             lpStartAddress, lpParameter, dwCreationFlags, out lpThreadId);
        }

        #endregion

        #region Utilitarios para instalación/desinstalación de hooks

        public static void InstallHooks()
        {
            try
            {
                // Obtener MethodInfo para las funciones nativas usando GetMethod desde DllImportResolver
                MethodInfo loadLibraryA_Method = typeof(WindowsApiHooks).GetMethod("LoadLibraryA");
                MethodInfo loadLibraryW_Method = typeof(WindowsApiHooks).GetMethod("LoadLibraryW");
                MethodInfo writeProcessMemory_Method = typeof(WindowsApiHooks).GetMethod("WriteProcessMemory");
                MethodInfo createRemoteThread_Method = typeof(WindowsApiHooks).GetMethod("CreateRemoteThread");

                // Guardar las referencias a las funciones originales
                Original_LoadLibraryA = Marshal.GetDelegateForFunctionPointer<LoadLibraryA_Delegate>(
                    GetNativeFunctionAddress("kernel32.dll", "LoadLibraryA"));

                Original_LoadLibraryW = Marshal.GetDelegateForFunctionPointer<LoadLibraryW_Delegate>(
                    GetNativeFunctionAddress("kernel32.dll", "LoadLibraryW"));

                Original_WriteProcessMemory = Marshal.GetDelegateForFunctionPointer<WriteProcessMemory_Delegate>(
                    GetNativeFunctionAddress("kernel32.dll", "WriteProcessMemory"));

                Original_CreateRemoteThread = Marshal.GetDelegateForFunctionPointer<CreateRemoteThread_Delegate>(
                    GetNativeFunctionAddress("kernel32.dll", "CreateRemoteThread"));

                // Aplicar los detours
                bool hookLoadLibraryA = DetourNativeFunction(
                    "kernel32.dll",
                    "LoadLibraryA",
                    typeof(WindowsApiHooks).GetMethod("Hook_LoadLibraryA", BindingFlags.Public | BindingFlags.Static));

                bool hookLoadLibraryW = DetourNativeFunction(
                    "kernel32.dll",
                    "LoadLibraryW",
                    typeof(WindowsApiHooks).GetMethod("Hook_LoadLibraryW", BindingFlags.Public | BindingFlags.Static));

                bool hookWriteProcessMemory = DetourNativeFunction(
                    "kernel32.dll",
                    "WriteProcessMemory",
                    typeof(WindowsApiHooks).GetMethod("Hook_WriteProcessMemory", BindingFlags.Public | BindingFlags.Static));

                bool hookCreateRemoteThread = DetourNativeFunction(
                    "kernel32.dll",
                    "CreateRemoteThread",
                    typeof(WindowsApiHooks).GetMethod("Hook_CreateRemoteThread", BindingFlags.Public | BindingFlags.Static));

                Console.WriteLine($"Instalación de hooks:");
                Console.WriteLine($"- LoadLibraryA: {(hookLoadLibraryA ? "Éxito" : "Fallido")}");
                Console.WriteLine($"- LoadLibraryW: {(hookLoadLibraryW ? "Éxito" : "Fallido")}");
                Console.WriteLine($"- WriteProcessMemory: {(hookWriteProcessMemory ? "Éxito" : "Fallido")}");
                Console.WriteLine($"- CreateRemoteThread: {(hookCreateRemoteThread ? "Éxito" : "Fallido")}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al instalar hooks: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }

        public static void RemoveHooks()
        {
            try
            {
                // Remover los detours
                bool unhookLoadLibraryA = RemoveNativeDetour("kernel32.dll", "LoadLibraryA");
                bool unhookLoadLibraryW = RemoveNativeDetour("kernel32.dll", "LoadLibraryW");
                bool unhookWriteProcessMemory = RemoveNativeDetour("kernel32.dll", "WriteProcessMemory");
                bool unhookCreateRemoteThread = RemoveNativeDetour("kernel32.dll", "CreateRemoteThread");

                Console.WriteLine($"Desinstalación de hooks:");
                Console.WriteLine($"- LoadLibraryA: {(unhookLoadLibraryA ? "Éxito" : "Fallido")}");
                Console.WriteLine($"- LoadLibraryW: {(unhookLoadLibraryW ? "Éxito" : "Fallido")}");
                Console.WriteLine($"- WriteProcessMemory: {(unhookWriteProcessMemory ? "Éxito" : "Fallido")}");
                Console.WriteLine($"- CreateRemoteThread: {(unhookCreateRemoteThread ? "Éxito" : "Fallido")}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al remover hooks: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }

        #endregion

        #region Métodos auxiliares para trabajar con funciones nativas

        private static bool DetourNativeFunction(string moduleName, string functionName, MethodInfo replacementMethod)
        {
            try
            {
                IntPtr functionPtr = GetNativeFunctionAddress(moduleName, functionName);
                if (functionPtr == IntPtr.Zero)
                {
                    Console.WriteLine($"No se pudo obtener dirección para {moduleName}.{functionName}");
                    return false;
                }

                // Crear un MethodInfo para la función nativa
                MethodInfo nativeMethod = CreateMethodInfoFromNative(functionPtr);

                // Aplicar el detour
                return Detours.Apply(nativeMethod, replacementMethod);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error en DetourNativeFunction: {ex.Message}");
                return false;
            }
        }

        private static bool RemoveNativeDetour(string moduleName, string functionName)
        {
            try
            {
                IntPtr functionPtr = GetNativeFunctionAddress(moduleName, functionName);
                if (functionPtr == IntPtr.Zero)
                {
                    Console.WriteLine($"No se pudo obtener dirección para {moduleName}.{functionName}");
                    return false;
                }

                // Crear un MethodInfo para la función nativa
                MethodInfo nativeMethod = CreateMethodInfoFromNative(functionPtr);

                // Remover el detour
                return Detours.Remove(nativeMethod);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error en RemoveNativeDetour: {ex.Message}");
                return false;
            }
        }

        private static IntPtr GetNativeFunctionAddress(string moduleName, string functionName)
        {
            IntPtr moduleHandle = GetModuleHandle(moduleName);
            if (moduleHandle == IntPtr.Zero)
            {
                moduleHandle = LoadLibraryA(moduleName);
                if (moduleHandle == IntPtr.Zero)
                {
                    throw new Exception($"No se pudo cargar la biblioteca {moduleName}");
                }
            }

            IntPtr functionPtr = GetProcAddress(moduleHandle, functionName);
            if (functionPtr == IntPtr.Zero)
            {
                throw new Exception($"No se pudo encontrar la función {functionName} en {moduleName}");
            }

            return functionPtr;
        }

        private static MethodInfo CreateMethodInfoFromNative(IntPtr functionPtr)
        {
            // Necesitamos crear un wrapper para el método nativo
            // Esta es una solución parcial ya que no tenemos acceso completo a la información del método nativo

            // En una implementación real, necesitaríamos extender la biblioteca DetourLibrary
            // para manejar directamente punteros a funciones nativas sin depender de MethodInfo

            // Esta es una simulación simplificada:
            DynamicMethod dynamicMethod = new DynamicMethod(
                $"NativeMethod_{functionPtr.ToInt64():X}",
                typeof(void),
                Type.EmptyTypes,
                typeof(WindowsApiHooks),
                true);

            // Devolvemos el MethodInfo, aunque esto no es una solución completa
            return dynamicMethod.GetBaseDefinition();
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        #endregion
    }

    /// <summary>
    /// Clase de demostración para el uso de los hooks
    /// </summary>
    //public class ApiHookDemo
    //{
    //    public static void Main()
    //    {
    //        Console.WriteLine("Instalando hooks a funciones de la Windows API...");
    //        WindowsApiHooks.InstallHooks();

    //        Console.WriteLine("\nProbando LoadLibraryA...");
    //        IntPtr testLib = WindowsApiHooks.LoadLibraryA("user32.dll");
    //        Console.WriteLine($"Handle de biblioteca cargada: 0x{testLib.ToInt64():X}");

    //        Console.WriteLine("\nProbando carga de biblioteca potencialmente maliciosa (será bloqueada)...");
    //        IntPtr maliciousLib = WindowsApiHooks.LoadLibraryA("malicious.dll");
    //        Console.WriteLine($"Handle de biblioteca maliciosa: 0x{maliciousLib.ToInt64():X} (Debería ser 0)");

    //        Console.WriteLine("\nRemoviendo hooks...");
    //        WindowsApiHooks.RemoveHooks();

    //        Console.WriteLine("\nDemo completada. Presione cualquier tecla para salir.");
    //        Console.ReadKey();
    //    }
    //}
}