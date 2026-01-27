using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading;
using System.Timers;

namespace WindowsServices
{
    public partial class Service1 : ServiceBase
    {
        private System.Timers.Timer timer;
        private string process1Name = "anticheat"; // Cambia esto por el nombre del proceso 1 (sin .exe)
        private string process2Name = "pointblank"; // Cambia esto por el nombre del proceso 2 (sin .exe)

        public Service1()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            timer = new System.Timers.Timer(6000); // Se ejecuta cada 5 segundos
            timer.Elapsed += new ElapsedEventHandler(MonitorProcesses);
            timer.Start();
        }

        protected override void OnStop()
        {
            timer.Stop();
        }

        private void MonitorProcesses(object sender, ElapsedEventArgs e)
        {
            try
            {
                var process1 = Process.GetProcessesByName(process1Name).FirstOrDefault();
                var process2 = Process.GetProcessesByName(process2Name).FirstOrDefault();

                if (process1 == null || process2 == null)
                {
                    // Si falta uno de los procesos, cerrar el otro
                    process1?.Kill();
                    process2?.Kill();
                    EventLog.WriteEntry("Un proceso ha desaparecido, cerrando el otro.");

                    Thread.Sleep(3000);
                    this.Stop();
                }
                else
                {
                    // Reanudar procesos si están suspendidos
                    if (IsProcessSuspended(process1)) ResumeProcess(process1);
                    if (IsProcessSuspended(process2)) ResumeProcess(process2);
                }
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Error en la verificación de procesos: " + ex.Message);
            }
        }

        // Método para verificar si un proceso está suspendido
        private bool IsProcessSuspended(Process process)
        {
            try
            {
                var threads = process.Threads;
                foreach (ProcessThread thread in threads)
                {
                    if (thread.ThreadState == System.Diagnostics.ThreadState.Wait &&
                        thread.WaitReason == ThreadWaitReason.Suspended)
                    {
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }

        // Método para reanudar un proceso suspendido
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtResumeProcess(IntPtr processHandle);

        private void ResumeProcess(Process process)
        {
            if (process != null)
            {
                EventLog.WriteEntry($"Reanudando {process.ProcessName}...");
                NtResumeProcess(process.Handle);
            }
        }
    }
}
