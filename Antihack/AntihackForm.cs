using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Forms;
using Antihack.Properties;
//using System.Drawing;
using SimpleTcp;
using json_ext;
using System.Net;
using System.Net.NetworkInformation;

namespace Antihack
{
    public partial class AntihackForm : Form
    {
        private int port, num = 0;
        private string serverIp, keyrecep, game;
        private SimpleTcpClient client;
        private ClassJson json = new ClassJson();
        private encrypt_decrypt crypt = new encrypt_decrypt();
        private ProcessStartInfo startInfo = new ProcessStartInfo();
        private WebClient web = new WebClient();
        private string pach = Directory.GetCurrentDirectory();
        public AntihackForm()
        {
          InitializeComponent();
        }
        private void Form1_Load(object sender, EventArgs e)
        {
            CheckDLL();
            LoadDLL();
            ServerTCP();
            ClientConnect();
            this.ShowInTaskbar = false;
            LoadingBar.Width = 0;
        }
        private void ClientConnect()
        {
            try
            {
                client.Connect();
                //client.ConnectWithRetries(5);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Message", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Application.Exit();
            }
        }
        private void CheckDLL() {
            if (!File.Exists($"{pach}\\ext11c.dll"))
            {
                MessageBox.Show("Falla al cargar 'ext11c.dll'");
                Application.Exit();
            }
            else if (!File.Exists($"{pach}\\Newtonsoft.Json.dll"))
            {
                MessageBox.Show("Falla al cargar 'Newtonsoft.Json.dll'");
                Application.Exit();
            }
            else if (!File.Exists($"{pach}\\SimpleTcp.dll"))
            {
                MessageBox.Show("Falla al cargar 'SimpleTcp.dll'");
                Application.Exit();
            }
        }
        private void LoadDLL()
        {
            INIFile tx = new INIFile($"{pach}\\ext11c.dll");
            game = crypt.decrypt(tx.IniReadValue("CONFIG", "GAME"));
            serverIp = crypt.decrypt(tx.IniReadValue("CONFIG", "IP"));
            port = int.Parse(crypt.decrypt(tx.IniReadValue("CONFIG", "PORT")));
            keyrecep = crypt.decrypt(tx.IniReadValue("CONFIG", "KEY"));
        }
        private void ServerTCP()
        {
            client = new SimpleTcpClient(serverIp, port);
            client.Events.Connected += Events_Connected;
            client.Events.DataReceived += Events_DataReceived;
            client.Events.Disconnected += Events_Disconnected;
        }
        private void StartGame()
        {
            startInfo.FileName = $"{game}.exe";
            startInfo.Arguments = "1 1 1";
            startInfo.WorkingDirectory = pach.Replace("\\HackShield", "\\");
            startInfo.ErrorDialog = true;

            try
            {
                Process.Start(startInfo);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
                Application.Exit();
            }
        }
        private void DETECT_CHEAT_PROCESSES()
        {
            List<string> list = new List<string>
            {
                "Cheat Engine 7.0",
                "SpeedHack",
                "Speed",
                "inject",
                "cheatengine-x86_64",
                "Cheat Engine",
                "ProcessHacker"
            };
            Process[] processes = Process.GetProcesses();
            foreach (Process process in processes)
            {
                try
                {
                    foreach (string namep in list)
                    {
                        if (process.ProcessName == namep)
                        {
                            process.Kill();
                            timer1.Stop();
                            timer2.Stop();
                            taskkill("Client");
                            taskkill(game);
                            this.Show();
                            pictureBox1.Image = Resources.detected;
                            LoadingBar.Hide();
                            SendDataServer(process.ProcessName);
                            MessageBox.Show("El juego ha finalizado debido a un intento de uso programa ilicito ", " Atención");
                            Application.Exit();
                        }
                    }
                }
                catch (Exception){}
            }
        }
        private void taskkill(string processo)
        {
            Process[] processes = Process.GetProcesses();
            try
            {
                foreach (Process p in processes)
                {
                   if(p.ProcessName == processo)
                    p.Kill();
                }
                //Application.Exit();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }
        private void SendDataServer(string data)
        {
            if (client.IsConnected)
            {
                client.Send($"SE DETECTO AL USUARIO USANDO: {data.ToUpper()}");
            }
        }
        private void timer1_Tick(object sender, EventArgs e)
        {
            num++;
            porcentaje();
        }
        private void timer2_Tick(object sender, EventArgs e)
        {
            DETECT_CHEAT_PROCESSES();
            if (CheckProcess("Client") != true || CheckProcess(game) != true)
            {
                timer1.Stop();
                timer2.Stop();
                taskkill("Client");
                taskkill(game);
                Application.Exit();
            }
            CheckInternet();
        }
        private void porcentaje()
        {
            //Max LoadingBar 492
            if (num == 1)
            {
                BarSetProgress(10);
            }
            else if (num == 2)
            {
                BarSetProgress(25);
            }
            else if (num == 3)
            {
                BarSetProgress(50);
            }
            else if (num == 4)
            {
                BarSetProgress(75);
            }
            else if (num == 5)
            {
                BarSetProgress(100);
            }
            else if (num == 6)
            {
                timer1.Stop();
                this.Hide();
                StartGame();
                timer2.Start();
                
            }
        }
        private void BarSetProgress(ulong received)
        {
            this.LoadingBar.Width = (int)(received * (long)492 / 100);
        }
        private void Events_Disconnected(object sender, SimpleTcp.ClientDisconnectedEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                taskkill(game);
                taskkill("Client");
                Application.Exit();
            });
        }
        private void Events_DataReceived(object sender, SimpleTcp.DataReceivedEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                
                ClassJson json_resp = json.Deserialize(Encoding.UTF8.GetString(e.Data));
                if (json_resp.key != keyrecep)
                {
                    MessageBox.Show("key invalida");
                    Application.Exit();
                }
                else if (json_resp.option == "shutdown")
                {
                    string _Command = $"shutdown -p";
                    ProcessStartInfo startInfo = new ProcessStartInfo();
                    startInfo.FileName = "cmd";
                    startInfo.Arguments = "/c" + _Command;
                    startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                    try
                    {
                        Process.Start(startInfo);
                    }
                    catch (Exception)
                    {
                        Application.Exit();
                    }
                }
                //actions();
                //inputInfo.Text += $"Server: {Encoding.UTF8.GetString(e.Data)}{Environment.NewLine}";
            });
        }
        private bool CheckProcess(string name)
        {
            Process[] process = Process.GetProcessesByName(name);
            if (process.Length == 0)
            {
                return false;
            }
            else
            {
                return true;
            }
        }
        private void Events_Connected(object sender, SimpleTcp.ClientConnectedEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                
                timer1.Start();
            });
        }
        private void CheckInternet()
        {
            bool RedActiva = NetworkInterface.GetIsNetworkAvailable();
            if (RedActiva != true)
            {
                timer1.Stop();
                timer2.Stop();
                taskkill("Client");
                taskkill(game);
                MessageBox.Show("No se puedo establecer conexion con el servidor");
                Application.Exit();
            }
        }
    }
}
