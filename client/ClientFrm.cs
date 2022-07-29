using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Diagnostics;
using System.IO;
using ext_Inifile;
using ext_base64;
using ext_encrypt_decrypt;
using _Firewall;

namespace Client
{
    public partial class Form1 : Form
    {
        string Oldgame,NewGame;
        int num;
        private encrypt_decrypt crypt = new encrypt_decrypt();
        private string pach = Directory.GetCurrentDirectory();
        private firewall firewall = new firewall();
        public Form1()
        {
            InitializeComponent();
            
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            
            this.Hide();
            this.ShowInTaskbar = false;
            CheckDLL();
            LoadDLL();
            firewall.delFirewall(Oldgame);

            if (!File.Exists($"{pach}\\{Oldgame}.exe"))
            {
                File.Move($"{pach}\\HackShield\\Backup\\{Oldgame}.exe", $"{pach}\\{Oldgame}.exe");
                NewGame = randCode(10);
                try
                {
                    File.Move($"{pach}\\{Oldgame}.exe", $"{pach}\\{NewGame}.exe");
                    File.Copy($"{pach}\\{NewGame}.exe", $"{pach}\\HackShield\\Backup\\{NewGame}.exe");
                    firewall.addFirewall(NewGame, $"{pach}\\{NewGame}.exe");
                    ReadDLL();
                    Start();
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message);
                    Application.Exit();
                }
            }
            else if (File.Exists($"{pach}\\{Oldgame}.exe"))
            {
                NewGame = randCode(10);
                try
                {
                    File.Move($"{pach}\\{Oldgame}.exe", $"{pach}\\{NewGame}.exe");
                    File.Copy($"{pach}\\{NewGame}.exe", $"{pach}\\HackShield\\Backup\\{NewGame}.exe");
                    
                    firewall.addFirewall(NewGame,$"{pach}\\{NewGame}.exe");
                    File.Delete($"{pach}\\HackShield\\Backup\\{Oldgame}.exe");
                    ReadDLL();
                    Start();
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message);
                    Application.Exit();
                }
                
            }
        }
        private void CheckDLL()
        {
            if (!File.Exists($"{pach}\\HackShield\\ext11c.dll"))
            {
                MessageBox.Show("ARCHIVO FALTANTE (ext11c.dll)","ERROR", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Application.Exit();
            }
        }
        private void LoadDLL()
        {
            INIFile tx = new INIFile($"{pach}\\HackShield\\ext11c.dll");
            Oldgame = crypt.decrypt(tx.IniReadValue("CONFIG", "GAME"));
        }
        private void ReadDLL()
        {
            INIFile tx = new INIFile($"{pach}\\HackShield\\ext11c.dll");
            tx.IniWriteValue("CONFIG", "GAME", $" {crypt.encrypt(NewGame)}");
        }
        private void Start()
        {
            
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = "Antihack.exe";
            startInfo.WorkingDirectory = $"{pach}\\HackShield";
            startInfo.ErrorDialog = true;
            timer1.Start();

            try
            {
                Process.Start(startInfo);
            }   
            catch (Exception)
            {
                Application.Exit();
            }
        }
        private void taskkill(string processo)
        {
            Process[] processes = Process.GetProcesses();
            try
            {
                foreach (Process p in processes)
                {
                    if (p.ProcessName == processo)
                        p.Kill();
                }
                Application.Exit();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }
        private void CheckProccess()
        {
            LoadDLL();
            Process[] p0 = Process.GetProcessesByName(Oldgame);
            Process[] p1 = Process.GetProcessesByName("Antihack");
            if (p0.Length == 0)
            {
                taskkill("Antihack");
                Application.Exit();
            }
            if (p1.Length == 0)
            {
                taskkill(Oldgame);
                Application.Exit();
            }
        }
        private void CheckDir()
        {
            if (!Directory.Exists("data\\SmData"))
            {
                taskkill(Oldgame); Application.Exit();
            }
        }
        private void DirDelAllFiles()
        {
            List<string> list = new List<string>
            {
                  "data\\SmData\\SmData1.ark",
                 "data\\SmData\\SmData10.ark",
                 "data\\SmData\\SmData11.ark",
                 "data\\SmData\\SmData112.ark",
                 "data\\SmData\\SmData113.ark",
                 "data\\SmData\\SmData114.ark",
                 "data\\SmData\\SmData115.ark",
                 "data\\SmData\\SmData116.ark",
                 "data\\SmData\\SmData117.ark",
                 "data\\SmData\\SmData118.ark",
                 "data\\SmData\\SmData12.ark",
                 "data\\SmData\\SmData13.ark",
                 "data\\SmData\\SmData14.ark",
                 "data\\SmData\\SmData19.ark",
                 "data\\SmData\\SmData2.ark",
                 "data\\SmData\\SmData20.ark",
                 "data\\SmData\\SmData21.ark",
                 "data\\SmData\\SmData22.ark",
                 "data\\SmData\\SmData23.ark",
                 "data\\SmData\\SmData24.ark",
                 "data\\SmData\\SmData25.ark",
                 "data\\SmData\\SmData26.ark",
                 "data\\SmData\\SmData27.ark",
                 "data\\SmData\\SmData28.ark",
                 "data\\SmData\\SmData29.ark",
                 "data\\SmData\\SmData30.ark",
                 "data\\SmData\\SmData31.ark",
                 "data\\SmData\\SmData32.ark",
                 "data\\SmData\\SmData33.ark",
                 "data\\SmData\\SmData34.ark",
                 "data\\SmData\\SmData35.ark",
                 "data\\SmData\\SmData40.ark",
                 "data\\SmData\\SmData41.ark",
                 "data\\SmData\\SmData42.ark",
                 "data\\SmData\\SmData43.ark",
                 "data\\SmData\\SmData44.ark",
                 "data\\SmData\\SmData45.ark",
                 "data\\SmData\\SmData46.ark",
                 "data\\SmData\\SmData47.ark",
                 "data\\SmData\\SmData50.ark",
                 "data\\SmData\\SmData51.ark",
                 "data\\SmData\\SmData52.ark",
                 "data\\SmData\\SmData53.ark",
                 "data\\SmData\\SmData54.ark",
                 "data\\SmData\\SmData55.ark",
                 "data\\SmData\\SmData6.ark",
                 "data\\SmData\\SmData60.ark",
                 "data\\SmData\\SmData61.ark",
                 "data\\SmData\\SmData62.ark",
                 "data\\SmData\\SmData63.ark",
                 "data\\SmData\\SmData64.ark",
                 "data\\SmData\\SmData65.ark",
                 "data\\SmData\\SmData66.ark",
                 "data\\SmData\\SmData67.ark",
                 "data\\SmData\\SmData9.ark",
                 "data\\SmData\\UserMonsterZone01.sm"
            };
            foreach (string file in list)
            {
                if (!File.Exists(file))
                {
                    timer2.Stop();
                    taskkill(Oldgame);
                    MessageBox.Show($"archivo \"{file}\" no encontrado", "ERROR", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Application.Exit();
                }

            }

            //Directory.Delete(path);
        }
        private void timer1_Tick(object sender, EventArgs e)
        {
            num++;
            if(num == 3)
            {
                timer2.Start();
            }
        }
        private void timer2_Tick(object sender, EventArgs e)
        {
            //timer1.Stop();
            CheckProccess();
            CheckDir();
            DirDelAllFiles();
        }
        public string randCode(int num)
        {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var stringChars = new char[num];
            var random = new Random();
            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = chars[random.Next(chars.Length)];
            }
            string finalString = new String(stringChars);
            return finalString;
        }
    }
}
