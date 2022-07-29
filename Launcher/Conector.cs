using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Resources;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Diagnostics;
using json_ext;
//using JGSC;

namespace Launcher
{
    public partial class Conector : Form
    {
        private string path = Directory.GetCurrentDirectory();
        private string url, updatedir, key;
        private ClassJson json = new ClassJson();

        public Conector()
        {
            InitializeComponent();
        }
        private void Conector_Load(object sender, EventArgs e)
        {
            Hide();
            ShowInTaskbar = false;
            CheckProccess();
            CheckDLLs();
            LoadDLL();

            try
            {
                ClassJson response = json.Deserialize(GetData(url));
                if (response.key != key)
                {
                    MessageBox.Show("Serial Invalido", "ERROR", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Application.Exit();
                }
                else if (response.status != "true")
                {
                    MessageBox.Show($"{response.messsage}", "Atencion", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    Application.Exit();
                }
                else if (response.status == "true")
                {
                    Launcher launcher = new Launcher();
                    launcher.Show();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
                Application.Exit();
            }
        }
        public void CheckDLLs()
        {
            if (!File.Exists($"{path}\\DotNetZip.dll"))
            {
                MessageBox.Show("Falla al cargar 'DotNetZip.dll'");
                Application.Exit();
            }
            if (!File.Exists($"{path}\\JGConfig.dll"))
            {
                MessageBox.Show("Falla al cargar 'JGConfig.dll'");
                Application.Exit();
            }
            if (!File.Exists($"{path}\\Newtonsoft.Json.dll"))
            {
                MessageBox.Show("Falla al cargar 'Newtonsoft.Json.dll'");
                Application.Exit();
            }
        }
        private void LoadDLL()
        {
            INIFile tx = new INIFile($"{path}\\JGConfig.dll");
            url = tx.IniReadValue("LAUNCHER_CONFIG", "URL_LAUNCHER");
            updatedir = tx.IniReadValue("LAUNCHER_CONFIG", "URL_DIR_UPDATE");
            key = tx.IniReadValue("LAUNCHER_CONFIG", "KEY");
            
        }
        private void CheckProccess()
        {
            Process[] p0 = Process.GetProcessesByName("Launcher");
            if (p0.Length > 1)
            {
                MessageBox.Show("Este proceso ya esta en ejecucion", "ERROR", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Application.Exit();
            }
        }
        private string GetData(string url)
        {
            try
            {
                WebClient client = new WebClient();
                return client.DownloadString(url);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
                Application.Exit();
                return "error";
            }

        }
    }
}
