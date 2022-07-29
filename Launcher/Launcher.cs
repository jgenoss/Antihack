using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Diagnostics;
using Microsoft.Win32;
using System.Net;
using System.IO;
using System.Runtime.InteropServices;
using Ionic.Zip;
using json_ext;

namespace Launcher
{

    public partial class Launcher : Form
    {

        private Point NewPoint;
        private WebClient web = new WebClient();
        private ClassJson json = new ClassJson();
        private string path = Directory.GetCurrentDirectory();

        string url, UpdateDir, LunchBANNER, soporte ,facebook,registro;

        public int lastVersion = 0, version;

        public Launcher()
        {
            InitializeComponent();
            web.DownloadFileCompleted += new AsyncCompletedEventHandler(gameUpdate_DownloadCompleted);
            web.DownloadProgressChanged += new DownloadProgressChangedEventHandler(gameUpdate_DownloadProgressChanged);
            LoadDLL();
            LoadImg();
        }
        private void Launcher_Load(object sender, EventArgs e)
        {
            ClassJson response = json.Deserialize(GetData(url));

            labelInfo.Text = "El texto predeterminado no se cargó.";
            LabelArchivos.Text = "Archivos";
            lastVersion = int.Parse(response.version);
            labelVesion.Text = $"Versión: [{version}/{lastVersion}]";
            ButtonStart.Enabled = false;

            if (File.Exists($"{path}\\_DownloadPatchFiles"))
            {
                DirDelAllFiles($"{path}\\_DownloadPatchFiles");
            }

            if (version != lastVersion)
            {
                ArchiveBar.Width = 0;
                TotalBar.Width = 0;
                labelInfo.Text = "Actualiza la versión de tu juego.";
                ButtonStart.Visible = false;
            }
            else
            {
                labelInfo.Text = "Tu juego está actualizado. Ahora puedes jugar.";
                ButtonStart.Enabled = true;
            }
        }
        private void timer1_Tick(object sender, EventArgs e)
        {
            LoadDLL();
            ClassJson response = json.Deserialize(GetData(url));
            lastVersion = int.Parse(response.version);
            if (lastVersion != version)
            {
                int num = version + 1;
                try
                {
                    Directory.CreateDirectory($"{path}\\_DownloadPatchFiles");
                    web.DownloadFileAsync(new Uri($"{UpdateDir}/Update_{num}.zip"), $"{path}\\_DownloadPatchFiles\\Update_{num}.zip");
                }
                catch (Exception exception)
                {
                    MessageBox.Show(exception.ToString());
                }

                Bar2SetProgress((ulong)0, (ulong)100);
                labelInfo.Text = "By downloading the patch files...";
                fileName.Text = $"Update_{num}.zip";
                timer1.Stop();
            }
            else if (lastVersion == version)
            {
                Bar1SetProgress((long)100, (long)100, false);
                labelInfo.Text = "Tu juego está actualizado. Ahora puedes jugar.";
                ButtonStart.Enabled = true;
                ButtonUpdate.Enabled = false;
                ButtonStart.Visible = true;
                ButtonUpdate.Visible = false;
                fileName.Visible = false;
                timer1.Stop();
            }

        }
        private void ButtonUpdate_Click(object sender, EventArgs e)
        {
            ButtonUpdate.Enabled = false;
            fileName.Visible = true;
            int num = version + 1;
            try
            {
                Directory.CreateDirectory($"{path}\\_DownloadPatchFiles");
                web.DownloadFileAsync(new Uri($"{UpdateDir}/Update_{num}.zip"), $"{path}\\_DownloadPatchFiles\\Update_{num}.zip");
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            //this.ButtonStart.BackgroundImage = LauncherMu.Properties.Resources.start_off;
            labelInfo.Text = "By downloading the patch files...";
            labelInfo.Refresh();
            fileName.Text = $"Update_{num}.zip";
            fileName.Refresh();
        }
        private void gameUpdate_DownloadCompleted(object sender, AsyncCompletedEventArgs e)
        {
            INIFile file = new INIFile($"{path}\\JGConfig.dll");
            if (e.Error == null)
            {
                int num = version + 1;
                labelInfo.Text = "Extracting files from the update...";
                ArchiveBar.Width = 0;
                unzip(path, $"{path}\\_DownloadPatchFiles\\Update_{num}.zip");
                file.IniWriteValue("LAUNCHER_CONFIG", "VERSION", $" {num}");
                ButtonStart.Enabled = false;
                ButtonUpdate.SendToBack();
                ButtonUpdate.Enabled = false;
                timer1.Start();
                labelVesion.Text = $"Versión: [{num}/{lastVersion}]";
                DirDelAllFiles($"{path}\\_DownloadPatchFiles");
            }
        }
        private void DirDelAllFiles(string path)
        {
            string[] files = Directory.GetFiles(path);
            foreach (string file in files)
            {
                File.Delete(file);
            }
            Directory.Delete(path);
        }
        private void LoadDLL()
        {
            INIFile tx = new INIFile($"{path}\\JGConfig.dll");
            url = tx.IniReadValue("LAUNCHER_CONFIG", "URL_LAUNCHER");
            UpdateDir = tx.IniReadValue("LAUNCHER_CONFIG", "URL_DIR_UPDATE");
            facebook = tx.IniReadValue("LAUNCHER_CONFIG", "URL_FACEBOOK");
            registro = tx.IniReadValue("LAUNCHER_CONFIG", "URL_REGISTRO");
            soporte = tx.IniReadValue("LAUNCHER_CONFIG", "URL_SOPORTE");
            LunchBANNER = tx.IniReadValue("LAUNCHER_CONFIG", "URL_BANNER");
            version = int.Parse(tx.IniReadValue("LAUNCHER_CONFIG", "VERSION"));
            webBrowser2.Url = new Uri(LunchBANNER);
        }
        public void LoadImg()
        {
            try
            {
                BackgroundImage = Image.FromFile(".\\data\\img\\bg.png");
                ButtonStart.Image = Image.FromFile(".\\data\\img\\StartGame.png");
                ButtonUpdate.Image = Image.FromFile(".\\data\\img\\UpdateGame.png");
                btnRegistro.Image = Image.FromFile(".\\data\\img\\Registro.png");
                btnFacebook.Image = Image.FromFile(".\\data\\img\\Facebook.png");
                btnSoporte.Image = Image.FromFile(".\\data\\img\\Soporte.png");
                ArchiveBar.Image = Image.FromFile(".\\data\\img\\loadingbar1.png");
                TotalBar.Image = Image.FromFile(".\\data\\img\\loadingbar2.png");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"No se puedo encontrar {ex.Message}", "ERROR", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Application.Exit();
            }
        }
        private void btnSoporte_Click(object sender, EventArgs e)
        {
            Process.Start(soporte);
        }

        private void btnRegistro_Click(object sender, EventArgs e)
        {
            Process.Start(registro);
        }

        private void btnFacebook_Click(object sender, EventArgs e)
        {
            Process.Start(facebook);
        }

        private void btnExit_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void btnMinimize_Click(object sender, EventArgs e)
        {
            base.WindowState = FormWindowState.Minimized;
        }

        private void Launcher_MouseDown(object sender, MouseEventArgs e)
        {
            if (Control.MouseButtons == System.Windows.Forms.MouseButtons.Left)
            {
                int left = base.Left;
                Point mousePosition = Control.MousePosition;
                NewPoint.X = left - mousePosition.X;
                int top = base.Top;
                Point point = Control.MousePosition;
                NewPoint.Y = top - point.Y;
            }
        }

        private void Launcher_MouseMove(object sender, MouseEventArgs e)
        {
            if (Control.MouseButtons == System.Windows.Forms.MouseButtons.Left)
            {
                int x = NewPoint.X;
                Point mousePosition = Control.MousePosition;
                base.Left = x + mousePosition.X;
                int y = NewPoint.Y;
                mousePosition = Control.MousePosition;
                base.Top = y + mousePosition.Y;
            }
        }
        private void ButtonStart_Click(object sender, EventArgs e)
        {
            Process.Start("Client.exe");
            Application.Exit();
        }

        private void linkLabel1_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            Process.Start("https://www.facebook.com/azpirin4");
        }

        public void unzip(string TargetDir, string ZipToUnpack)
        {
            try
            {
                ZipFile zipFile = ZipFile.Read(ZipToUnpack);
                try//All credits to Coyote per decompile and fix errors in source
                //Do not remove credits...
                {
                    zipFile.ExtractProgress += new EventHandler<ExtractProgressEventArgs>(unzip_ExtractProgressChanged);
                    int num = 0;
                    int num1 = 0;
                    foreach (ZipEntry zipEntry in zipFile)
                    {
                        if (!zipEntry.IsDirectory)
                        {
                            num1++;
                        }
                    }
                    fileName.Visible = true;
                    foreach (ZipEntry zipEntry1 in zipFile)
                    {
                        string fileName = zipEntry1.FileName;
                        if (fileName.Contains("/"))
                        {
                            int num2 = fileName.LastIndexOf("/");
                            fileName = fileName.Substring(num2 + 1);
                        }
                        if (!zipEntry1.IsDirectory)
                        {
                            this.fileName.Text = fileName;
                            base.Update();
                            Refresh();
                            int num3 = num + 1;
                            num = num3;
                            Bar2SetProgress((ulong)num3, (ulong)num1);
                        }//All credits to Coyote per decompile and fix errors in source
                        //Do not remove credits...
                        zipEntry1.Extract(TargetDir, ExtractExistingFileAction.OverwriteSilently);
                    }
                }
                finally
                {
                    if (zipFile != null)
                    {
                        zipFile.Dispose();
                    }
                }
            }
            catch (Exception exception)
            {
                MessageBox.Show(exception.ToString());
            }//All credits to Coyote per decompile and fix errors in source
            //Do not remove credits...
        }

        private void unzip_ExtractProgressChanged(object sender, ExtractProgressEventArgs e)
        {
            try
            {
                if (e.TotalBytesToTransfer != (long)0)
                {
                    Bar1SetProgress(e.BytesTransferred, e.TotalBytesToTransfer ,false);
                }
                ArchiveBar.Refresh();
                ArchiveBar.Update();
            }
            catch (Exception exception)
            {
                MessageBox.Show(exception.Message);
            }
        }

        private void gameUpdate_DownloadProgressChanged(object sender, DownloadProgressChangedEventArgs e)
        {
            Bar1SetProgress(e.BytesReceived, e.TotalBytesToReceive ,false);
        }

        public void Bar1SetProgress(long received, long maximum , bool progress)
        {
            ArchiveBar.Width = (int)(received * (long)240 / maximum);
        }
        public void Bar2SetProgress(ulong received, ulong maximum)
        {
            TotalBar.Width = (int)(received * (long)240 / maximum);
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
