namespace Launcher
{
    partial class Launcher
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Launcher));
            this.timer1 = new System.Windows.Forms.Timer(this.components);
            this.fileName = new System.Windows.Forms.Label();
            this.labelVesion = new System.Windows.Forms.Label();
            this.LabelArchivos = new System.Windows.Forms.Label();
            this.labelInfo = new System.Windows.Forms.Label();
            this.webBrowser2 = new System.Windows.Forms.WebBrowser();
            this.TotalBar = new System.Windows.Forms.PictureBox();
            this.ArchiveBar = new System.Windows.Forms.PictureBox();
            this.btnSoporte = new System.Windows.Forms.PictureBox();
            this.btnFacebook = new System.Windows.Forms.PictureBox();
            this.btnRegistro = new System.Windows.Forms.PictureBox();
            this.ButtonStart = new System.Windows.Forms.PictureBox();
            this.ButtonUpdate = new System.Windows.Forms.PictureBox();
            this.btnExit = new System.Windows.Forms.PictureBox();
            this.btnMinimize = new System.Windows.Forms.PictureBox();
            this.linkLabel1 = new System.Windows.Forms.LinkLabel();
            ((System.ComponentModel.ISupportInitialize)(this.TotalBar)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.ArchiveBar)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.btnSoporte)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.btnFacebook)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.btnRegistro)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.ButtonStart)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.ButtonUpdate)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.btnExit)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.btnMinimize)).BeginInit();
            this.SuspendLayout();
            // 
            // timer1
            // 
            this.timer1.Interval = 1000;
            this.timer1.Tick += new System.EventHandler(this.timer1_Tick);
            // 
            // fileName
            // 
            this.fileName.AutoSize = true;
            this.fileName.BackColor = System.Drawing.Color.Transparent;
            this.fileName.Font = new System.Drawing.Font("Consolas", 7F, System.Drawing.FontStyle.Bold);
            this.fileName.ForeColor = System.Drawing.Color.Lime;
            this.fileName.Location = new System.Drawing.Point(112, 400);
            this.fileName.Name = "fileName";
            this.fileName.Size = new System.Drawing.Size(60, 12);
            this.fileName.TabIndex = 15;
            this.fileName.Text = "Archivo.zip";
            this.fileName.Visible = false;
            // 
            // labelVesion
            // 
            this.labelVesion.AutoSize = true;
            this.labelVesion.BackColor = System.Drawing.Color.Transparent;
            this.labelVesion.Font = new System.Drawing.Font("Consolas", 7F);
            this.labelVesion.ForeColor = System.Drawing.Color.White;
            this.labelVesion.Location = new System.Drawing.Point(23, 15);
            this.labelVesion.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelVesion.Name = "labelVesion";
            this.labelVesion.Size = new System.Drawing.Size(60, 12);
            this.labelVesion.TabIndex = 16;
            this.labelVesion.Text = "Cargando...";
            // 
            // LabelArchivos
            // 
            this.LabelArchivos.AutoSize = true;
            this.LabelArchivos.BackColor = System.Drawing.Color.Transparent;
            this.LabelArchivos.Font = new System.Drawing.Font("Consolas", 7F, System.Drawing.FontStyle.Bold);
            this.LabelArchivos.ForeColor = System.Drawing.Color.DeepSkyBlue;
            this.LabelArchivos.Location = new System.Drawing.Point(62, 400);
            this.LabelArchivos.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.LabelArchivos.Name = "LabelArchivos";
            this.LabelArchivos.Size = new System.Drawing.Size(45, 12);
            this.LabelArchivos.TabIndex = 17;
            this.LabelArchivos.Text = "ARCHIVOS";
            // 
            // labelInfo
            // 
            this.labelInfo.AutoSize = true;
            this.labelInfo.BackColor = System.Drawing.Color.Transparent;
            this.labelInfo.Font = new System.Drawing.Font("Consolas", 7F, System.Drawing.FontStyle.Bold);
            this.labelInfo.ForeColor = System.Drawing.Color.Red;
            this.labelInfo.Location = new System.Drawing.Point(85, 454);
            this.labelInfo.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelInfo.Name = "labelInfo";
            this.labelInfo.Size = new System.Drawing.Size(135, 12);
            this.labelInfo.TabIndex = 20;
            this.labelInfo.Text = "Texto estándar no cargado.";
            // 
            // webBrowser2
            // 
            this.webBrowser2.Location = new System.Drawing.Point(530, 66);
            this.webBrowser2.MinimumSize = new System.Drawing.Size(20, 20);
            this.webBrowser2.Name = "webBrowser2";
            this.webBrowser2.ScriptErrorsSuppressed = true;
            this.webBrowser2.ScrollBarsEnabled = false;
            this.webBrowser2.Size = new System.Drawing.Size(250, 280);
            this.webBrowser2.TabIndex = 22;
            this.webBrowser2.Url = new System.Uri("http://s", System.UriKind.Absolute);
            // 
            // TotalBar
            // 
            this.TotalBar.BackColor = System.Drawing.Color.Cyan;
            this.TotalBar.ErrorImage = null;
            this.TotalBar.Image = global::Launcher.Properties.Resources.loadingbar2;
            this.TotalBar.Location = new System.Drawing.Point(63, 428);
            this.TotalBar.Name = "TotalBar";
            this.TotalBar.Size = new System.Drawing.Size(240, 10);
            this.TotalBar.SizeMode = System.Windows.Forms.PictureBoxSizeMode.StretchImage;
            this.TotalBar.TabIndex = 18;
            this.TotalBar.TabStop = false;
            // 
            // ArchiveBar
            // 
            this.ArchiveBar.BackColor = System.Drawing.Color.Transparent;
            this.ArchiveBar.Image = global::Launcher.Properties.Resources.loadingbar1;
            this.ArchiveBar.Location = new System.Drawing.Point(63, 412);
            this.ArchiveBar.Name = "ArchiveBar";
            this.ArchiveBar.Size = new System.Drawing.Size(240, 10);
            this.ArchiveBar.SizeMode = System.Windows.Forms.PictureBoxSizeMode.StretchImage;
            this.ArchiveBar.TabIndex = 19;
            this.ArchiveBar.TabStop = false;
            // 
            // btnSoporte
            // 
            this.btnSoporte.BackColor = System.Drawing.Color.Transparent;
            this.btnSoporte.Image = ((System.Drawing.Image)(resources.GetObject("btnSoporte.Image")));
            this.btnSoporte.Location = new System.Drawing.Point(247, 337);
            this.btnSoporte.Name = "btnSoporte";
            this.btnSoporte.Size = new System.Drawing.Size(100, 50);
            this.btnSoporte.SizeMode = System.Windows.Forms.PictureBoxSizeMode.StretchImage;
            this.btnSoporte.TabIndex = 35;
            this.btnSoporte.TabStop = false;
            this.btnSoporte.Click += new System.EventHandler(this.btnSoporte_Click);
            // 
            // btnFacebook
            // 
            this.btnFacebook.BackColor = System.Drawing.Color.Transparent;
            this.btnFacebook.Image = global::Launcher.Properties.Resources.Facebook;
            this.btnFacebook.Location = new System.Drawing.Point(141, 337);
            this.btnFacebook.Name = "btnFacebook";
            this.btnFacebook.Size = new System.Drawing.Size(100, 50);
            this.btnFacebook.SizeMode = System.Windows.Forms.PictureBoxSizeMode.StretchImage;
            this.btnFacebook.TabIndex = 36;
            this.btnFacebook.TabStop = false;
            this.btnFacebook.Click += new System.EventHandler(this.btnFacebook_Click);
            // 
            // btnRegistro
            // 
            this.btnRegistro.BackColor = System.Drawing.Color.Transparent;
            this.btnRegistro.Image = ((System.Drawing.Image)(resources.GetObject("btnRegistro.Image")));
            this.btnRegistro.Location = new System.Drawing.Point(35, 337);
            this.btnRegistro.Name = "btnRegistro";
            this.btnRegistro.Size = new System.Drawing.Size(100, 50);
            this.btnRegistro.SizeMode = System.Windows.Forms.PictureBoxSizeMode.StretchImage;
            this.btnRegistro.TabIndex = 37;
            this.btnRegistro.TabStop = false;
            this.btnRegistro.Click += new System.EventHandler(this.btnRegistro_Click);
            // 
            // ButtonStart
            // 
            this.ButtonStart.BackColor = System.Drawing.Color.Transparent;
            this.ButtonStart.Image = ((System.Drawing.Image)(resources.GetObject("ButtonStart.Image")));
            this.ButtonStart.ImageLocation = "";
            this.ButtonStart.Location = new System.Drawing.Point(316, 363);
            this.ButtonStart.Name = "ButtonStart";
            this.ButtonStart.Size = new System.Drawing.Size(207, 107);
            this.ButtonStart.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.ButtonStart.TabIndex = 38;
            this.ButtonStart.TabStop = false;
            this.ButtonStart.Tag = "ButtonStart";
            this.ButtonStart.Click += new System.EventHandler(this.ButtonStart_Click);
            // 
            // ButtonUpdate
            // 
            this.ButtonUpdate.BackColor = System.Drawing.Color.Transparent;
            this.ButtonUpdate.Location = new System.Drawing.Point(316, 363);
            this.ButtonUpdate.Name = "ButtonUpdate";
            this.ButtonUpdate.Size = new System.Drawing.Size(207, 107);
            this.ButtonUpdate.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.ButtonUpdate.TabIndex = 39;
            this.ButtonUpdate.TabStop = false;
            this.ButtonUpdate.Click += new System.EventHandler(this.ButtonUpdate_Click);
            // 
            // btnExit
            // 
            this.btnExit.BackColor = System.Drawing.Color.Transparent;
            this.btnExit.Image = global::Launcher.Properties.Resources.btnExit;
            this.btnExit.Location = new System.Drawing.Point(759, 20);
            this.btnExit.Name = "btnExit";
            this.btnExit.Size = new System.Drawing.Size(30, 30);
            this.btnExit.SizeMode = System.Windows.Forms.PictureBoxSizeMode.AutoSize;
            this.btnExit.TabIndex = 40;
            this.btnExit.TabStop = false;
            this.btnExit.Click += new System.EventHandler(this.btnExit_Click);
            // 
            // btnMinimize
            // 
            this.btnMinimize.BackColor = System.Drawing.Color.Transparent;
            this.btnMinimize.Image = global::Launcher.Properties.Resources.btnMinimize;
            this.btnMinimize.Location = new System.Drawing.Point(723, 20);
            this.btnMinimize.Name = "btnMinimize";
            this.btnMinimize.Size = new System.Drawing.Size(30, 30);
            this.btnMinimize.SizeMode = System.Windows.Forms.PictureBoxSizeMode.AutoSize;
            this.btnMinimize.TabIndex = 41;
            this.btnMinimize.TabStop = false;
            this.btnMinimize.Click += new System.EventHandler(this.btnMinimize_Click);
            // 
            // linkLabel1
            // 
            this.linkLabel1.AutoSize = true;
            this.linkLabel1.BackColor = System.Drawing.Color.Transparent;
            this.linkLabel1.Location = new System.Drawing.Point(669, 471);
            this.linkLabel1.Name = "linkLabel1";
            this.linkLabel1.Size = new System.Drawing.Size(48, 13);
            this.linkLabel1.TabIndex = 42;
            this.linkLabel1.TabStop = true;
            this.linkLabel1.Text = "JGenoss";
            this.linkLabel1.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.linkLabel1_LinkClicked);
            // 
            // Launcher
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.AutoSize = true;
            this.BackColor = System.Drawing.Color.Silver;
            this.BackgroundImage = ((System.Drawing.Image)(resources.GetObject("$this.BackgroundImage")));
            this.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Stretch;
            this.ClientSize = new System.Drawing.Size(813, 500);
            this.Controls.Add(this.linkLabel1);
            this.Controls.Add(this.btnMinimize);
            this.Controls.Add(this.btnExit);
            this.Controls.Add(this.btnSoporte);
            this.Controls.Add(this.ButtonStart);
            this.Controls.Add(this.ButtonUpdate);
            this.Controls.Add(this.btnRegistro);
            this.Controls.Add(this.btnFacebook);
            this.Controls.Add(this.webBrowser2);
            this.Controls.Add(this.labelVesion);
            this.Controls.Add(this.labelInfo);
            this.Controls.Add(this.TotalBar);
            this.Controls.Add(this.ArchiveBar);
            this.Controls.Add(this.LabelArchivos);
            this.Controls.Add(this.fileName);
            this.DoubleBuffered = true;
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(2);
            this.MaximizeBox = false;
            this.Name = "Launcher";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Launcher";
            this.TransparencyKey = System.Drawing.Color.Gray;
            this.Load += new System.EventHandler(this.Launcher_Load);
            this.MouseDown += new System.Windows.Forms.MouseEventHandler(this.Launcher_MouseDown);
            this.MouseMove += new System.Windows.Forms.MouseEventHandler(this.Launcher_MouseMove);
            ((System.ComponentModel.ISupportInitialize)(this.TotalBar)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.ArchiveBar)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.btnSoporte)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.btnFacebook)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.btnRegistro)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.ButtonStart)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.ButtonUpdate)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.btnExit)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.btnMinimize)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion
        private System.Windows.Forms.Timer timer1;
        private System.Windows.Forms.Label fileName;
        private System.Windows.Forms.Label labelVesion;
        private System.Windows.Forms.Label LabelArchivos;
        private System.Windows.Forms.PictureBox TotalBar;
        private System.Windows.Forms.PictureBox ArchiveBar;
        private System.Windows.Forms.Label labelInfo;
        private System.Windows.Forms.WebBrowser webBrowser2;
        private System.Windows.Forms.PictureBox btnSoporte;
        private System.Windows.Forms.PictureBox btnFacebook;
        private System.Windows.Forms.PictureBox btnRegistro;
        private System.Windows.Forms.PictureBox ButtonStart;
        private System.Windows.Forms.PictureBox ButtonUpdate;
        private System.Windows.Forms.PictureBox btnExit;
        private System.Windows.Forms.PictureBox btnMinimize;
        private System.Windows.Forms.LinkLabel linkLabel1;
    }
}