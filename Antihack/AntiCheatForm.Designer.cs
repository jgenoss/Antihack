namespace AntiCheat
{
    partial class AntiCheatForm
    {
        /// <summary>
        /// Variable del diseñador necesaria.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Limpiar los recursos que se estén usando.
        /// </summary>
        /// <param name="disposing">true si los recursos administrados se deben desechar; false en caso contrario.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Código generado por el Diseñador de Windows Forms

        /// <summary>
        /// Método necesario para admitir el Diseñador. No se puede modificar
        /// el contenido de este método con el editor de código.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(AntiCheatForm));
            this.LoadingBar = new System.Windows.Forms.PictureBox();
            this._loadingTimer = new System.Windows.Forms.Timer(this.components);
            this._securityTimer = new System.Windows.Forms.Timer(this.components);
            ((System.ComponentModel.ISupportInitialize)(this.LoadingBar)).BeginInit();
            this.SuspendLayout();
            // 
            // LoadingBar
            // 
            this.LoadingBar.BackColor = System.Drawing.Color.Transparent;
            this.LoadingBar.BackgroundImage = global::AntiCheat.Properties.Resources.loadingbar;
            this.LoadingBar.Location = new System.Drawing.Point(14, 195);
            this.LoadingBar.Name = "LoadingBar";
            this.LoadingBar.Size = new System.Drawing.Size(492, 11);
            this.LoadingBar.TabIndex = 3;
            this.LoadingBar.TabStop = false;
            // 
            // _loadingTimer
            // 
            this._loadingTimer.Interval = 500;
            this._loadingTimer.Tick += new System.EventHandler(this.OnLoadingTimerTick);
            // 
            // _securityTimer
            // 
            this._securityTimer.Tick += new System.EventHandler(this.OnSecurityTimerTick);
            // 
            // AntiCheatForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackgroundImage = global::AntiCheat.Properties.Resources.anticheat;
            this.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Stretch;
            this.ClientSize = new System.Drawing.Size(520, 250);
            this.ControlBox = false;
            this.Controls.Add(this.LoadingBar);
            this.DoubleBuffered = true;
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "AntiCheatForm";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "AntiCheat";
            this.Load += new System.EventHandler(this.Form1_Load);
            ((System.ComponentModel.ISupportInitialize)(this.LoadingBar)).EndInit();
            this.ResumeLayout(false);

        }

        #endregion
        private System.Windows.Forms.PictureBox LoadingBar;
        private System.Windows.Forms.Timer _loadingTimer;
        private System.Windows.Forms.Timer _securityTimer;
    }
}
