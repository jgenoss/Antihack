namespace ServerTCP
{
    partial class Form1
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            this.btnStart = new System.Windows.Forms.Button();
            this.btnSend = new System.Windows.Forms.Button();
            this.inputInfo = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.lstClientIP = new System.Windows.Forms.ListBox();
            this.inputSelect = new System.Windows.Forms.ComboBox();
            this.label1 = new System.Windows.Forms.Label();
            this.inputServerIp = new System.Windows.Forms.TextBox();
            this.statusStrip1 = new System.Windows.Forms.StatusStrip();
            this.toolStripStatusLabel1 = new System.Windows.Forms.ToolStripStatusLabel();
            this.toolStripStatusLabel2 = new System.Windows.Forms.ToolStripStatusLabel();
            this.searchBox = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.textBox_playes_report = new System.Windows.Forms.TextBox();
            this.statusStrip1.SuspendLayout();
            this.SuspendLayout();
            // 
            // btnStart
            // 
            this.btnStart.Location = new System.Drawing.Point(413, 7);
            this.btnStart.Name = "btnStart";
            this.btnStart.Size = new System.Drawing.Size(89, 23);
            this.btnStart.TabIndex = 13;
            this.btnStart.Text = "Start";
            this.btnStart.UseVisualStyleBackColor = true;
            this.btnStart.Click += new System.EventHandler(this.btnStart_Click);
            // 
            // btnSend
            // 
            this.btnSend.Location = new System.Drawing.Point(973, 573);
            this.btnSend.Name = "btnSend";
            this.btnSend.Size = new System.Drawing.Size(181, 23);
            this.btnSend.TabIndex = 12;
            this.btnSend.Text = "Send Command";
            this.btnSend.UseVisualStyleBackColor = true;
            this.btnSend.Click += new System.EventHandler(this.btnSend_Click);
            // 
            // inputInfo
            // 
            this.inputInfo.BackColor = System.Drawing.SystemColors.Control;
            this.inputInfo.Font = new System.Drawing.Font("Consolas", 8F);
            this.inputInfo.ForeColor = System.Drawing.Color.Black;
            this.inputInfo.HideSelection = false;
            this.inputInfo.Location = new System.Drawing.Point(12, 36);
            this.inputInfo.Multiline = true;
            this.inputInfo.Name = "inputInfo";
            this.inputInfo.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.inputInfo.Size = new System.Drawing.Size(955, 288);
            this.inputInfo.TabIndex = 10;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(1043, 17);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(49, 13);
            this.label3.TabIndex = 14;
            this.label3.Text = "Client IP:";
            // 
            // lstClientIP
            // 
            this.lstClientIP.BackColor = System.Drawing.SystemColors.Control;
            this.lstClientIP.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.lstClientIP.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lstClientIP.FormattingEnabled = true;
            this.lstClientIP.Location = new System.Drawing.Point(973, 59);
            this.lstClientIP.Name = "lstClientIP";
            this.lstClientIP.ScrollAlwaysVisible = true;
            this.lstClientIP.Size = new System.Drawing.Size(181, 483);
            this.lstClientIP.TabIndex = 15;
            // 
            // inputSelect
            // 
            this.inputSelect.FormattingEnabled = true;
            this.inputSelect.Items.AddRange(new object[] {
            "Seleccione una opcion",
            "Apagar pc del jugador",
            "Desconectar jugador",
            "Stream Viewer"});
            this.inputSelect.Location = new System.Drawing.Point(973, 546);
            this.inputSelect.Name = "inputSelect";
            this.inputSelect.Size = new System.Drawing.Size(181, 21);
            this.inputSelect.TabIndex = 16;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(9, 12);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(54, 13);
            this.label1.TabIndex = 7;
            this.label1.Text = "Server IP:";
            // 
            // inputServerIp
            // 
            this.inputServerIp.Location = new System.Drawing.Point(66, 9);
            this.inputServerIp.Name = "inputServerIp";
            this.inputServerIp.ReadOnly = true;
            this.inputServerIp.Size = new System.Drawing.Size(341, 20);
            this.inputServerIp.TabIndex = 9;
            // 
            // statusStrip1
            // 
            this.statusStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.toolStripStatusLabel1,
            this.toolStripStatusLabel2});
            this.statusStrip1.Location = new System.Drawing.Point(0, 605);
            this.statusStrip1.Name = "statusStrip1";
            this.statusStrip1.Size = new System.Drawing.Size(1162, 22);
            this.statusStrip1.TabIndex = 17;
            this.statusStrip1.Text = "Datos Enviados :";
            // 
            // toolStripStatusLabel1
            // 
            this.toolStripStatusLabel1.Name = "toolStripStatusLabel1";
            this.toolStripStatusLabel1.Size = new System.Drawing.Size(96, 17);
            this.toolStripStatusLabel1.Text = "Datos enviados : ";
            // 
            // toolStripStatusLabel2
            // 
            this.toolStripStatusLabel2.Name = "toolStripStatusLabel2";
            this.toolStripStatusLabel2.Size = new System.Drawing.Size(89, 17);
            this.toolStripStatusLabel2.Text = "Datos resividos:";
            // 
            // searchBox
            // 
            this.searchBox.Location = new System.Drawing.Point(973, 35);
            this.searchBox.Name = "searchBox";
            this.searchBox.Size = new System.Drawing.Size(181, 20);
            this.searchBox.TabIndex = 18;
            this.searchBox.TextChanged += new System.EventHandler(this.searchBox_TextChanged);
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(12, 327);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(191, 13);
            this.label2.TabIndex = 20;
            this.label2.Text = "Player ALL or Report Dll or INJECTION";
            // 
            // textBox_playes_report
            // 
            this.textBox_playes_report.Location = new System.Drawing.Point(12, 343);
            this.textBox_playes_report.Multiline = true;
            this.textBox_playes_report.Name = "textBox_playes_report";
            this.textBox_playes_report.ReadOnly = true;
            this.textBox_playes_report.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.textBox_playes_report.Size = new System.Drawing.Size(955, 253);
            this.textBox_playes_report.TabIndex = 21;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1162, 627);
            this.Controls.Add(this.textBox_playes_report);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.searchBox);
            this.Controls.Add(this.statusStrip1);
            this.Controls.Add(this.inputSelect);
            this.Controls.Add(this.lstClientIP);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.btnStart);
            this.Controls.Add(this.btnSend);
            this.Controls.Add(this.inputInfo);
            this.Controls.Add(this.inputServerIp);
            this.Controls.Add(this.label1);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.Name = "Form1";
            this.Text = "Server AntiCheats";
            this.Load += new System.EventHandler(this.Server_Load);
            this.statusStrip1.ResumeLayout(false);
            this.statusStrip1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button btnStart;
        private System.Windows.Forms.Button btnSend;
        private System.Windows.Forms.TextBox inputInfo;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.ListBox lstClientIP;
        private System.Windows.Forms.ComboBox inputSelect;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox inputServerIp;
        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.ToolStripStatusLabel toolStripStatusLabel1;
        private System.Windows.Forms.ToolStripStatusLabel toolStripStatusLabel2;
        private System.Windows.Forms.TextBox searchBox;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox textBox_playes_report;
    }
}

