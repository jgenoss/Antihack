namespace Launcher
{
    partial class Conector
    {
        /// <summary>
        /// Variable del diseñador requerida.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Limpiar los recursos que se estén utilizando.
        /// </summary>
        /// <param name="disposing">true si los recursos administrados se deben eliminar; false en caso contrario, false.</param>
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
        /// el contenido del método con el editor de código.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Conector));
            this.Mensaje_de_espera = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // Mensaje_de_espera
            // 
            this.Mensaje_de_espera.AutoSize = true;
            this.Mensaje_de_espera.BackColor = System.Drawing.Color.Transparent;
            this.Mensaje_de_espera.Font = new System.Drawing.Font("Consolas", 11.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Mensaje_de_espera.Location = new System.Drawing.Point(83, 63);
            this.Mensaje_de_espera.Name = "Mensaje_de_espera";
            this.Mensaje_de_espera.Size = new System.Drawing.Size(144, 18);
            this.Mensaje_de_espera.TabIndex = 0;
            this.Mensaje_de_espera.Text = "Por favor Aguarde";
            // 
            // Conector
            // 
            this.AllowDrop = true;
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(313, 149);
            this.ControlBox = false;
            this.Controls.Add(this.Mensaje_de_espera);
            this.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "Conector";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Conector";
            this.Load += new System.EventHandler(this.Conector_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label Mensaje_de_espera;
    }
}

