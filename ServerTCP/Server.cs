using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using SimpleTcp;
//using Newtonsoft.Json;
using json_ext;
using Antihack;
using System.IO;
using Newtonsoft.Json;
using libc.hwid;
using ext_encrypt_decrypt;

namespace ServerTCP
{
    public partial class Form1 : Form
    {
        //
        private string pach = Directory.GetCurrentDirectory();
        private ClassJson json = new ClassJson();
        encrypt_decrypt crypt = new encrypt_decrypt();
        string serverIp,key, postData, clientIp, hwid;
        int port;
        private SimpleTcpServer server;
        public Form1()
        {
            InitializeComponent();
            LoadDLL();
            
        }
        private void LoadDLL()
        {
            INIFile tx = new INIFile($"{pach}\\Config.ini");
            serverIp = tx.IniReadValue("CONFIG", "IP");
            port = int.Parse(tx.IniReadValue("CONFIG", "PORT"));
            key = tx.IniReadValue("CONFIG", "KEY");
            hwid = crypt.decrypt(tx.IniReadValue("CONFIG", "HWID"));
        }
        private void Server_Load(object sender, EventArgs e)
        {
            if (getHwid() != hwid)
            {
                MessageBox.Show("Su licencia es invalida para este equipo");
                Application.Exit();
            }
            inputSelect.SelectedIndex =0; 
            btnSend.Enabled = false;
            server = new SimpleTcpServer(serverIp,port);
            server.Events.ClientConnected += Events_ClientConnected;
            server.Events.ClientDisconnected += Events_ClientDisconnected;
            server.Events.DataReceived += Events_DataReceived;
        }
        private string getHwid()
        {
            return HwId.Generate();
        }
        private void btnStart_Click(object sender, EventArgs e)
        {
            try
            {
                server.Start();

                inputServerIp.Text = $"{serverIp}:{port}";
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            inputInfo.Text += $"....Starting....{Environment.NewLine}";
            btnStart.Enabled = false;
            btnSend.Enabled = true;
        }
        private void Events_ClientConnected(object sender, ClientConnectedEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                
                string[] str = json.Blacklist().IP.Split(',');
                foreach (string row in str)
                {
                    if (row.ToString() == row.ToString())
                    {
                        server.DisconnectClient(row.ToString());
                    }
                }
                /*
                postData = json.Serialize(key, "validator");
                server.Send(e.IpPort, postData);
                */
                inputInfo.Text += $"{e.IpPort} Connect.{Environment.NewLine}";
                lstClientIP.Items.Add(e.IpPort);
                clientIp = e.IpPort;

            });
        }

        private void Events_ClientDisconnected(object sender, ClientDisconnectedEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate 
            {
                inputInfo.Text += $"{e.IpPort} disconnect.{Environment.NewLine}";
                lstClientIP.Items.Remove(e.IpPort);
            });
        }
        private void Events_DataReceived(object sender, DataReceivedEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate 
            {
                
                toolStripStatusLabel2.Text = $"Datos resividos: {server.Statistics.ReceivedBytes.ToString()}";
                inputInfo.Text += $"{e.IpPort}: {Encoding.UTF8.GetString(e.Data)}{Environment.NewLine}";
                
            });
        }
        private void btnSend_Click(object sender, EventArgs e)
        {
            if (server.IsListening)
            {
                if (inputSelect.SelectedIndex != 0 && lstClientIP.SelectedItem!=null)
                {
                    
                    switch(inputSelect.SelectedIndex)
                    {
                        case 1:
                            postData = json.Serialize(key, "shutdown");
                            ClassJson json_resp = json.Deserialize(postData);
                            server.Send(lstClientIP.SelectedItem.ToString(), postData);
                            inputInfo.Text += $"Server: {json_resp.option}:{clientIp}{Environment.NewLine}";
                            break;
                        case 2:
                            server.DisconnectClient(lstClientIP.SelectedItem.ToString());
                            break;
                    }
                }
                else
                {
                    MessageBox.Show("Seleccione una ip");
                }
            }
        }
    }
}
