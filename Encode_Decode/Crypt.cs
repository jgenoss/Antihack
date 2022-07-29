using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using _Firewall;

namespace Encode_Decode
{
    public partial class Crypt : Form
    {
        private string codigo = "JGenoss";
        public Crypt()
        {
            InitializeComponent();
        }

        public string encrypt(string code)
        {
            byte[] data = UTF8Encoding.UTF8.GetBytes(code);
            using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
            {
                byte[] keys = md5.ComputeHash(UTF8Encoding.UTF8.GetBytes(codigo));
                using (TripleDESCryptoServiceProvider tripDes = new TripleDESCryptoServiceProvider() { Key = keys, Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7 })
                {
                    ICryptoTransform transform = tripDes.CreateEncryptor();
                    byte[] results = transform.TransformFinalBlock(data, 0, data.Length);
                    return Convert.ToBase64String(results, 0, results.Length);
                }
            }
        }
        public string decrypt(string code)
        {
            byte[] data = Convert.FromBase64String(code); // decrypt the incrypted text
            using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
            {
                byte[] keys = md5.ComputeHash(UTF8Encoding.UTF8.GetBytes(codigo));
                using (TripleDESCryptoServiceProvider tripDes = new TripleDESCryptoServiceProvider() { Key = keys, Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7 })
                {
                    ICryptoTransform transform = tripDes.CreateDecryptor();
                    byte[] results = transform.TransformFinalBlock(data, 0, data.Length);
                    return UTF8Encoding.UTF8.GetString(results);
                }
            }
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

        private void button1_Click(object sender, EventArgs e)
        {
             textBox2.Text = encrypt(textBox1.Text);
        }

        private void btnRand_Click(object sender, EventArgs e)
        {
            inputGame.Text = randCode(10);
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            
        }
        private void dll()
        {
            string path = @".\\ext11c.dll";
            using (StreamWriter sw = File.CreateText(path))
            {
                sw.WriteLine("[CONFIG]");
                sw.WriteLine($"GAME = {encrypt(inputGame.Text)}");
                sw.WriteLine($"IP = {encrypt(inputIp.Text)}");
                sw.WriteLine($"PORT = {encrypt(inputPort.Text)}");
                sw.WriteLine($"KEY = {encrypt(inputKey.Text)}");
                MessageBox.Show("DLL Generada con exito");
            }
        }

        private void btnGenerardll_Click(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(inputGame.Text) &&
                !string.IsNullOrEmpty(inputIp.Text) &&
                !string.IsNullOrEmpty(inputPort.Text) &&
                !string.IsNullOrEmpty(inputKey.Text))
            {
                string path = @".\\ext11c.dll";
                if (!File.Exists(path))
                {
                    dll();
                }
                else
                {
                    File.Delete(path);
                    dll();
                }
            }
        }

        private void btnDecrypt_Click(object sender, EventArgs e)
        {

            textBox3.Text = decrypt(textBox4.Text);
        }
    }
}
