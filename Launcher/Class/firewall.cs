using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;

namespace _Firewall
{
    class firewall
    {
        public static void addFirewall(string name, string path1)
        {
            string path2 = path1.Replace("/", "\\");
            string _Command = $"netsh advfirewall firewall add rule name=\"{name}\" dir=in action=allow program=\"{path2}\" enable =yes";
            Process.Start("cmd", "/c " + _Command);
        }
        public void delFirewall(string name)
        {
            string _Command = $"netsh advfirewall firewall delete rule name=\"{name}\"";
            Process.Start("cmd", "/c " + _Command);
        }
    }
}
