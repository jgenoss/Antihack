using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using json_ext;

namespace test_code_console
{
    class Program
    {
        static void Main(string[] args)
        {
            string[] str = Directory.GetFiles($"data\\SmData");
            StreamWriter streamWriter = new StreamWriter("Log.txt");
            foreach (string st in str)
            {
                string ste = st.Replace(@"\",@"\\");
                streamWriter.WriteLine($" \"{ste}\",");
                Console.WriteLine($" \"{ste}\",{Environment.NewLine}");
            }
            streamWriter.Close();
            Console.Write("Proceso Completado");
            Console.ReadKey();
            /*
            WebClient client = new WebClient();
            string response = client.DownloadString("http://localhost/launcher/launcher.json");
            ClassJson json = new ClassJson();
            ClassJson classJson1 = json.Deserialize(response);
            Console.WriteLine(classJson1.key);
            Console.Read();
            */
        }
    }
}
