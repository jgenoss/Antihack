using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Newtonsoft.Json;

namespace json_ext
{
    class ClassJson
    {
        public string message { get; set; }
        public string key { get; set; }

        public string Serialize(string key, string message)
        {
            ClassJson jsonData = new ClassJson()
            {
                key = $"{key}",
                message = $"{message}"
            };
            return JsonConvert.SerializeObject(jsonData, Formatting.Indented);
        }
        public ClassJson Deserialize(string message)
        {
            ClassJson json_response = JsonConvert.DeserializeObject<ClassJson>(message);
            return json_response;
        }
    }
}
