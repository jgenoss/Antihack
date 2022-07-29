using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace json_ext
{
    class ClassJson
    {
        public string option { get; set; }
        public string key { get; set; }

        public string Serialize(string key, string option)
        {
            ClassJson jsonData = new ClassJson()
            {
                key = $"{key}",
                option = $"{option}"
            };
            return JsonConvert.SerializeObject(jsonData, Formatting.Indented);
        }
        public ClassJson Deserialize(string option)
        {
            ClassJson json_response = JsonConvert.DeserializeObject<ClassJson>(option);
            return json_response;
        }
    }
}
