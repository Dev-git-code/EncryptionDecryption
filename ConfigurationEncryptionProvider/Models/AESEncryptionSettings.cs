using System;
using System.Collections.Generic;
using System.Text;

namespace ConfigurationEncryptionProvider.Models
{
    public class AESEncryptionSettings 
    {
        public string Key { get; set; }
        public string IV { get; set; }
    }
}
