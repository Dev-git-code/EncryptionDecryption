using ConfigurationEncryptionProvider.CryptoProviders;

namespace ConfigurationEncryptionProvider.Models
{
    public class EncryptionSettings : AESEncryptionSettings
    {
        public string Algorithm { get; set; }
    }
}
