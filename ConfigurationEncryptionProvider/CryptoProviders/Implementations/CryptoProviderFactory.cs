using Microsoft.Extensions.Options;
using ConfigurationEncryptionProvider.CryptoProviders.Interfaces;
using System;
using ConfigurationEncryptionProvider.Models;

namespace ConfigurationEncryptionProvider.CryptoProviders.Implementations
{
    public class CryptoProviderFactory : ICryptoProviderFactory
    {
        private readonly EncryptionSettings encryptionSettings;

        public CryptoProviderFactory(IOptions<EncryptionSettings> options)
        {
            encryptionSettings = options.Value;
        }
        public ICryptoProvider GetCryptoProvider()
        {
            try
            {
                CryptoProviderType cryptoProviderType;
                if (encryptionSettings.Algorithm == null)
                    cryptoProviderType = CryptoProviderType.AES;
                else
                 cryptoProviderType = (CryptoProviderType)Enum.Parse(typeof(CryptoProviderType), encryptionSettings.Algorithm);
                switch (cryptoProviderType)
                {
                    case CryptoProviderType.AES:
                        return new AESCryptoProvider(encryptionSettings);
                    default:
                        return null;
                }
            }
            catch (Exception)
            {
                throw;
            }
        }
    }
}
