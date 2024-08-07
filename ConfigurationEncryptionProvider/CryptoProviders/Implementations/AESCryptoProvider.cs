using ConfigurationEncryptionProvider.CryptoProviders.Interfaces;
using ConfigurationEncryptionProvider.Models;
using Microsoft.Extensions.Options;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ConfigurationEncryptionProvider.CryptoProviders.Implementations
{
    public class AESCryptoProvider : ICryptoProvider
    {
        private readonly AESEncryptionSettings aesEncryptionSettings;
        public AESCryptoProvider(AESEncryptionSettings aesEncryptionSettings)
        {
            if (aesEncryptionSettings == null) throw new ArgumentNullException(nameof(aesEncryptionSettings));
            this.aesEncryptionSettings = aesEncryptionSettings;
        }
        public string Decrypt(string secret)
        {
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = Encoding.UTF8.GetBytes(aesEncryptionSettings.Key);
                    aes.IV = Encoding.UTF8.GetBytes(aesEncryptionSettings.IV);
                    string plaintext = null;
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(secret)))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                plaintext = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                    return plaintext;
                }
            }
            catch (Exception)
            {

                throw;
            }
        }

        public string Encrypt(string secret)
        {
            byte[] encrypted;
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = Encoding.UTF8.GetBytes(aesEncryptionSettings.Key);
                    aes.IV = Encoding.UTF8.GetBytes(aesEncryptionSettings.IV);
                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                swEncrypt.Write(secret);
                            }
                            encrypted = msEncrypt.ToArray();
                        }
                    }
                }
                return Convert.ToBase64String(encrypted);
            }
            catch (Exception)
            {

                throw;
            }
        }
    }
}
