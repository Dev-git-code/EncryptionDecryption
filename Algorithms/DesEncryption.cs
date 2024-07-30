using EncyptionDecryption;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using EncyptionDecryption.Helpers;

namespace EncyptionDecryption.Algorithms
{
    public class DesEncryption : IEncryptDecrypt<byte[][]>
    {
        public string Encrypt(string plaintext, params byte[][] parameters)
        {
            HelperMethods.ValidateParameters(parameters, 8, 8);
            byte[] key = HelperMethods.GetParameter(parameters, 0);
            byte[] iv = HelperMethods.GetParameter(parameters, 1);
            return DesEncrypt(plaintext, key, iv);
        }

        public string Decrypt(string ciphertext, params byte[][] parameters)
        {
            HelperMethods.ValidateParameters(parameters, 8, 8);
            byte[] key = HelperMethods.GetParameter(parameters, 0);
            byte[] iv = HelperMethods.GetParameter(parameters, 1);
            return DesDecrypt(ciphertext, key, iv);
        }

        public bool Verify(string plaintext, string hash, params byte[][] parameters)
        {
            byte[] key = HelperMethods.GetParameter(parameters, 0);
            byte[] iv = HelperMethods.GetParameter(parameters, 1);
            string decrypted = DesDecrypt(hash, key, iv);
            return decrypted == plaintext;
        }

        private static string DesEncrypt(string plaintext, byte[] key, byte[] iv)
        {
            byte[] cipheredtext;
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                ICryptoTransform encryptor = des.CreateEncryptor(key, iv);
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter writer = new StreamWriter(cryptoStream))
                        {
                            writer.Write(plaintext);
                        }
                        cipheredtext = memoryStream.ToArray();
                    }
                }
            }
            return Convert.ToBase64String(cipheredtext);
        }

        private static string DesDecrypt(string ciphertext, byte[] key, byte[] iv)
        {
            byte[] cipheredtext = Convert.FromBase64String(ciphertext);
            string simpletext;
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                ICryptoTransform decryptor = des.CreateDecryptor(key, iv);
                using (MemoryStream memoryStream = new MemoryStream(cipheredtext))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader(cryptoStream))
                        {
                            simpletext = streamReader.ReadToEnd();
                        }
                    }
                }
            }
            return simpletext;
        }

    }
}
