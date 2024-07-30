using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncyptionDecryption.Algorithms
{
    public class AesEncryption : IEncryptDecrypt
    {

        public string Encrypt(string plaintext, params byte[][] parameters)
        {
            ValidateParameters(parameters, 32, 16);
            byte[] key = GetParameter(parameters, 0);
            byte[] iv = GetParameter(parameters, 1);
            return AesEncrypt(plaintext, key, iv);
        }

        public string Decrypt(string ciphertext, params byte[][] parameters)
        {
            ValidateParameters(parameters, 32, 16);
            byte[] key = GetParameter(parameters, 0);
            byte[] iv = GetParameter(parameters, 1);
            return AesDecrypt(ciphertext, key, iv);
        }

        public bool Verify(string plaintext, string hash, params byte[][] parameters)
        {
            byte[] key = GetParameter(parameters, 0);
            byte[] iv = GetParameter(parameters, 1);
            string decrypted = AesDecrypt(hash, key, iv);
            return decrypted == plaintext;
        }
            
        private static string AesEncrypt(string plaintext, byte[] key, byte[] iv)
        {
            byte[] cipheredtext;
            using (Aes aes = Aes.Create())
            {
                ICryptoTransform encryptor = aes.CreateEncryptor(key,iv);
                using(MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor,CryptoStreamMode.Write))
                    {
                        using(StreamWriter  writer = new StreamWriter(cryptoStream))
                        {
                            writer.Write(plaintext);
                        }

                        cipheredtext = memoryStream.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(cipheredtext);
        }

        private static string AesDecrypt(string ciphertext, byte[] key, byte[] iv)
        {
            byte[] cipheredtext = Convert.FromBase64String(ciphertext);
            string simpletext = String.Empty;
            using (Aes aes = Aes.Create())
            {
                ICryptoTransform decryptor = aes.CreateDecryptor(key, iv);
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

        private static byte[] GetParameter(byte[][] parameters, int index)
        {
            if (parameters.Length <= index || parameters[index] == null)
            {
                throw new ArgumentException($"Parameter at index {index} is missing.");
            }
            return parameters[index];
        }

        private static void ValidateParameters(byte[][] parameters, int expectedKeySize, int expectedIvSize)
        {
            if (parameters == null || parameters.Length < 2)
            {
                throw new ArgumentException("Parameters array must contain at least two elements: key and IV.");
            }

            byte[] key = parameters[0];
            byte[] iv = parameters[1];

            if (key == null || iv == null)
            {
                throw new ArgumentException("Key and IV cannot be null.");
            }

            if (key.Length != expectedKeySize)
            {
                throw new ArgumentException($"Key size must be {expectedKeySize} bytes.");
            }

            if (iv.Length != expectedIvSize)
            {
                throw new ArgumentException($"IV size must be {expectedIvSize} bytes.");
            }
        }
    }
}
