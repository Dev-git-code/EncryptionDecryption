using EncyptionDecryption;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using EncyptionDecryption.Helpers;

namespace EncyptionDecryption.Algorithms
{
    public class DesEncryption : IEncryptDecrypt<byte[][]>
    {
        private readonly TraceSource traceSource;

        public DesEncryption(TraceSource traceSource)
        {
            this.traceSource = traceSource;
        }

        public string Encrypt(string plaintext, params byte[][] parameters)
        {
            try
            {
                traceSource.TraceInformation($"{DateTime.Now} - Starting DES encryption process.");
                HelperMethods.ValidateParameters(parameters, 8, 8);
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);
                string encrypted = DesEncrypt(plaintext, key, iv);
                traceSource.TraceInformation($"{DateTime.Now} - DES encryption successful.");
                return encrypted;
            }
            catch (ArgumentException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Argument error: {ex.Message}");
                throw new CryptographicException("Invalid parameters provided for encryption.", ex);
            }
            catch (CryptographicException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Cryptographic error: {ex.Message}");
                throw new CryptographicException("An error occurred during encryption.", ex);
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - General error: {ex.Message}");
                throw new CryptographicException("An unknown error occurred during encryption.", ex);
            }
        }

        public string Decrypt(string ciphertext, params byte[][] parameters)
        {
            try
            {
                traceSource.TraceInformation($"{DateTime.Now} - Starting DES decryption process.");
                HelperMethods.ValidateParameters(parameters, 8, 8);
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);
                string decrypted = DesDecrypt(ciphertext, key, iv);
                traceSource.TraceInformation($"{DateTime.Now} - DES decryption successful.");
                return decrypted;
            }
            catch (ArgumentException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Argument error: {ex.Message}");
                throw new CryptographicException("Invalid parameters provided for decryption.", ex);
            }
            catch (CryptographicException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Cryptographic error: {ex.Message}");
                throw new CryptographicException("An error occurred during decryption.", ex);
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - General error: {ex.Message}");
                throw new CryptographicException("An unknown error occurred during decryption.", ex);
            }
        }

        public bool Verify(string plaintext, string hash, params byte[][] parameters)
        {
            try
            {
                traceSource.TraceInformation($"{DateTime.Now} - Starting DES verification process.");
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);
                string decrypted = DesDecrypt(hash, key, iv);
                bool result = decrypted == plaintext;
                if (result)
                {
                    traceSource.TraceInformation($"{DateTime.Now} - DES verification successful.");
                }
                else
                {
                    traceSource.TraceEvent(TraceEventType.Warning, 0, $"{DateTime.Now} - DES verification failed.");
                }
                return result;
            }
            catch (ArgumentException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Argument error: {ex.Message}");
                throw new CryptographicException("Invalid parameters provided for verification.", ex);
            }
            catch (CryptographicException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Cryptographic error: {ex.Message}");
                throw new CryptographicException("An error occurred during verification.", ex);
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - General error: {ex.Message}");
                throw new CryptographicException("An unknown error occurred during verification.", ex);
            }
        }

        private string DesEncrypt(string plaintext, byte[] key, byte[] iv)
        {
            try
            {
                traceSource.TraceInformation($"{DateTime.Now} - Performing DES encryption.");
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
                string encrypted = Convert.ToBase64String(cipheredtext);
                traceSource.TraceInformation($"{DateTime.Now} - DES encryption completed.");
                return encrypted;
            }
            catch (CryptographicException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Error in DesEncrypt: {ex.Message}");
                throw new CryptographicException("An error occurred during the DES encryption process.", ex);
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - General error in DesEncrypt: {ex.Message}");
                throw new CryptographicException("An unknown error occurred during the DES encryption process.", ex);
            }
        }

        private string DesDecrypt(string ciphertext, byte[] key, byte[] iv)
        {
            try
            {
                traceSource.TraceInformation($"{DateTime.Now} - Performing DES decryption.");
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
                traceSource.TraceInformation($"{DateTime.Now} - DES decryption completed.");
                return simpletext;
            }
            catch (CryptographicException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Error in DesDecrypt: {ex.Message}");
                throw new CryptographicException("An error occurred during the DES decryption process.", ex);
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - General error in DesDecrypt: {ex.Message}");
                throw new CryptographicException("An unknown error occurred during the DES decryption process.", ex);
            }
        }
    }
}
