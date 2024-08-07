using EncyptionDecryption;
using System;
using System.IO;
using System.Security.Cryptography;
using EncyptionDecryption.Helpers;
using log4net;

namespace EncyptionDecryption.Algorithms
{
    public class DesEncryption : IEncryptDecrypt<byte[][]>
    {
        private readonly ILog _logger;

        public DesEncryption(ILog logger)
        {
            _logger = logger;
        }

        public string Encrypt(string plaintext, params byte[][] parameters)
        {
            _logger.Info("Starting DES encryption process.");

            try
            {
                HelperMethods.ValidateParameters(parameters, 8, 8);
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);
                string encrypted = DesEncrypt(plaintext, key, iv);
                _logger.Info("DES encryption successful.");
                return encrypted;
            }
            catch (ArgumentException ex)
            {
                _logger.Error($"Argument error: {ex.Message}", ex);
                throw new CryptographicException("Invalid parameters provided for encryption.", ex);
            }
            catch (CryptographicException ex)
            {
                _logger.Error($"Cryptographic error: {ex.Message}", ex);
                throw new CryptographicException("An error occurred during encryption.", ex);
            }
            catch (Exception ex)
            {
                _logger.Error($"General error: {ex.Message}", ex);
                throw new CryptographicException("An unknown error occurred during encryption.", ex);
            }
        }

        public string Decrypt(string ciphertext, params byte[][] parameters)
        {
            _logger.Info("Starting DES decryption process.");

            try
            {
                HelperMethods.ValidateParameters(parameters, 8, 8);
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);
                string decrypted = DesDecrypt(ciphertext, key, iv);
                _logger.Info("DES decryption successful.");
                return decrypted;
            }
            catch (ArgumentException ex)
            {
                _logger.Error($"Argument error: {ex.Message}", ex);
                throw new CryptographicException("Invalid parameters provided for decryption.", ex);
            }
            catch (CryptographicException ex)
            {
                _logger.Error($"Cryptographic error: {ex.Message}", ex);
                throw new CryptographicException("An error occurred during decryption.", ex);
            }
            catch (Exception ex)
            {
                _logger.Error($"General error: {ex.Message}", ex);
                throw new CryptographicException("An unknown error occurred during decryption.", ex);
            }
        }

        public bool Verify(string plaintext, string hash, params byte[][] parameters)
        {
            _logger.Info("Starting DES verification process.");

            try
            {
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);
                string decrypted = DesDecrypt(hash, key, iv);
                bool result = decrypted == plaintext;
                if (result)
                {
                    _logger.Info("DES verification successful.");
                }
                else
                {
                    _logger.Warn("DES verification failed.");
                }
                return result;
            }
            catch (ArgumentException ex)
            {
                _logger.Error($"Argument error: {ex.Message}", ex);
                throw new CryptographicException("Invalid parameters provided for verification.", ex);
            }
            catch (CryptographicException ex)
            {
                _logger.Error($"Cryptographic error: {ex.Message}", ex);
                throw new CryptographicException("An error occurred during verification.", ex);
            }
            catch (Exception ex)
            {
                _logger.Error($"General error: {ex.Message}", ex);
                throw new CryptographicException("An unknown error occurred during verification.", ex);
            }
        }

        private string DesEncrypt(string plaintext, byte[] key, byte[] iv)
        {
            _logger.Info("Performing DES encryption.");

            try
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
                string encrypted = Convert.ToBase64String(cipheredtext);
                _logger.Info("DES encryption completed.");
                return encrypted;
            }
            catch (CryptographicException ex)
            {
                _logger.Error($"Error in DesEncrypt: {ex.Message}", ex);
                throw new CryptographicException("An error occurred during the DES encryption process.", ex);
            }
            catch (Exception ex)
            {
                _logger.Error($"General error in DesEncrypt: {ex.Message}", ex);
                throw new CryptographicException("An unknown error occurred during the DES encryption process.", ex);
            }
        }

        private string DesDecrypt(string ciphertext, byte[] key, byte[] iv)
        {
            _logger.Info("Performing DES decryption.");

            try
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
                _logger.Info("DES decryption completed.");
                return simpletext;
            }
            catch (CryptographicException ex)
            {
                _logger.Error($"Error in DesDecrypt: {ex.Message}", ex);
                throw new CryptographicException("An error occurred during the DES decryption process.", ex);
            }
            catch (Exception ex)
            {
                _logger.Error($"General error in DesDecrypt: {ex.Message}", ex);
                throw new CryptographicException("An unknown error occurred during the DES decryption process.", ex);
            }
        }
    }
}
