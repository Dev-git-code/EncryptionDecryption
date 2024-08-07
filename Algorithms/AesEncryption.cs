using System;
using System.IO;
using System.Security.Cryptography;
using EncyptionDecryption.Exceptions;
using EncyptionDecryption.Helpers;
using EncyptionDecryption;
using log4net;

namespace EncyptionDecryption.Algorithms
{
    public class AesEncryption : IEncryptDecrypt<byte[][]>
    {
        private readonly ILog _logger;

        public AesEncryption(ILog logger)
        {
            _logger = logger;
        }

        public string Encrypt(string plaintext, params byte[][] parameters)
        {
            _logger.Info("Starting encryption process.");

            try
            {
                _logger.Info("Validating parameters for encryption.");
                HelperMethods.ValidateParameters(parameters, 32, 16);

                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);

                _logger.Info("Parameters validated successfully.");
                _logger.Info($"Encryption key: {Convert.ToBase64String(key)}");
                _logger.Info($"Encryption IV: {Convert.ToBase64String(iv)}");

                string encrypted = AesEncrypt(plaintext, key, iv);
                _logger.Info("Encryption successful.");
                _logger.Info($"Encrypted text: {encrypted}");

                return encrypted;
            }
            catch (ArgumentException ex)
            {
                _logger.Error("Argument error: " + ex.Message, ex);
                throw new EncryptionException("Invalid parameters provided for encryption.", ex);
            }
            catch (CryptographicException ex)
            {
                _logger.Error("Cryptographic error: " + ex.Message, ex);
                throw new EncryptionException("An error occurred during encryption.", ex);
            }
            catch (Exception ex)
            {
                _logger.Error("General error: " + ex.Message, ex);
                throw new EncryptionException("An unknown error occurred during encryption.", ex);
            }
        }

        public string Decrypt(string ciphertext, params byte[][] parameters)
        {
            _logger.Info("Starting decryption process.");

            try
            {
                _logger.Info("Validating parameters for decryption.");
                HelperMethods.ValidateParameters(parameters, 32, 16);

                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);

                _logger.Info("Parameters validated successfully.");
                _logger.Info($"Decryption key: {Convert.ToBase64String(key)}");
                _logger.Info($"Decryption IV: {Convert.ToBase64String(iv)}");

                string decrypted = AesDecrypt(ciphertext, key, iv);
                _logger.Info("Decryption successful.");
                _logger.Info($"Decrypted text: {decrypted}");

                return decrypted;
            }
            catch (ArgumentException ex)
            {
                _logger.Error("Argument error: " + ex.Message, ex);
                throw new DecryptionException("Invalid parameters provided for decryption.", ex);
            }
            catch (CryptographicException ex)
            {
                _logger.Error("Cryptographic error: " + ex.Message, ex);
                throw new DecryptionException("An error occurred during decryption.", ex);
            }
            catch (Exception ex)
            {
                _logger.Error("General error: " + ex.Message, ex);
                throw new DecryptionException("An unknown error occurred during decryption.", ex);
            }
        }

        public bool Verify(string plaintext, string hash, params byte[][] parameters)
        {
            _logger.Info("Starting verification process.");

            try
            {
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);

                _logger.Info("Verifying decrypted text against original plaintext.");
                string decrypted = AesDecrypt(hash, key, iv);
                bool isVerified = decrypted == plaintext;

                if (isVerified)
                {
                    _logger.Info("Verification successful.");
                }
                else
                {
                    _logger.Info("Verification failed.");
                }

                return isVerified;
            }
            catch (Exception ex)
            {
                _logger.Error("Verification error: " + ex.Message, ex);
                return false;
            }
        }

        private string AesEncrypt(string plaintext, byte[] key, byte[] iv)
        {
            _logger.Info("Performing AES encryption.");

            try
            {
                byte[] cipheredtext;
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;

                    _logger.Info("AES instance created and configured.");
                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

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

                _logger.Info("AES encryption completed.");
                return Convert.ToBase64String(cipheredtext);
            }
            catch (Exception ex)
            {
                _logger.Error("Error in AesEncrypt: " + ex.Message, ex);
                throw new EncryptionException("An error occurred during AES encryption.", ex);
            }
        }

        private string AesDecrypt(string ciphertext, byte[] key, byte[] iv)
        {
            _logger.Info("Performing AES decryption.");

            try
            {
                byte[] cipheredtext = Convert.FromBase64String(ciphertext);
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;

                    _logger.Info("AES instance created and configured.");
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (MemoryStream memoryStream = new MemoryStream(cipheredtext))
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader streamReader = new StreamReader(cryptoStream))
                            {
                                string result = streamReader.ReadToEnd();
                                _logger.Info("AES decryption completed.");
                                return result;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Error("Error in AesDecrypt: " + ex.Message, ex);
                throw new DecryptionException("An error occurred during AES decryption.", ex);
            }
        }
    }
}
