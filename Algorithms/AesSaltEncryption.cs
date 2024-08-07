using EncyptionDecryption.Exceptions;
using EncyptionDecryption.Helpers;
using System;
using System.IO;
using System.Security.Cryptography;
using log4net;

namespace EncyptionDecryption.Algorithms
{
    public class AesSaltEncryption : IEncryptDecrypt<byte[][]>
    {
        private const int SaltSize = 16;
        private readonly ILog logger;

        public AesSaltEncryption(ILog logger)
        {
            this.logger = logger;
        }

        public string Encrypt(string plaintext, params byte[][] parameters)
        {
            try
            {
                logger.Info("Starting encryption process.");
                HelperMethods.ValidateParameters(parameters, 32, 16);
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);

                logger.Info("Validating parameters for encryption.");
                string salt = GenerateSalt();
                logger.Info($"Generated Salt: {salt}");
                string saltedPassword = salt + plaintext;
                string encrypted = AesEncrypt(saltedPassword, key, iv);
                logger.Info("Encryption successful.");
                return salt + ":" + encrypted;
            }
            catch (ArgumentException ex)
            {
                logger.Error($"Argument error: {ex.Message}", ex);
                throw new EncryptionException("Invalid parameters provided for encryption.", ex);
            }
            catch (CryptographicException ex)
            {
                logger.Error($"Cryptographic error: {ex.Message}", ex);
                throw new EncryptionException("An error occurred during encryption.", ex);
            }
            catch (Exception ex)
            {
                logger.Error($"General error: {ex.Message}", ex);
                throw new EncryptionException("An unknown error occurred during encryption.", ex);
            }
        }

        public string Decrypt(string ciphertext, params byte[][] parameters)
        {
            try
            {
                logger.Info("Starting decryption process.");
                HelperMethods.ValidateParameters(parameters, 32, 16);
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);

                logger.Info("Validating parameters for decryption.");
                string[] parts = ciphertext.Split(':');
                if (parts.Length != 2)
                {
                    logger.Error("Invalid ciphertext format.");
                    throw new ArgumentException("Invalid ciphertext format.");
                }

                string salt = parts[0];
                string encryptedPassword = parts[1];
                string decrypted = AesDecrypt(encryptedPassword, key, iv);
                logger.Info("Decryption successful.");
                return decrypted.Substring(salt.Length);
            }
            catch (ArgumentException ex)
            {
                logger.Error($"Argument error: {ex.Message}", ex);
                throw new DecryptionException("Invalid parameters or format provided for decryption.", ex);
            }
            catch (CryptographicException ex)
            {
                logger.Error($"Cryptographic error: {ex.Message}", ex);
                throw new DecryptionException("An error occurred during decryption.", ex);
            }
            catch (Exception ex)
            {
                logger.Error($"General error: {ex.Message}", ex);
                throw new DecryptionException("An unknown error occurred during decryption.", ex);
            }
        }

        public bool Verify(string plaintext, string storedSaltedEncryptedPassword, params byte[][] parameters)
        {
            try
            {
                logger.Info("Starting verification process.");
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);

                logger.Info("Validating parameters for verification.");
                string[] parts = storedSaltedEncryptedPassword.Split(':');
                if (parts.Length != 2)
                {
                    logger.Error("Invalid stored salted encrypted password format.");
                    throw new ArgumentException("Invalid stored salted encrypted password format.");
                }

                string salt = parts[0];
                string storedEncryptedPassword = parts[1];
                string enteredSaltedPassword = salt + plaintext;
                string decryptedPassword = AesDecrypt(storedEncryptedPassword, key, iv);
                bool result = decryptedPassword == enteredSaltedPassword;
                if (result)
                {
                    logger.Info("Verification successful.");
                }
                else
                {
                    logger.Warn("Verification failed.");
                }
                return result;
            }
            catch (Exception ex)
            {
                logger.Error($"Verification error: {ex.Message}", ex);
                return false;
            }
        }

        private string GenerateSalt()
        {
            try
            {
                logger.Info("Generating salt.");
                byte[] saltBytes = new byte[SaltSize];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(saltBytes);
                }
                string salt = Convert.ToBase64String(saltBytes);
                logger.Info($"Generated salt: {salt}");
                return salt;
            }
            catch (CryptographicException ex)
            {
                logger.Error($"Error generating salt: {ex.Message}", ex);
                throw new EncryptionException("An error occurred during salt generation.", ex);
            }
            catch (Exception ex)
            {
                logger.Error($"General error generating salt: {ex.Message}", ex);
                throw new EncryptionException("An unknown error occurred during salt generation.", ex);
            }
        }

        private string AesEncrypt(string plaintext, byte[] key, byte[] iv)
        {
            try
            {
                logger.Info("Performing AES encryption.");
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                    using (MemoryStream memoryStream = new MemoryStream())
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                        {   
                            using (StreamWriter writer = new StreamWriter(cryptoStream))
                            {
                                writer.Write(plaintext);
                            }
                            string encrypted = Convert.ToBase64String(memoryStream.ToArray());
                            logger.Info("AES encryption completed.");
                            return encrypted;
                        }
                    }
                }
            }
            catch (CryptographicException ex)
            {
                logger.Error($"Error in AesEncrypt: {ex.Message}", ex);
                throw new EncryptionException("An error occurred during AES encryption.", ex);
            }
            catch (Exception ex)
            {
                logger.Error($"General error in AesEncrypt: {ex.Message}", ex);
                throw new EncryptionException("An unknown error occurred during AES encryption.", ex);
            }
        }

        private string AesDecrypt(string ciphertext, byte[] key, byte[] iv)
        {
            try
            {
                logger.Info("Performing AES decryption.");
                byte[] cipheredtext = Convert.FromBase64String(ciphertext);
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                    using (MemoryStream memoryStream = new MemoryStream(cipheredtext))
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader streamReader = new StreamReader(cryptoStream))
                            {
                                string decrypted = streamReader.ReadToEnd();
                                logger.Info("AES decryption completed.");
                                return decrypted;
                            }
                        }
                    }
                }
            }
            catch (CryptographicException ex)
            {
                logger.Error($"Error in AesDecrypt: {ex.Message}", ex);
                throw new DecryptionException("An error occurred during AES decryption.", ex);
            }
            catch (Exception ex)
            {
                logger.Error($"General error in AesDecrypt: {ex.Message}", ex);
                throw new DecryptionException("An unknown error occurred during AES decryption.", ex);
            }
        }
    }
}
