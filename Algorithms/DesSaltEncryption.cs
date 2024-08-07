using EncyptionDecryption;
using EncyptionDecryption.Exceptions;
using EncyptionDecryption.Helpers;
using System;
using System.IO;
using System.Security.Cryptography;
using log4net;

namespace EncyptionDecryption.Algorithms
{
    public class DesSaltEncryption : IEncryptDecrypt<byte[][]>
    {
        private const int SaltSize = 8;
        private readonly ILog logger;

        public DesSaltEncryption(ILog logger)
        {
            this.logger = logger;
        }

        public string Encrypt(string plaintext, params byte[][] parameters)
        {
            try
            {
                logger.Info("Starting encryption process.");
                HelperMethods.ValidateParameters(parameters, 8, 8);
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);

                string salt = GenerateSalt();
                logger.Info($"Generated Salt: {salt}");
                string saltedPassword = salt + plaintext;
                string encrypted = DesEncrypt(saltedPassword, key, iv);
                logger.Info($"Encryption successful. Encrypted text: {encrypted}");
                return salt + ":" + encrypted;
            }
            catch (Exception ex)
            {
                logger.Error($"Encryption error: {ex.Message}", ex);
                throw new EncryptionException("An error occurred during encryption.", ex);
            }
        }

        public string Decrypt(string ciphertext, params byte[][] parameters)
        {
            try
            {
                logger.Info("Starting decryption process.");
                HelperMethods.ValidateParameters(parameters, 8, 8);
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);

                string[] parts = ciphertext.Split(':');
                if (parts.Length != 2)
                {
                    logger.Error("Invalid ciphertext format.");
                    throw new ArgumentException("Invalid ciphertext format.");
                }

                string salt = parts[0];
                string encryptedPassword = parts[1];
                string decrypted = DesDecrypt(encryptedPassword, key, iv);
                logger.Info($"Decryption successful. Decrypted text: {decrypted}");
                return decrypted.Substring(salt.Length);
            }
            catch (Exception ex)
            {
                logger.Error($"Decryption error: {ex.Message}", ex);
                throw new DecryptionException("An error occurred during decryption.", ex);
            }
        }

        public bool Verify(string plaintext, string storedSaltedEncryptedPassword, params byte[][] parameters)
        {
            try
            {
                logger.Info("Starting verification process.");
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);

                string[] parts = storedSaltedEncryptedPassword.Split(':');
                if (parts.Length != 2)
                {
                    logger.Error("Invalid stored salted encrypted password format.");
                    throw new ArgumentException("Invalid stored salted encrypted password format.");
                }

                string salt = parts[0];
                string storedEncryptedPassword = parts[1];
                string enteredSaltedPassword = salt + plaintext;
                string decryptedPassword = DesDecrypt(storedEncryptedPassword, key, iv);
                bool isVerified = decryptedPassword == enteredSaltedPassword;
                logger.Info($"Verification {(isVerified ? "successful" : "failed")}. Entered text matches stored encrypted text.");
                return isVerified;
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
                logger.Info($"Salt generation successful: {salt}");
                return salt;
            }
            catch (Exception ex)
            {
                logger.Error($"Salt generation error: {ex.Message}", ex);
                throw new EncryptionException("An error occurred during salt generation.", ex);
            }
        }

        private string DesEncrypt(string plaintext, byte[] key, byte[] iv)
        {
            try
            {
                logger.Info("Starting DES encryption process.");
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
                string encryptedText = Convert.ToBase64String(cipheredtext);
                logger.Info($"DES encryption successful. Encrypted text: {encryptedText}");
                return encryptedText;
            }
            catch (Exception ex)
            {
                logger.Error($"DES encryption error: {ex.Message}", ex);
                throw new EncryptionException("An error occurred during DES encryption.", ex);
            }
        }

        private string DesDecrypt(string ciphertext, byte[] key, byte[] iv)
        {
            try
            {
                logger.Info("Starting DES decryption process.");
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
                logger.Info($"DES decryption successful. Decrypted text: {simpletext}");
                return simpletext;
            }
            catch (Exception ex)
            {
                logger.Error($"DES decryption error: {ex.Message}", ex);
                throw new DecryptionException("An error occurred during DES decryption.", ex);
            }
        }
    }
}
