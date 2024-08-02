using EncyptionDecryption.Exceptions;
using EncyptionDecryption.Helpers;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace EncyptionDecryption.Algorithms
{
    public class AesSaltEncryption : IEncryptDecrypt<byte[][]>
    {
        private const int SaltSize = 16;
        private readonly TraceSource traceSource;

        public AesSaltEncryption(TraceSource traceSource)
        {
            this.traceSource = traceSource;
        }

        public string Encrypt(string plaintext, params byte[][] parameters)
        {
            try
            {
                traceSource.TraceInformation($"{DateTime.Now} - Starting encryption process.");
                HelperMethods.ValidateParameters(parameters, 32, 16);
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);

                traceSource.TraceInformation($"{DateTime.Now} - Validating parameters for encryption.");
                string salt = GenerateSalt();
                traceSource.TraceInformation($"{DateTime.Now} - Generated Salt: {salt}");
                string saltedPassword = salt + plaintext;
                string encrypted = AesEncrypt(saltedPassword, key, iv);
                traceSource.TraceInformation($"{DateTime.Now} - Encryption successful.");
                return salt + ":" + encrypted;
            }
            catch (ArgumentException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Argument error: {ex.Message}");
                throw new EncryptionException("Invalid parameters provided for encryption.", ex);
            }
            catch (CryptographicException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Cryptographic error: {ex.Message}");
                throw new EncryptionException("An error occurred during encryption.", ex);
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - General error: {ex.Message}");
                throw new EncryptionException("An unknown error occurred during encryption.", ex);
            }
        }

        public string Decrypt(string ciphertext, params byte[][] parameters)
        {
            try
            {
                traceSource.TraceInformation($"{DateTime.Now} - Starting decryption process.");
                HelperMethods.ValidateParameters(parameters, 32, 16);
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);

                traceSource.TraceInformation($"{DateTime.Now} - Validating parameters for decryption.");
                string[] parts = ciphertext.Split(':');
                if (parts.Length != 2)
                {
                    traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Invalid ciphertext format.");
                    throw new ArgumentException("Invalid ciphertext format.");
                }

                string salt = parts[0];
                string encryptedPassword = parts[1];
                string decrypted = AesDecrypt(encryptedPassword, key, iv);
                traceSource.TraceInformation($"{DateTime.Now} - Decryption successful.");
                return decrypted.Substring(salt.Length);
            }
            catch (ArgumentException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Argument error: {ex.Message}");
                throw new DecryptionException("Invalid parameters or format provided for decryption.", ex);
            }
            catch (CryptographicException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Cryptographic error: {ex.Message}");
                throw new DecryptionException("An error occurred during decryption.", ex);
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - General error: {ex.Message}");
                throw new DecryptionException("An unknown error occurred during decryption.", ex);
            }
        }

        public bool Verify(string plaintext, string storedSaltedEncryptedPassword, params byte[][] parameters)
        {
            try
            {
                traceSource.TraceInformation($"{DateTime.Now} - Starting verification process.");
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);

                traceSource.TraceInformation($"{DateTime.Now} - Validating parameters for verification.");
                string[] parts = storedSaltedEncryptedPassword.Split(':');
                if (parts.Length != 2)
                {
                    traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Invalid stored salted encrypted password format.");
                    throw new ArgumentException("Invalid stored salted encrypted password format.");
                }

                string salt = parts[0];
                string storedEncryptedPassword = parts[1];
                string enteredSaltedPassword = salt + plaintext;
                string decryptedPassword = AesDecrypt(storedEncryptedPassword, key, iv);
                bool result = decryptedPassword == enteredSaltedPassword;
                if (result)
                {
                    traceSource.TraceInformation($"{DateTime.Now} - Verification successful.");
                }
                else
                {
                    traceSource.TraceEvent(TraceEventType.Warning, 0, $"{DateTime.Now} - Verification failed.");
                }
                return result;
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Verification error: {ex.Message}");
                return false;
            }
        }

        private string GenerateSalt()
        {
            try
            {
                traceSource.TraceInformation($"{DateTime.Now} - Generating salt.");
                byte[] saltBytes = new byte[SaltSize];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(saltBytes);
                }
                string salt = Convert.ToBase64String(saltBytes);
                traceSource.TraceInformation($"{DateTime.Now} - Generated salt: {salt}");
                return salt;
            }
            catch (CryptographicException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Error generating salt: {ex.Message}");
                throw new EncryptionException("An error occurred during salt generation.", ex);
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - General error generating salt: {ex.Message}");
                throw new EncryptionException("An unknown error occurred during salt generation.", ex);
            }
        }

        private string AesEncrypt(string plaintext, byte[] key, byte[] iv)
        {
            try
            {
                traceSource.TraceInformation($"{DateTime.Now} - Performing AES encryption.");
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
                            traceSource.TraceInformation($"{DateTime.Now} - AES encryption completed.");
                            return encrypted;
                        }
                    }
                }
            }
            catch (CryptographicException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Error in AesEncrypt: {ex.Message}");
                throw new EncryptionException("An error occurred during AES encryption.", ex);
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - General error in AesEncrypt: {ex.Message}");
                throw new EncryptionException("An unknown error occurred during AES encryption.", ex);
            }
        }

        private string AesDecrypt(string ciphertext, byte[] key, byte[] iv)
        {
            try
            {
                traceSource.TraceInformation($"{DateTime.Now} - Performing AES decryption.");
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
                                traceSource.TraceInformation($"{DateTime.Now} - AES decryption completed.");
                                return decrypted;
                            }
                        }
                    }
                }
            }
            catch (CryptographicException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Error in AesDecrypt: {ex.Message}");
                throw new DecryptionException("An error occurred during AES decryption.", ex);
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - General error in AesDecrypt: {ex.Message}");
                throw new DecryptionException("An unknown error occurred during AES decryption.", ex);
            }
        }
    }
}
