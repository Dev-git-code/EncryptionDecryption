using EncyptionDecryption;
using EncyptionDecryption.Exceptions;
using EncyptionDecryption.Helpers;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;

namespace EncyptionDecryption.Algorithms
{
    public class DesSaltEncryption : IEncryptDecrypt<byte[][]>
    {
        private const int SaltSize = 8;
        private readonly TraceSource traceSource;

        public DesSaltEncryption(TraceSource traceSource)
        {
            this.traceSource = traceSource;
        }

        public string Encrypt(string plaintext, params byte[][] parameters)
        {
            try
            {
                traceSource.TraceEvent(TraceEventType.Information, 0, $"{DateTime.Now} - Starting encryption process.");
                HelperMethods.ValidateParameters(parameters, 8, 8);
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);

                string salt = GenerateSalt();
                traceSource.TraceEvent(TraceEventType.Information, 0, $"{DateTime.Now} - Generated Salt: {salt}");
                string saltedPassword = salt + plaintext;
                string encrypted = DesEncrypt(saltedPassword, key, iv);
                traceSource.TraceEvent(TraceEventType.Information, 0, $"{DateTime.Now} - Encryption successful. Encrypted text: {encrypted}");
                return salt + ":" + encrypted;
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Encryption error: {ex.Message}");
                throw new EncryptionException("An error occurred during encryption.", ex);
            }
        }

        public string Decrypt(string ciphertext, params byte[][] parameters)
        {
            try
            {
                traceSource.TraceEvent(TraceEventType.Information, 0, $"{DateTime.Now} - Starting decryption process.");
                HelperMethods.ValidateParameters(parameters, 8, 8);
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);

                string[] parts = ciphertext.Split(':');
                if (parts.Length != 2)
                {
                    traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Invalid ciphertext format.");
                    throw new ArgumentException("Invalid ciphertext format.");
                }

                string salt = parts[0];
                string encryptedPassword = parts[1];
                string decrypted = DesDecrypt(encryptedPassword, key, iv);
                traceSource.TraceEvent(TraceEventType.Information, 0, $"{DateTime.Now} - Decryption successful. Decrypted text: {decrypted}");
                return decrypted.Substring(salt.Length);
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Decryption error: {ex.Message}");
                throw new DecryptionException("An error occurred during decryption.", ex);
            }
        }

        public bool Verify(string plaintext, string storedSaltedEncryptedPassword, params byte[][] parameters)
        {
            try
            {
                traceSource.TraceEvent(TraceEventType.Information, 0, $"{DateTime.Now} - Starting verification process.");
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);

                string[] parts = storedSaltedEncryptedPassword.Split(':');
                if (parts.Length != 2)
                {
                    traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Invalid stored salted encrypted password format.");
                    throw new ArgumentException("Invalid stored salted encrypted password format.");
                }

                string salt = parts[0];
                string storedEncryptedPassword = parts[1];
                string enteredSaltedPassword = salt + plaintext;
                string decryptedPassword = DesDecrypt(storedEncryptedPassword, key, iv);
                bool isVerified = decryptedPassword == enteredSaltedPassword;
                traceSource.TraceEvent(TraceEventType.Information, 0, $"{DateTime.Now} - Verification {(isVerified ? "successful" : "failed")}. Entered text matches stored encrypted text.");
                return isVerified;
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
                traceSource.TraceEvent(TraceEventType.Information, 0, $"{DateTime.Now} - Generating salt.");
                byte[] saltBytes = new byte[SaltSize];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(saltBytes);
                }
                string salt = Convert.ToBase64String(saltBytes);
                traceSource.TraceEvent(TraceEventType.Information, 0, $"{DateTime.Now} - Salt generation successful: {salt}");
                return salt;
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Salt generation error: {ex.Message}");
                throw new EncryptionException("An error occurred during salt generation.", ex);
            }
        }

        private string DesEncrypt(string plaintext, byte[] key, byte[] iv)
        {
            try
            {
                traceSource.TraceEvent(TraceEventType.Information, 0, $"{DateTime.Now} - Starting DES encryption process.");
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
                traceSource.TraceEvent(TraceEventType.Information, 0, $"{DateTime.Now} - DES encryption successful. Encrypted text: {encryptedText}");
                return encryptedText;
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - DES encryption error: {ex.Message}");
                throw new EncryptionException("An error occurred during DES encryption.", ex);
            }
        }

        private string DesDecrypt(string ciphertext, byte[] key, byte[] iv)
        {
            try
            {
                traceSource.TraceEvent(TraceEventType.Information, 0, $"{DateTime.Now} - Starting DES decryption process.");
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
                traceSource.TraceEvent(TraceEventType.Information, 0, $"{DateTime.Now} - DES decryption successful. Decrypted text: {simpletext}");
                return simpletext;
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - DES decryption error: {ex.Message}");
                throw new DecryptionException("An error occurred during DES decryption.", ex);
            }
        }
    }
}
    