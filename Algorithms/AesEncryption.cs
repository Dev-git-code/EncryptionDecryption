﻿using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using EncyptionDecryption.Exceptions;
using EncyptionDecryption.Helpers;

namespace EncyptionDecryption.Algorithms
{
    public class AesEncryption : IEncryptDecrypt<byte[][]>
    {
        private TraceSource traceSource;

        public AesEncryption(TraceSource traceSource)
        {
            this.traceSource = traceSource;
        }

        public string Encrypt(string plaintext, params byte[][] parameters)
        {
            traceSource.TraceInformation($"{DateTime.Now} - Starting encryption process.");
            traceSource.Flush();

            try
            {
                traceSource.TraceInformation($"{DateTime.Now} - Validating parameters for encryption.");
                traceSource.Flush();
                HelperMethods.ValidateParameters(parameters, 32, 16);

                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);

                traceSource.TraceInformation($"{DateTime.Now} - Parameters validated successfully.");
                traceSource.TraceInformation($"{DateTime.Now} - Encryption key: {Convert.ToBase64String(key)}");
                traceSource.TraceInformation($"{DateTime.Now} - Encryption IV: {Convert.ToBase64String(iv)}");
                traceSource.Flush();

                string encrypted = AesEncrypt(plaintext, key, iv);
                traceSource.TraceInformation($"{DateTime.Now} - Encryption successful.");
                traceSource.TraceInformation($"{DateTime.Now} - Encrypted text: {encrypted}");
                traceSource.Flush();

                return encrypted;
            }
            catch (ArgumentException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Argument error: {ex.Message}");
                traceSource.Flush();
                throw new EncryptionException("Invalid parameters provided for encryption.", ex);
            }
            catch (CryptographicException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Cryptographic error: {ex.Message}");
                traceSource.Flush();
                throw new EncryptionException("An error occurred during encryption.", ex);
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - General error: {ex.Message}");
                traceSource.Flush();
                throw new EncryptionException("An unknown error occurred during encryption.", ex);
            }
        }

        public string Decrypt(string ciphertext, params byte[][] parameters)
        {
            traceSource.TraceInformation($"{DateTime.Now} - Starting decryption process.");
            traceSource.Flush();

            try
            {
                traceSource.TraceInformation($"{DateTime.Now} - Validating parameters for decryption.");
                traceSource.Flush();
                HelperMethods.ValidateParameters(parameters, 32, 16);

                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);

                traceSource.TraceInformation($"{DateTime.Now} - Parameters validated successfully.");
                traceSource.TraceInformation($"{DateTime.Now} - Decryption key: {Convert.ToBase64String(key)}");
                traceSource.TraceInformation($"{DateTime.Now} - Decryption IV: {Convert.ToBase64String(iv)}");
                traceSource.Flush();

                string decrypted = AesDecrypt(ciphertext, key, iv);
                traceSource.TraceInformation($"{DateTime.Now} - Decryption successful.");
                traceSource.TraceInformation($"{DateTime.Now} - Decrypted text: {decrypted}");
                traceSource.Flush();

                return decrypted;
            }
            catch (ArgumentException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Argument error: {ex.Message}");
                traceSource.Flush();
                throw new DecryptionException("Invalid parameters provided for decryption.", ex);
            }
            catch (CryptographicException ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Cryptographic error: {ex.Message}");
                traceSource.Flush();
                throw new DecryptionException("An error occurred during decryption.", ex);
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - General error: {ex.Message}");
                traceSource.Flush();
                throw new DecryptionException("An unknown error occurred during decryption.", ex);
            }
        }

        public bool Verify(string plaintext, string hash, params byte[][] parameters)
        {
            traceSource.TraceInformation($"{DateTime.Now} - Starting verification process.");
            traceSource.Flush();

            try
            {
                byte[] key = HelperMethods.GetParameter(parameters, 0);
                byte[] iv = HelperMethods.GetParameter(parameters, 1);

                traceSource.TraceInformation($"{DateTime.Now} - Verifying decrypted text against original plaintext.");
                traceSource.Flush();
                string decrypted = AesDecrypt(hash, key, iv);
                bool isVerified = decrypted == plaintext;

                if (isVerified)
                {
                    traceSource.TraceInformation($"{DateTime.Now} - Verification successful.");
                }
                else
                {
                    traceSource.TraceInformation($"{DateTime.Now} - Verification failed.");
                }
                traceSource.Flush();

                return isVerified;
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Verification error: {ex.Message}");
                traceSource.Flush();
                return false;
            }
        }

        private string AesEncrypt(string plaintext, byte[] key, byte[] iv)
        {
            traceSource.TraceInformation($"{DateTime.Now} - Performing AES encryption.");
            traceSource.Flush();

            try
            {
                byte[] cipheredtext;
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;

                    traceSource.TraceInformation($"{DateTime.Now} - AES instance created and configured.");
                    traceSource.Flush();
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

                traceSource.TraceInformation($"{DateTime.Now} - AES encryption completed.");
                traceSource.Flush();
                return Convert.ToBase64String(cipheredtext);
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Error in AesEncrypt: {ex.Message}");
                traceSource.Flush();
                throw new EncryptionException("An error occurred during AES encryption.", ex);
            }
        }

        private string AesDecrypt(string ciphertext, byte[] key, byte[] iv)
        {
            traceSource.TraceInformation($"{DateTime.Now} - Performing AES decryption.");
            traceSource.Flush();

            try
            {
                byte[] cipheredtext = Convert.FromBase64String(ciphertext);
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;

                    traceSource.TraceInformation($"{DateTime.Now} - AES instance created and configured.");
                    traceSource.Flush();
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (MemoryStream memoryStream = new MemoryStream(cipheredtext))
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader streamReader = new StreamReader(cryptoStream))
                            {
                                string result = streamReader.ReadToEnd();
                                traceSource.TraceInformation($"{DateTime.Now} - AES decryption completed.");
                                traceSource.Flush();
                                return result;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Error in AesDecrypt: {ex.Message}");
                traceSource.Flush();
                throw new DecryptionException("An error occurred during AES decryption.", ex);
            }
        }
    }
}
