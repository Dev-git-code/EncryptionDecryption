﻿using System;
using System.Security.Cryptography;
using System.Text;
using log4net;

namespace EncyptionDecryption.Algorithms
{
    public class RsaEncryption : IEncryptDecrypt<RSAParameters>
    {
        private readonly ILog logger;

        public RsaEncryption(ILog logger)
        {
            this.logger = logger;
        }

        public string Encrypt(string plaintext, RSAParameters parameters)
        {
            try
            {
                logger.Info("Starting RSA encryption process.");
                if (parameters.Exponent == null || parameters.Exponent.Length == 0)
                {
                    throw new ArgumentException("Invalid RSA public key.");
                }

                string encrypted = RsaEncrypt(plaintext, parameters);
                logger.Info("RSA encryption successful.");
                return encrypted;
            }
            catch (Exception ex)
            {
                logger.Error("Encryption error.", ex);
                throw new CryptographicException("An error occurred during encryption.", ex);
            }
        }

        public string Decrypt(string ciphertext, RSAParameters parameters)
        {
            try
            {
                logger.Info("Starting RSA decryption process.");
                if (parameters.D == null || parameters.D.Length == 0)
                {
                    throw new ArgumentException("Invalid RSA private key.");
                }

                string decrypted = RsaDecrypt(ciphertext, parameters);
                logger.Info("RSA decryption successful.");
                return decrypted;
            }
            catch (Exception ex)
            {
                logger.Error("Decryption error.", ex);
                throw new CryptographicException("An error occurred during decryption.", ex);
            }
        }

        public bool Verify(string plaintext, string hash, RSAParameters parameters)
        {
            try
            {
                logger.Info("Starting RSA verification process.");
                string decryptedHash = Decrypt(hash, parameters);
                bool result = decryptedHash == plaintext;
                if (result)
                {
                    logger.Info("RSA verification successful.");
                }
                else
                {
                    logger.Warn("RSA verification failed.");
                }
                return result;
            }
            catch (Exception ex)
            {
                logger.Error("Verification error.", ex);
                throw new CryptographicException("An error occurred during verification.", ex);
            }
        }

        private string RsaEncrypt(string plaintext, RSAParameters publicKey)
        {
            try
            {
                logger.Info("Performing RSA encryption.");
                using (var rsa = RSA.Create())
                {
                    rsa.ImportParameters(publicKey);
                    byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                    byte[] encryptedBytes = rsa.Encrypt(plaintextBytes, RSAEncryptionPadding.OaepSHA256);
                    string encrypted = Convert.ToBase64String(encryptedBytes);
                    logger.Info("RSA encryption completed.");
                    return encrypted;
                }
            }
            catch (Exception ex)
            {
                logger.Error("Error in RsaEncrypt.", ex);
                throw new CryptographicException("An error occurred during the RSA encryption process.", ex);
            }
        }

        private string RsaDecrypt(string ciphertext, RSAParameters privateKey)
        {
            try
            {
                logger.Info("Performing RSA decryption.");
                byte[] ciphertextBytes = Convert.FromBase64String(ciphertext);
                using (var rsa = RSA.Create())
                {
                    rsa.ImportParameters(privateKey);
                    byte[] decryptedBytes = rsa.Decrypt(ciphertextBytes, RSAEncryptionPadding.OaepSHA256);
                    string decrypted = Encoding.UTF8.GetString(decryptedBytes);
                    logger.Info("RSA decryption completed.");
                    return decrypted;
                }
            }
            catch (Exception ex)
            {
                logger.Error("Error in RsaDecrypt.", ex);
                throw new CryptographicException("An error occurred during the RSA decryption process.", ex);
            }
        }
    }
}
