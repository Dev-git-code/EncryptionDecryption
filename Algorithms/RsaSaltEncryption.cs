using System;
using System.Security.Cryptography;
using System.Text;
using log4net;

namespace EncyptionDecryption.Algorithms
{
    public class RsaSaltEncryption : IEncryptDecrypt<RSAParameters>
    {
        private readonly ILog logger;
        private const int SaltSize = 16; // Size of the salt in bytes

        public RsaSaltEncryption(ILog logger)
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

                string salt = GenerateSalt();
                string saltedPlaintext = salt + plaintext;
                string encrypted = RsaEncrypt(saltedPlaintext, parameters);
                logger.Info("RSA encryption successful.");
                return salt + ":" + encrypted;
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

                string[] parts = ciphertext.Split(':');
                if (parts.Length != 2)
                {
                    throw new ArgumentException("Invalid ciphertext format.");
                }

                string salt = parts[0];
                string encryptedText = parts[1];
                string decrypted = RsaDecrypt(encryptedText, parameters);
                logger.Info("RSA decryption successful.");
                return decrypted.Substring(salt.Length);
            }
            catch (Exception ex)
            {
                logger.Error("Decryption error.", ex);
                throw new CryptographicException("An error occurred during decryption.", ex);
            }
        }

        public bool Verify(string plaintext, string storedSaltedEncryptedPassword, RSAParameters parameters)
        {
            try
            {
                logger.Info("Starting RSA verification process.");
                string[] parts = storedSaltedEncryptedPassword.Split(':');
                if (parts.Length != 2)
                {
                    throw new ArgumentException("Invalid stored salted encrypted password format.");
                }

                string salt = parts[0];
                string storedEncryptedPassword = parts[1];
                string enteredSaltedPassword = salt + plaintext;
                string decryptedPassword = Decrypt(salt + ":" + storedEncryptedPassword, parameters);
                bool isVerified = decryptedPassword == plaintext;
                logger.Info($"RSA verification {(isVerified ? "successful" : "failed")}.");
                return isVerified;
            }
            catch (Exception ex)
            {
                logger.Error("Verification error.", ex);
                throw new CryptographicException("An error occurred during verification.", ex);
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
                logger.Info("Salt generation successful.");
                return salt;
            }
            catch (Exception ex)
            {
                logger.Error("Salt generation error.", ex);
                throw new CryptographicException("An error occurred during salt generation.", ex);
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
