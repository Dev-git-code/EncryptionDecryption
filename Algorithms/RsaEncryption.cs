using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace EncyptionDecryption.Algorithms
{
    public class RsaEncryption : IEncryptDecrypt<RSAParameters>
    {
        private readonly TraceSource traceSource;

        public RsaEncryption(TraceSource traceSource)
        {
            this.traceSource = traceSource;
        }

        public string Encrypt(string plaintext, RSAParameters parameters)
        {
            try
            {
                traceSource.TraceInformation($"{DateTime.Now} - Starting RSA encryption process.");
                if (parameters.Exponent == null || parameters.Exponent.Length == 0)
                {
                    throw new ArgumentException("Invalid RSA public key.");
                }

                string encrypted = RsaEncrypt(plaintext, parameters);
                traceSource.TraceInformation($"{DateTime.Now} - RSA encryption successful.");
                return encrypted;
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Encryption error: {ex}");
                throw new CryptographicException("An error occurred during encryption.", ex);
            }
        }

        public string Decrypt(string ciphertext, RSAParameters parameters)
        {
            try
            {
                traceSource.TraceInformation($"{DateTime.Now} - Starting RSA decryption process.");
                if (parameters.D == null || parameters.D.Length == 0)
                {
                    throw new ArgumentException("Invalid RSA private key.");
                }

                string decrypted = RsaDecrypt(ciphertext, parameters);
                traceSource.TraceInformation($"{DateTime.Now} - RSA decryption successful.");
                return decrypted;
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Decryption error: {ex}");
                throw new CryptographicException("An error occurred during decryption.", ex);
            }
        }

        public bool Verify(string plaintext, string hash, RSAParameters parameters)
        {
            try
            {
                traceSource.TraceInformation($"{DateTime.Now} - Starting RSA verification process.");
                string decryptedHash = Decrypt(hash, parameters);
                bool result = decryptedHash == plaintext;
                if (result)
                {
                    traceSource.TraceInformation($"{DateTime.Now} - RSA verification successful.");
                }
                else
                {
                    traceSource.TraceEvent(TraceEventType.Warning, 0, $"{DateTime.Now} - RSA verification failed.");
                }
                return result;
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Verification error: {ex}");
                throw new CryptographicException("An error occurred during verification.", ex);
            }
        }

        private string RsaEncrypt(string plaintext, RSAParameters publicKey)
        {
            try
            {
                traceSource.TraceInformation($"{DateTime.Now} - Performing RSA encryption.");
                using (var rsa = RSA.Create())
                {
                    rsa.ImportParameters(publicKey);
                    byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                    byte[] encryptedBytes = rsa.Encrypt(plaintextBytes, RSAEncryptionPadding.OaepSHA256);
                    string encrypted = Convert.ToBase64String(encryptedBytes);
                    traceSource.TraceInformation($"{DateTime.Now} - RSA encryption completed.");
                    return encrypted;
                }
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Error in RsaEncrypt: {ex}");
                throw new CryptographicException("An error occurred during the RSA encryption process.", ex);
            }
        }

        private string RsaDecrypt(string ciphertext, RSAParameters privateKey)
        {
            try
            {
                traceSource.TraceInformation($"{DateTime.Now} - Performing RSA decryption.");
                byte[] ciphertextBytes = Convert.FromBase64String(ciphertext);
                using (var rsa = RSA.Create())
                {
                    rsa.ImportParameters(privateKey);
                    byte[] decryptedBytes = rsa.Decrypt(ciphertextBytes, RSAEncryptionPadding.OaepSHA256);
                    string decrypted = Encoding.UTF8.GetString(decryptedBytes);
                    traceSource.TraceInformation($"{DateTime.Now} - RSA decryption completed.");
                    return decrypted;
                }
            }
            catch (Exception ex)
            {
                traceSource.TraceEvent(TraceEventType.Error, 0, $"{DateTime.Now} - Error in RsaDecrypt: {ex}");
                throw new CryptographicException("An error occurred during the RSA decryption process.", ex);
            }
        }
    }
}
