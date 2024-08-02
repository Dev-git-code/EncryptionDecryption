using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;

namespace EncyptionDecryption.Helpers
{
    public class HelperMethods
    {
        public static byte[] GetParameter(byte[][] parameters, int index)
        {
            if (parameters.Length <= index || parameters[index] == null)
            {
                throw new ArgumentException($"Parameter at index {index} is missing.");
            }
            return parameters[index];
        }

        public static void ValidateParameters(byte[][] parameters, int expectedKeySize, int expectedIvSize)
        {
            if (parameters == null || parameters.Length < 2)
            {
                throw new ArgumentException("Parameters array must contain at least two elements: key and IV.");
            }

            byte[] key = parameters[0];
            byte[] iv = parameters[1];

            if (key == null || iv == null)
            {
                throw new ArgumentException("Key and IV cannot be null.");
            }

            if (key.Length != expectedKeySize)
            {
                throw new ArgumentException($"Key size must be {expectedKeySize} bytes.");
            }

            if (iv.Length != expectedIvSize)
            {
                throw new ArgumentException($"IV size must be {expectedIvSize} bytes.");
            }
        }

        public static byte[][] GenerateRandomKeyAndIV(int keySize, int ivSize)
        {
            byte[] Key = new byte[keySize];
            byte[] iv = new byte[ivSize];

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(Key);
                rng.GetBytes(iv);
            }

            byte[][] parameters = new byte[][]
            {
                Key,iv
            };

            return parameters;
        }

        public static void WriteKeyAndIVToAppSettings(string algorithm, byte[][] keyIv, string filePath)
        {
            var config = new ConfigurationBuilder()
                .AddJsonFile(filePath, optional: false, reloadOnChange: true)
                .Build();

            var keyIvObj = new
            {
                Key = Convert.ToBase64String(keyIv[0]),
                IV = Convert.ToBase64String(keyIv[1])
            };

            var jsonDoc = JsonDocument.Parse(File.ReadAllText(filePath));
            var root = jsonDoc.RootElement.Clone();

            using (var stream = new MemoryStream())
            using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            {
                writer.WriteStartObject();

                foreach (var property in root.EnumerateObject())
                {
                    if (property.NameEquals("CryptoSettings"))
                    {
                        writer.WritePropertyName("CryptoSettings");
                        writer.WriteStartObject();

                        foreach (var subProperty in property.Value.EnumerateObject())
                        {
                            if (subProperty.NameEquals(algorithm))
                            {
                                writer.WritePropertyName(algorithm);
                                writer.WriteStartObject();
                                writer.WriteString("Key", keyIvObj.Key);
                                writer.WriteString("IV", keyIvObj.IV);
                                writer.WriteEndObject();
                            }
                            else
                            {
                                subProperty.WriteTo(writer);
                            }
                        }

                        writer.WriteEndObject();
                    }
                    else
                    {
                        property.WriteTo(writer);
                    }
                }

                writer.WriteEndObject();
                writer.Flush();
                File.WriteAllBytes(filePath, stream.ToArray());
            }
        }

        public static byte[][] ReadKeyAndIVFromAppSettings(string algorithm, string filePath)
        {
            var config = new ConfigurationBuilder()
                .AddJsonFile(filePath, optional: false, reloadOnChange: true)
                .Build();

            var keyIvSection = config.GetSection($"CryptoSettings:{algorithm}");
            string keyBase64 = keyIvSection["Key"];
            string ivBase64 = keyIvSection["IV"];

            byte[] key = Convert.FromBase64String(keyBase64);
            byte[] iv = Convert.FromBase64String(ivBase64);

            return new byte[][] { key, iv };
        }

        public static (RSAParameters PublicKey, RSAParameters PrivateKey) GenerateRsaKeyPair(int keySize)
        {
            using (var rsa = new RSACryptoServiceProvider(keySize))
            {
                rsa.PersistKeyInCsp = false; // Do not persist keys in the CSP
                var publicKey = rsa.ExportParameters(false); // false to exclude private parameters
                var privateKey = rsa.ExportParameters(true);  // true to include private parameters
                return (publicKey, privateKey);
            }
        }

        public static void WriteRsaKeysToAppSettings(string algorithm, RSAParameters publicKey, RSAParameters privateKey, string filePath)
        {
            var config = new ConfigurationBuilder()
                .AddJsonFile(filePath, optional: false, reloadOnChange: true)
                .Build();

            var keyObj = new
            {
                PublicKey = Convert.ToBase64String(publicKey.Modulus),
                PrivateKey = Convert.ToBase64String(privateKey.D) // Adjust according to which parameters you want to save
            };

            var jsonDoc = JsonDocument.Parse(File.ReadAllText(filePath));
            var root = jsonDoc.RootElement.Clone();

            using (var stream = new MemoryStream())
            using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            {
                writer.WriteStartObject();

                foreach (var property in root.EnumerateObject())
                {
                    if (property.NameEquals("CryptoSettings"))
                    {
                        writer.WritePropertyName("CryptoSettings");
                        writer.WriteStartObject();

                        foreach (var subProperty in property.Value.EnumerateObject())
                        {
                            if (subProperty.NameEquals(algorithm))
                            {
                                writer.WritePropertyName(algorithm);
                                writer.WriteStartObject();
                                writer.WriteString("PublicKey", keyObj.PublicKey);
                                writer.WriteString("PrivateKey", keyObj.PrivateKey);
                                writer.WriteEndObject();
                            }
                            else
                            {
                                subProperty.WriteTo(writer);
                            }
                        }

                        writer.WriteEndObject();
                    }
                    else
                    {
                        property.WriteTo(writer);
                    }
                }

                writer.WriteEndObject();
                writer.Flush();
                File.WriteAllBytes(filePath, stream.ToArray());
            }
        }

        public static (RSAParameters PublicKey, RSAParameters PrivateKey) ReadRsaKeysFromAppSettings(string algorithm, string filePath)
        {
            var config = new ConfigurationBuilder()
                .AddJsonFile(filePath, optional: false, reloadOnChange: true)
                .Build();

            var keySection = config.GetSection($"CryptoSettings:{algorithm}");
            string publicKeyBase64 = keySection["PublicKey"];
            string privateKeyBase64 = keySection["PrivateKey"];

            byte[] publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
            byte[] privateKeyBytes = Convert.FromBase64String(privateKeyBase64);

            var publicKey = new RSAParameters { Modulus = publicKeyBytes };
            var privateKey = new RSAParameters { D = privateKeyBytes };

            return (publicKey, privateKey);
        }
    }
}
