using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EncyptionDecryption.Algorithms;
using EncyptionDecryption.Helpers;

namespace EncyptionDecryption
{
    public class Program
    {
        public static TraceSource traceSource = new TraceSource("EncryptionDecryptionLogger");

        static Program()
        {
            // Set up the log file path
            string logFilePath = "C:\\Users\\kanch\\source\\repos\\EncyptionDecryption\\encryption_decryption_log.txt";
            Directory.CreateDirectory(Path.GetDirectoryName(logFilePath));

            // Configure the TraceSource
            TraceListener fileListener = new TextWriterTraceListener(logFilePath);
            traceSource.Listeners.Add(fileListener);
            traceSource.Switch = new SourceSwitch("SourceSwitch", "All");
            traceSource.Listeners["Default"].TraceOutputOptions = TraceOptions.DateTime | TraceOptions.Timestamp;
        }
         
        public static void Main(string[] args)
        {
            string filePath = "C:\\Users\\kanch\\source\\repos\\EncyptionDecryption\\appsettings.json";

            while (true)
            {
                Console.WriteLine("Choose an algorithm:");
                Console.WriteLine("1. AES");
                Console.WriteLine("2. DES");
                Console.WriteLine("3. AES Salt");
                Console.WriteLine("4. DES Salt");
                Console.WriteLine("5. RSA");
                Console.WriteLine("6. Exit");
                int choice = int.Parse(Console.ReadLine());

                dynamic? encryptDecrypt = null;
                dynamic? parameters = null;
                string algorithm = "";
                dynamic publicKeyFromFile = null, privateKeyFromFile = null;

                if (choice == 6)
                {
                    traceSource.TraceInformation("User chose to exit.");
                    Console.WriteLine("Exiting...");
                    break;
                }

                try
                {
                    switch (choice)
                    {
                        case 1:
                            algorithm = "AES";
                            var aesParameters = HelperMethods.GenerateRandomKeyAndIV(32, 16);
                            HelperMethods.WriteKeyAndIVToAppSettings(algorithm, aesParameters, filePath);
                            encryptDecrypt = new AesEncryption(traceSource);
                            parameters = HelperMethods.ReadKeyAndIVFromAppSettings(algorithm, filePath);
                            traceSource.TraceInformation("AES algorithm selected.");
                            break;

                        case 2:
                            algorithm = "DES";
                            var desParameters = HelperMethods.GenerateRandomKeyAndIV(8, 8);
                            HelperMethods.WriteKeyAndIVToAppSettings(algorithm, desParameters, filePath);
                            encryptDecrypt = new DesEncryption(traceSource);
                            parameters = HelperMethods.ReadKeyAndIVFromAppSettings(algorithm, filePath);
                            traceSource.TraceInformation("DES algorithm selected.");
                            break;

                        case 3:
                            algorithm = "AES_Salt";
                            var aesSaltParameters = HelperMethods.GenerateRandomKeyAndIV(32, 16);
                            HelperMethods.WriteKeyAndIVToAppSettings(algorithm, aesSaltParameters, filePath);
                            encryptDecrypt = new AesSaltEncryption(traceSource);
                            parameters = HelperMethods.ReadKeyAndIVFromAppSettings(algorithm, filePath);
                            traceSource.TraceInformation("AES with Salt algorithm selected.");
                            break;

                        case 4:
                            algorithm = "DES_Salt";
                            var desSaltParameters = HelperMethods.GenerateRandomKeyAndIV(8, 8);
                            HelperMethods.WriteKeyAndIVToAppSettings(algorithm, desSaltParameters, filePath);
                            encryptDecrypt = new DesSaltEncryption(traceSource);
                            parameters = HelperMethods.ReadKeyAndIVFromAppSettings(algorithm, filePath);
                            traceSource.TraceInformation("DES with Salt algorithm selected.");
                            break;

                        case 5:
                            algorithm = "RSA";
                            (publicKeyFromFile, privateKeyFromFile) = HelperMethods.GenerateRsaKeyPair(2048); // Generate RSA key pair
                            //HelperMethods.WriteRsaKeysToAppSettings(algorithm, publicKey, privateKey, filePath);
                            encryptDecrypt = new RsaEncryption(traceSource);
                           // (publicKeyFromFile, privateKeyFromFile) = HelperMethods.ReadRsaKeysFromAppSettings(algorithm, filePath);
                            traceSource.TraceInformation("RSA algorithm selected.");
                            break;

                        default:
                            traceSource.TraceEvent(TraceEventType.Warning, 0, "Invalid choice.");
                            Console.WriteLine("Invalid choice.");
                            return;
                    }

                    Console.Write("Enter the text to encrypt: ");
                    string? plaintext = Console.ReadLine();

                    traceSource.TraceInformation($"Encrypting text: {plaintext}");

                    if (algorithm == "RSA")
                    {
                        string encrypted = encryptDecrypt.Encrypt(plaintext, publicKeyFromFile);
                        Console.WriteLine($"Encrypted: {encrypted}");

                        string decrypted = encryptDecrypt.Decrypt(encrypted, privateKeyFromFile);
                        Console.WriteLine($"Decrypted: {decrypted}");

                    }
                    else
                    {
                        string encrypted = encryptDecrypt.Encrypt(plaintext, parameters);
                        Console.WriteLine($"Encrypted: {encrypted}");

                        string decrypted = encryptDecrypt.Decrypt(encrypted, parameters);
                        Console.WriteLine($"Decrypted: {decrypted}");

                        bool verify = encryptDecrypt.Verify(plaintext, encrypted, parameters);
                        if (verify) traceSource.TraceInformation("Encryption verified successfully.");
                        else traceSource.TraceEvent(TraceEventType.Warning, 0, "Encryption verification failed.");

                        Console.WriteLine(verify ? "Verified Encryption\n" : "Encryption could not be verified\n");
                    }

                    
                }
                catch (Exception ex)
                {
                    traceSource.TraceEvent(TraceEventType.Error, 0, $"Error occurred: {ex.Message}");
                    Console.WriteLine("An error occurred during encryption/decryption. Check the log file for details.");
                }
            }

            traceSource.Flush();
            traceSource.Close();
        }
    }
}
