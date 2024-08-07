using System;
using System.IO;
using EncyptionDecryption.Algorithms;
using EncyptionDecryption.Helpers;
using log4net;
using log4net.Config;

namespace EncryptionDecryption
{
    public class Program
    {
        private static readonly ILog Logger = LogManager.GetLogger(typeof(Program));

        static void Main(string[] args)
        {
            try
            {
                // Configure log4net using the configuration file
                var logRepository = LogManager.GetRepository(System.Reflection.Assembly.GetEntryAssembly());
                string log4netConfigPath = "C:\\Users\\kanch\\source\\repos\\EncyptionDecryption\\log4net.config"; // Ensure this path is correct
                if (!File.Exists(log4netConfigPath))
                {
                    Logger.Error($"Log4net configuration file not found at path: {log4netConfigPath}");
                    return;
                }

                XmlConfigurator.Configure(logRepository, new FileInfo(log4netConfigPath));

                // Ensure the log directory exists
                string logFilePath = "C:\\Users\\kanch\\source\\repos\\EncyptionDecryption\\encryption_decryption_log.txt";
                string logDirectory = Path.GetDirectoryName(Path.GetFullPath(logFilePath));
                if (!Directory.Exists(logDirectory))
                {
                    Directory.CreateDirectory(logDirectory);
                }

                string filePath = "C:\\Users\\kanch\\source\\repos\\EncyptionDecryption\\appsettings.json";

                while (true)
                {
                    Console.Write("Choose an algorithm:\n1. AES\n2. DES\n3. AES Salt\n4. DES Salt\n5. RSA\n6. RSA with Salt\n7. Exit\n");
                    string input = Console.ReadLine(); // Capture user input for algorithm choice
                    if (int.TryParse(input, out int choice))
                    {
                        dynamic encryptDecrypt = null;
                        dynamic parameters = null;
                        string algorithm = "";
                        dynamic publicKeyFromFile = null, privateKeyFromFile = null;

                        if (choice == 7)
                        {
                            Logger.Info("User chose to exit.");
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
                                    encryptDecrypt = new AesEncryption(Logger);
                                    parameters = HelperMethods.ReadKeyAndIVFromAppSettings(algorithm, filePath);
                                    Logger.Info("AES algorithm selected.");
                                    break;

                                case 2:
                                    algorithm = "DES";
                                    var desParameters = HelperMethods.GenerateRandomKeyAndIV(8, 8);
                                    HelperMethods.WriteKeyAndIVToAppSettings(algorithm, desParameters, filePath);
                                    encryptDecrypt = new DesEncryption(Logger);
                                    parameters = HelperMethods.ReadKeyAndIVFromAppSettings(algorithm, filePath);
                                    Logger.Info("DES algorithm selected.");
                                    break;

                                case 3:
                                    algorithm = "AES_Salt";
                                    var aesSaltParameters = HelperMethods.GenerateRandomKeyAndIV(32, 16);
                                    HelperMethods.WriteKeyAndIVToAppSettings(algorithm, aesSaltParameters, filePath);
                                    encryptDecrypt = new AesSaltEncryption(Logger);
                                    parameters = HelperMethods.ReadKeyAndIVFromAppSettings(algorithm, filePath);
                                    Logger.Info("AES with Salt algorithm selected.");
                                    break;

                                case 4:
                                    algorithm = "DES_Salt";
                                    var desSaltParameters = HelperMethods.GenerateRandomKeyAndIV(8, 8);
                                    HelperMethods.WriteKeyAndIVToAppSettings(algorithm, desSaltParameters, filePath);
                                    encryptDecrypt = new DesSaltEncryption(Logger);
                                    parameters = HelperMethods.ReadKeyAndIVFromAppSettings(algorithm, filePath);
                                    Logger.Info("DES with Salt algorithm selected.");
                                    break;

                                case 5:
                                    algorithm = "RSA";
                                    (publicKeyFromFile, privateKeyFromFile) = HelperMethods.GenerateRsaKeyPair(2048);
                                    encryptDecrypt = new RsaEncryption(Logger);
                                    Logger.Info("RSA algorithm selected.");
                                    break;

                                case 6:
                                    algorithm = "RSA_Salt";
                                    (publicKeyFromFile, privateKeyFromFile) = HelperMethods.GenerateRsaKeyPair(2048);
                                    encryptDecrypt = new RsaSaltEncryption(Logger);
                                    Logger.Info("RSA algorithm selected.");
                                    break;

                                default:
                                    Logger.Error("Invalid choice.");
                                    continue; 
                            }

                            Console.WriteLine("Enter the text to encrypt: ");
                            string plaintext = Console.ReadLine();

                            Logger.Info($"Encrypting text: {plaintext}");

                            if (algorithm == "RSA")
                            {
                                string encrypted = encryptDecrypt.Encrypt(plaintext, publicKeyFromFile);
                                Logger.Info($"Encrypted: {encrypted}");

                                string decrypted = encryptDecrypt.Decrypt(encrypted, privateKeyFromFile);
                                Logger.Info($"Decrypted: {decrypted}");
                            }
                            else
                            {
                                string encrypted = encryptDecrypt.Encrypt(plaintext, parameters);
                                Logger.Info($"Encrypted: {encrypted}");

                                string decrypted = encryptDecrypt.Decrypt(encrypted, parameters);
                                Logger.Info($"Decrypted: {decrypted}");

                                bool verify = encryptDecrypt.Verify(plaintext, encrypted, parameters);
                                if (verify) Logger.Info("Encryption verified successfully.");
                                else Logger.Error("Encryption verification failed.");
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Error($"Error occurred during encryption/decryption: {ex.Message}", ex);
                        }
                    }
                    else
                    {
                        Logger.Error("Invalid choice.");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Initialization error: {ex.Message}", ex);
            }
        }
    }
}
