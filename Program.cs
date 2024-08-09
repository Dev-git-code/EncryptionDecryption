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
                
                string currentDirectory = Directory.GetCurrentDirectory();
                string projectRootDirectory = Directory.GetParent(Directory.GetParent(Directory.GetParent(currentDirectory).FullName).FullName).FullName;
                var logRepository = LogManager.GetRepository(System.Reflection.Assembly.GetEntryAssembly());         
                string log4netConfigPath = Path.Combine(projectRootDirectory, "log4net.config");
               
                if (!File.Exists(log4netConfigPath))
                {
                    Logger.Error($"Log4net configuration file not found at path: {log4netConfigPath}");
                    return;
                }

                XmlConfigurator.Configure(logRepository, new FileInfo(log4netConfigPath));

               
                string logFilePath = Path.Combine(projectRootDirectory, "encryption_decryption_log.txt");
                string logDirectory = Path.GetDirectoryName(Path.GetFullPath(logFilePath));
                if (!Directory.Exists(logDirectory))
                {
                    Directory.CreateDirectory(logDirectory);
                }

                string filePath = Path.Combine(projectRootDirectory, "appsettings.json");

                while (true)
                {
                    Console.Write("Choose an algorithm:\n1. AES\n2. DES\n3. AES Salt\n4. DES Salt\n5. RSA\n6. RSA with Salt\n7. SRMS Encrypt\n9. Exit\n");
                    string input = Console.ReadLine(); 
                    if (int.TryParse(input, out int choice))
                    {
                        dynamic encryptDecrypt = null;
                        dynamic parameters = null;
                        string algorithm = "";
                        dynamic publicKeyFromFile = null, privateKeyFromFile = null;

                        if (choice == 9)
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

                                case 7:
                                    algorithm = "SRMS";
                                    parameters = filePath;
                                    encryptDecrypt = new SRMSEncryption(Logger);
                                    Logger.Info("SRMS encryption selected.");
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

                                 //string key = "ge9CXD8e6z94PAFC9IpqZW45jkGDtItAtC/dRda5GJ2UNCri6VWTOYPiii9g/Pk2c5VDnWuerim97byptFkMxNysd9VLkst0X55SIlw3AsB8fWxsBzzTqkKUGKRwQbbxb884O0EbTvmfDNMjO/ZTQi1izEOnmO+caCDW1nTw2htST9l7RYsrKPrJK8uQ2x9Z/ke9Xp+SoYokSz87d+mfUZcvXnzBX/N40Qvp6KBx7qd0lTJI3dNRIUeH+erw4u1uLgBTq3KbkIjv+bSGR+jmV/XRHe48agm0+/VYWiRR3kyTvwsQ3iJz/2upCM2OkbilEXDNJ7hy/2Tu5nTKEvKi5RDrfCQOKV+4WHEsoTC/3RJkKBaFC9BDZj329Ufvqw189l80PXR40S/Dg7pXK9F/NpQFPXIxt86E/T6aruQ6fH/M/3fqRRFgYPorzK03EytGZarYEQT+8vqbnkkRXM+gGbt4ykdD578IFiedgUUTuThQL9nrmGbt8C+18alkmxv5cbDckLnUwLGT+AR1UbITk5ebk++OuN6/A/WPwv61pggKq9wrAbGO06D5VFmTVjBbPjcvOMebvclRaeGuTPF2+a4nTXifBMZUWHi8T0tJUzQaTy5iMjkQxjdjfskZahh0lpK1MH9OVxXn6EaGQ+maTmMRYuGuIThHgZYiqVC8FPZ6g3Bw79BUWq9xC8C9a2T248BuWbjeWiXFW4brad3mgc7PgHncMMKsiW816+byy06hBF7h6wOqiO4krSm7MKMaWNxJyn6Uf8RFNkJpkLRMly8shRCljEG2DZ/FZfmcNlfe6fLrCJFl3Q3QRSEbui7jABd5DlA3pq+1Vb0dHkDEl0vLNp9jzmnWC3CMevoV1lvDDHIJim5NSq2yDWBqSztaRRSQtg3m3CNyTwNeONP3HKIzAjLGBAxiWuqd3tNPfDz09HOBO41YObojDJwO1b3KmhxuMKfiURaaf8P7kq6KPXbBAwUcYeXrhXzSsea5ZlaO3mVXowbYTAcXm/8KBTOcmsgxd0i0oUsAnP26ebUQBN7U6tJFjJYueqTkTHMJJtsfHeQWXEUnyThs7NjUrzpZKqHK7+9dzUx9Se/Q5CSgWzVfJOhXq53PjsPr90qYsY1GB6tazeHPfv9fAMaMMfZ14xongD23B0pDWcx8fCmkezT/Nop7MPxqFnfvPZjQ0QKNmG5sM1ChgWsTdAvFyv8XCj98ienRUnWRilR7EvF4egjkOkeKDvfz83YX83mazR0J3xy+cPR69Q4nXX0CeGyGt4rEPzsCbkj3El7R+xICJPeWUPu5rvdDJL8c6C2c+6bqjrct8FHK7iZABcMQzBfBEikHAPCEHTJVtzqhl1mXEiRDlmAqHWbRoROvxt5eq9AB7Cg46sEzwOZMh5nZZ/M9BlNA8Sn1N2tUI9VdWXbAekdkQqsFc+B8MfjQU8InBCXqP58bLo7WSKmG22yKfXLVQFQ2QkFDa067iSjg2KB7esRGyaVFxdCo78L/Rt2Vqa4uJqYaPo3egEHrFXGODCYzCRc4lajcmIOTWOsnVAO+968/T0tsdsnSIcUWRlOIDhHp8MKUqA5HlRnSZnd/2/u4SUOYas6VNiOT1nhSGh4X1D6S1feKsXglm9pLe7pqX4JC811jq+ZfE0usuAqxFkSd";


                                 string decrypted = encryptDecrypt.Decrypt(encrypted, parameters);
                                 Logger.Info($"Decrypted: {decrypted}");


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
