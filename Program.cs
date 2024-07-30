using EncyptionDecryption.Algorithms;
using System.Security.Cryptography;
using System.Text;
using EncyptionDecryption.Helpers;

namespace EncyptionDecryption
{ 
    public class Program
    {
        public static void Main(string[] args)
        {
            while (true)
            {
                Console.WriteLine("Choose an algorithm:");
                Console.WriteLine("1. AES");
                Console.WriteLine("2. DES");
                Console.WriteLine("3. RSA");
                Console.WriteLine("4. BCrypt");
                Console.WriteLine("5. Exit");
                int choice = int.Parse(Console.ReadLine());

                dynamic? encryptDecrypt = null;
                dynamic? parameters = null;

                if (choice == 5)
                {
                    Console.WriteLine("Exiting...");
                    break;
                }

                switch (choice)
                {
                    case 1:
                        encryptDecrypt = new AesEncryption();
                        parameters = HelperMethods.GenerateRandomKeyAndIV(32,16);
                        break;
                    case 2:
                        encryptDecrypt = new DesEncryption();
                        parameters = HelperMethods.GenerateRandomKeyAndIV(8,8); 
                        break;
                    case 3:
                        encryptDecrypt = new RsaEncryption();
                        //parameters = GenerateRandomKey(); 
                        break;
                    case 4:
                        encryptDecrypt = new BCryptEncryption();
                        //parameters = GenerateSalt(); 
                        break;

                    default:
                        Console.WriteLine("Invalid choice.");
                        return;
                }

                Console.Write("Enter the text to encrypt: ");
                string? plaintext = Console.ReadLine();

                string encrypted = encryptDecrypt.Encrypt(plaintext, parameters);
                Console.WriteLine($"Encrypted: {encrypted}");

                string decrypted = encryptDecrypt.Decrypt(encrypted, parameters);
                Console.WriteLine($"Decrypted: {decrypted}");

                bool verify = encryptDecrypt.Verify(plaintext, encrypted, parameters);
                if (verify) Console.WriteLine("Verified Encryption\n");
                else Console.WriteLine("Encryption could not be verified\n");
            }
        }

       
    }
}

