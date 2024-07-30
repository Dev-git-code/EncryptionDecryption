using EncyptionDecryption.Algorithms;
using System.Security.Cryptography;
using System.Text;

namespace EncyptionDecryption
{ 
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Choose an algorithm:");
            Console.WriteLine("1. AES");
            Console.WriteLine("2. DES");
            Console.WriteLine("3. RSA");
            Console.WriteLine("4. BCrypt");
            int choice = int.Parse(Console.ReadLine());

            IEncryptDecrypt? encryptDecrypt = null;
            byte[]? parameters = null;

            switch (choice)
            {
                case 1:
                    encryptDecrypt = new AesEncryption();
                    parameters = GenerateRandomKeyAndIV();
                    break;
                case 2:
                    encryptDecrypt = new DesEncryption();
                    parameters = GenerateRandomKey(); 
                    break;
                case 3:
                    encryptDecrypt = new RsaEncryption();
                    parameters = GenerateRandomKey(); 
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
            string plaintext = Console.ReadLine();

            string encrypted = encryptDecrypt.Encrypt(plaintext, parameters);
            Console.WriteLine($"Encrypted: {encrypted}");

          
        }

        static byte[] GenerateRandomKeyAndIV()
        {
            byte[] key = new byte[32]; // AES key size is 32 bytes (256 bits)
            byte[] iv = new byte[16];  // AES IV size is 16 bytes (128 bits)

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
                rng.GetBytes(iv);
            }

            byte[] parameters = new byte[32 + 16];
            Array.Copy(key, 0, parameters, 0, 32);
            Array.Copy(iv, 0, parameters, 32, 16);

            return parameters;
        }

        static byte[] GenerateRandomKey()
        {
            byte[] key = new byte[32]; // Adjust size based on the algorithm
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            return key;
        }

       
    }
}

