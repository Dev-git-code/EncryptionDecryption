using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

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
    }
}
