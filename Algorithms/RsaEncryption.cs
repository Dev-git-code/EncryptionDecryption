using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncyptionDecryption.Algorithms
{
    public class RsaEncryption : IEncryptDecrypt<RSAParameters>
    {
        public string Decrypt(string ciphertext, RSAParameters parameters)
        {
            throw new NotImplementedException();
        }

        public string Encrypt(string plaintext, RSAParameters parameters)
        {
            throw new NotImplementedException();
        }

        public bool Verify(string plaintext, string hash, RSAParameters parameters)
        {
            throw new NotImplementedException();
        }
    }
}
