using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncyptionDecryption
{
    public interface IEncryptDecrypt
    {
        string Encrypt(string plaintext, params byte[][] parameters);
        string Decrypt(string ciphertext, params byte[][] parameters);
        bool Verify(string plaintext, string hash, params byte[][] parameters);
    }
}
