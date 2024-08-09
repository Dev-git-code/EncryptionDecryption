using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncyptionDecryption
{
    public interface IEncryptDecrypt<T>
    { 
        string Encrypt(string plaintext, T parameters);
        string Decrypt(string ciphertext, T parameters);
       
    }
}
