﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncyptionDecryption.Algorithms
{
    public class BCryptEncryption : IEncryptDecrypt
    {
        public string Decrypt(string ciphertext, params byte[] parameters)
        {
            throw new NotImplementedException();
        }

        public string Encrypt(string plaintext, params byte[] parameters)
        {
            throw new NotImplementedException();
        }

        public string Verify(string plaintext, string hash, params byte[] parameters)
        {
            throw new NotImplementedException();
        }
    }
}
