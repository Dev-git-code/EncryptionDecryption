using ConfigurationEncryptionProvider.Models;
using System;
using System.Collections.Generic;
using System.Text;

namespace ConfigurationEncryptionProvider
{
    public interface IConfigEncryptionProvider
    {
        /// <summary>
        /// Decrypt the section and return key value pair with decrypted strings
        /// </summary>
        /// <param name="section"></param>
        /// <returns></returns>
        Dictionary<string, string> Decrypt(ConfigEncryptionProviderSection section);

        /// <summary>
        /// Encrypt the particular secret
        /// </summary>
        /// <param name="secret"></param>
        /// <returns></returns>
        string Encrypt(string secret);

        /// <summary>
        /// Encrypt the particular section and update the file provided
        /// </summary>
        /// <param name="section"></param>
        /// <param name="filepath"></param>
        void Update(ConfigEncryptionProviderSection section, string filepath);
    }
}
