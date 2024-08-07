using ConfigurationEncryptionProvider.CryptoProviders.Interfaces;
using ConfigurationEncryptionProvider.Models;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace ConfigurationEncryptionProvider
{
    public class ConfigEncryptionProvider : IConfigEncryptionProvider
    {
        private readonly IConfiguration configuration;
        private readonly ICryptoProviderFactory cryptoProviderFactory;
        public ConfigEncryptionProvider(IConfiguration configuration, ICryptoProviderFactory cryptoProviderFactory)
        {
            if (cryptoProviderFactory == null) throw new ArgumentNullException(typeof(ICryptoProviderFactory).Name);

            this.configuration = configuration;
            this.cryptoProviderFactory = cryptoProviderFactory;
        }

        public Dictionary<string, string> Decrypt(ConfigEncryptionProviderSection section)
        {
            Dictionary<string, string> decryptedKeyValues = new Dictionary<string, string>();
            switch (section)
            {
                case ConfigEncryptionProviderSection.ConnectionsStrings:
                    foreach (var connectionstring in configuration.GetSection(Convert.ToString(section)).GetChildren().AsEnumerable())
                        decryptedKeyValues.Add(connectionstring.Key, cryptoProviderFactory.GetCryptoProvider().Decrypt(connectionstring.Value));
                    break;
                case ConfigEncryptionProviderSection.RabbitMq:
                    var rmqConfig = configuration.GetSection(Convert.ToString(section));
                    if (rmqConfig != null)
                    {
                        decryptedKeyValues.Add("Password", cryptoProviderFactory.GetCryptoProvider().Decrypt(rmqConfig["Password"]));
                    }
                    break;
                default:
                    break;
            }
            return decryptedKeyValues;
        }

        public string Encrypt(string secret)
        {
            if (string.IsNullOrEmpty(secret) == true)
                throw new ArgumentNullException(nameof(secret));
            return cryptoProviderFactory.GetCryptoProvider().Encrypt(secret);
        }

        public void Update(ConfigEncryptionProviderSection section, string filepath)
        {
            if (string.IsNullOrEmpty(filepath) == true)
                throw new ArgumentNullException(nameof(filepath));

            Dictionary<string, string> encryptedKeyValues = new Dictionary<string, string>();
            SetEncryptedKeyVaules(section, encryptedKeyValues);
            if (encryptedKeyValues.Count > 0)
                WriteToFilePath(section, filepath, encryptedKeyValues);
        }

        private static void WriteToFilePath(ConfigEncryptionProviderSection section, string filepath, Dictionary<string, string> encryptedKeyValues)
        {
            string json = File.ReadAllText(filepath);
            var jObject = JObject.Parse(json);

            var configEncryptionSection = jObject[section.ToString()];
            foreach (var item in configEncryptionSection.Children())
            {
                string key = item.Path.Split('.').ToList().Last();
                string value;
                if (encryptedKeyValues.TryGetValue(key, out value))
                    configEncryptionSection[key] = value;
            }
            string output = JsonConvert.SerializeObject(jObject, Formatting.Indented);
            File.WriteAllText(filepath, output);
        }

        private void SetEncryptedKeyVaules(ConfigEncryptionProviderSection section, Dictionary<string, string> encryptedKeyValues)
        {
            switch (section)
            {
                case ConfigEncryptionProviderSection.ConnectionsStrings:
                    foreach (var connectionstring in configuration.GetSection(Convert.ToString(section)).GetChildren().AsEnumerable())
                        encryptedKeyValues.Add(connectionstring.Key, cryptoProviderFactory.GetCryptoProvider().Encrypt(connectionstring.Value));
                    break;
                default:
                    break;
            }
        }
    }
}
