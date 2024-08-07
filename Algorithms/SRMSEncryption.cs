using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ConfigurationEncryptionProvider;
using ConfigurationEncryptionProvider.Models;
using log4net;
using ConfigurationEncryptionProvider.CryptoProviders.Implementations;
using ConfigurationEncryptionProvider.CryptoProviders.Interfaces;
using Microsoft.Extensions.Options;

namespace EncyptionDecryption.Algorithms
{
    public class SRMSEncryption
    {
        private readonly ILog _logger;

        public SRMSEncryption(ILog logger)
        {
            _logger = logger;
        }
        private void FetchInputs(IConfiguration configuration, out EncryptionSettings encryptionSettings, out ConfigEncryptionProviderSection configEncryptionProviderSection)
        {

            encryptionSettings = new EncryptionSettings();
            configEncryptionProviderSection = new ConfigEncryptionProviderSection();
            try
            {
                IConfigurationSection configurationSection = configuration.GetSection("srmconfig");
                encryptionSettings.Algorithm = "AES";
                encryptionSettings.Key = configurationSection["suffix"];
                encryptionSettings.IV = configurationSection["preffix"];
                configEncryptionProviderSection = (ConfigEncryptionProviderSection)Enum.Parse(typeof(ConfigEncryptionProviderSection), "ConnectionsStrings");
            }
            catch (Exception ex)
            {
                _logger.Error("Unable to Fetch data from config file : " + ex.Message);
            }
        }

        private void EncryptSRMSFile(string file)
        {
            try
            {
                IConfiguration configuration = new ConfigurationBuilder().AddJsonFile(file).Build();
                this.FetchInputs(configuration, out EncryptionSettings encryptionSettings, out ConfigEncryptionProviderSection configEncryptionProviderSection);

                IOptions<EncryptionSettings> options = Options.Create(encryptionSettings);
                ICryptoProviderFactory cryptoProviderFactory = new CryptoProviderFactory(options);
                IConfigEncryptionProvider configEncryptionProvider = new ConfigEncryptionProvider(configuration, cryptoProviderFactory);
                configEncryptionProvider.Update(configEncryptionProviderSection, file);
            }
            catch (Exception ex)
            {
                _logger.Error("SRMS encryption failed : " + ex.Message);
            }

        }

        public string EncryptString(string StringTobeEncrypted, string FilePath)
        {
            try
            {
                if (StringTobeEncrypted == "")
                {
                    return "";
                }

                IConfiguration configuration = new ConfigurationBuilder().AddJsonFile(FilePath).Build();
                IConfigurationSection configurationSection = configuration.GetSection("srmconfig");
                EncryptionSettings encryptionSettings;
                encryptionSettings = new EncryptionSettings
                {
                    Algorithm = "AES",
                    Key = configurationSection["suffix"],
                    IV = configurationSection["preffix"]
                };
                IOptions<EncryptionSettings> options = Options.Create(encryptionSettings);
                ICryptoProviderFactory cryptoProviderFactory = new CryptoProviderFactory(options);
                IConfigEncryptionProvider configEncryptionProvider = new ConfigEncryptionProvider(configuration, cryptoProviderFactory);
                return configEncryptionProvider.Encrypt(StringTobeEncrypted);
            }
            catch (Exception ex)
            {
                _logger.Error("String Encryption Failed: " + ex.Message);
            }
            return string.Empty;
        }
    }
}
