using Microsoft.Extensions.Configuration;
using ConfigurationEncryptionProvider;
using ConfigurationEncryptionProvider.Models;
using log4net;
using ConfigurationEncryptionProvider.CryptoProviders.Implementations;
using ConfigurationEncryptionProvider.CryptoProviders.Interfaces;
using Microsoft.Extensions.Options;

namespace EncyptionDecryption.Algorithms
{
    public class SRMSEncryption : IEncryptDecrypt<string>
    {
        private readonly ILog _logger;

        public SRMSEncryption(ILog logger)
        {
            _logger = logger;
        }

        public string Encrypt(string plaintext, string parameters)
        {
            return EncryptString(plaintext, parameters);
        }

        public string Decrypt(string ciphertext, string parameters)
        {
            return DecryptString(ciphertext, parameters);
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

        public void EncryptSRMSFile(string file)
        {
            _logger.Debug($"EncryptSRMSFile called with file: {file}");
            try
            {
                _logger.Debug("Building configuration from JSON file.");
                IConfiguration configuration = new ConfigurationBuilder().AddJsonFile(file).Build();
                _logger.Debug("Configuration built successfully.");

                _logger.Debug("Fetching inputs for encryption settings and provider section.");
                this.FetchInputs(configuration, out EncryptionSettings encryptionSettings, out ConfigEncryptionProviderSection configEncryptionProviderSection);
                _logger.Debug("Inputs fetched successfully.");
                _logger.Debug($"EncryptionSettings: Algorithm={encryptionSettings.Algorithm}, Key={encryptionSettings.Key}, IV={encryptionSettings.IV}");

                _logger.Debug("Creating necessary options and providers for encryption.");
                IOptions<EncryptionSettings> options = Options.Create(encryptionSettings);
                ICryptoProviderFactory cryptoProviderFactory = new CryptoProviderFactory(options);
                IConfigEncryptionProvider configEncryptionProvider = new ConfigEncryptionProvider(configuration, cryptoProviderFactory);

                _logger.Debug("Updating configuration with encrypted data.");
                configEncryptionProvider.Update(configEncryptionProviderSection, file);
                _logger.Info("SRMS file encryption successful.");

                _logger.Debug("Reading encrypted file content.");
                string updatedFileContent = File.ReadAllText(file);
                _logger.Debug($"Updated file content: {updatedFileContent}");
            }
            catch (Exception ex)
            {
                _logger.Error("SRMS encryption failed: " + ex.Message, ex);
            }
        }


        private string EncryptString(string stringToBeEncrypted, string filePath)
        {
            _logger.Debug($"EncryptString called with stringToBeEncrypted: {stringToBeEncrypted}, filePath: {filePath}");
            try
            {
                if (string.IsNullOrEmpty(stringToBeEncrypted))
                {
                    _logger.Warn("String to be encrypted is empty.");
                    return "";
                }

                _logger.Debug("Building configuration from JSON file.");
                IConfiguration configuration = new ConfigurationBuilder().AddJsonFile(filePath).Build();
                _logger.Debug("Configuration built successfully.");

                _logger.Debug("Fetching configuration section 'srmconfig'.");
                IConfigurationSection configurationSection = configuration.GetSection("srmconfig");

                _logger.Debug("Creating EncryptionSettings.");
                EncryptionSettings encryptionSettings = new EncryptionSettings
                {
                    Algorithm = "AES",
                    Key = configurationSection["suffix"],
                    IV = configurationSection["preffix"]
                };
                _logger.Debug($"EncryptionSettings created: Algorithm={encryptionSettings.Algorithm}, Key={encryptionSettings.Key}, IV={encryptionSettings.IV}");


                IOptions<EncryptionSettings> options = Options.Create(encryptionSettings);             
                ICryptoProviderFactory cryptoProviderFactory = new CryptoProviderFactory(options);              
                IConfigEncryptionProvider configEncryptionProvider = new ConfigEncryptionProvider(configuration, cryptoProviderFactory);

                _logger.Debug("Encrypting string.");
                string encryptedString = configEncryptionProvider.Encrypt(stringToBeEncrypted);
                _logger.Info("String encryption successful.");
                return encryptedString;
            }
            catch (Exception ex)
            {
                _logger.Error("String encryption failed: " + ex.Message, ex);
            }

            return string.Empty;
        }

        private string DecryptString(string stringToBeDecrypted, string filePath)
        {
            _logger.Debug($"DecryptString called with stringToBeDecrypted: {stringToBeDecrypted}, filePath: {filePath}");
            try
            {
                if (string.IsNullOrEmpty(stringToBeDecrypted))
                {
                    _logger.Warn("String to be decrypted is empty.");
                    return "";
                }

                _logger.Debug("Building configuration from JSON file.");
                IConfiguration configuration = new ConfigurationBuilder().AddJsonFile(filePath).Build();
                _logger.Debug("Configuration built successfully.");

                _logger.Debug("Fetching configuration section 'srmconfig'.");
                IConfigurationSection configurationSection = configuration.GetSection("srmconfig");

                _logger.Debug("Creating EncryptionSettings.");
                EncryptionSettings encryptionSettings = new EncryptionSettings
                {
                    Algorithm = "AES",
                    Key = configurationSection["suffix"],
                    IV = configurationSection["preffix"]
                };
                _logger.Debug($"EncryptionSettings created: Algorithm={encryptionSettings.Algorithm}, Key={encryptionSettings.Key}, IV={encryptionSettings.IV}");


                IOptions<EncryptionSettings> options = Options.Create(encryptionSettings);
                ICryptoProviderFactory cryptoProviderFactory = new CryptoProviderFactory(options);
                IConfigEncryptionProvider configEncryptionProvider = new ConfigEncryptionProvider(configuration, cryptoProviderFactory);
                var aesCryptoProvider = new AESCryptoProvider(encryptionSettings);

                _logger.Debug("Decrypting string.");
                string decryptedString = aesCryptoProvider.Decrypt(stringToBeDecrypted);
                _logger.Info("String decryption successful.");
                return decryptedString;
            }
            catch (Exception ex)
            {
                _logger.Error("String decryption failed: " + ex.Message, ex);
            }

            return string.Empty;
        }


        public bool Verify(string plaintext, string hash, string parameters)
        {
            throw new NotImplementedException();
        }
    }
}
