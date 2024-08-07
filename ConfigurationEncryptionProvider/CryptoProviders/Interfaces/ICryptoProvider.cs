namespace ConfigurationEncryptionProvider.CryptoProviders.Interfaces
{
    public interface ICryptoProvider
    {
        string Decrypt(string secret);

        string Encrypt(string secret);
    }


}
