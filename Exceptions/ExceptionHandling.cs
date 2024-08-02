using System;

namespace EncyptionDecryption.Exceptions
{
    public class EncryptionException : Exception
    {
        public EncryptionException() { }

        public EncryptionException(string message) : base(message) { }

        public EncryptionException(string message, Exception inner) : base(message, inner) { }
    }

    public class DecryptionException : Exception
    {
        public DecryptionException() { }

        public DecryptionException(string message) : base(message) { }

        public DecryptionException(string message, Exception inner) : base(message, inner) { }
    }
}
