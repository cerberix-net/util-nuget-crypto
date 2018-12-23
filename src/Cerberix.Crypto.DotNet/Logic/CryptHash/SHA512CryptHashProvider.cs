using System;
using System.Security.Cryptography;
using Cerberix.Crypto.Core;
using Cerberix.Extension.Core;
using Cerberix.Serialization.Core;

namespace Cerberix.Crypto.DotNet.Logic
{
    internal class SHA512CryptHashProvider : ICryptHashProvider
    {
        private readonly IByteConverter ByteConverter;
        private readonly SHA512 Hasher;

        public SHA512CryptHashProvider(
            IByteConverter byteConverter,
            SHA512 hasher
            )
        {
            ByteConverter = byteConverter;
            Hasher = hasher;
        }

        public string Hash(string clearText)
        {
            if (clearText == null)
            {
                throw new ArgumentNullException("clearText");
            }

            var result = HashCore(ByteConverter, Hasher, clearText);
            return result;
        }

        private static string HashCore(IByteConverter byteConverter, SHA512 hasher, string value)
        {
            // setup encoding, hash, and read byte array
            var clearBytes = byteConverter.ConvertToBytes(value).EnsureArray();

            // perform hashing operation
            var hashBytes = hasher.ComputeHash(clearBytes);

            // convert back to string
            var result = hashBytes.ToHex();
            return result;
        }
    }
}
