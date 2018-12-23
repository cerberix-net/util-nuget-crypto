using System;
using System.Security.Cryptography;
using Cerberix.Crypto.Core;
using Cerberix.Extension.Core;
using Cerberix.Serialization.Core;

namespace Cerberix.Crypto.DotNet.Logic
{
    internal class MD5CryptHashProvider : ICryptHashProvider
	{
		private readonly IByteConverter ByteConverter;
        private readonly MD5 Hasher;

        public MD5CryptHashProvider(
            IByteConverter byteConverter,
            MD5 hasher
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

        private static string HashCore(IByteConverter byteConverter, MD5 hasher, string value)
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
