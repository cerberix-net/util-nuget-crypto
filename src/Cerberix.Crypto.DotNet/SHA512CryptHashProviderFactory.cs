using System.Security.Cryptography;
using Cerberix.Crypto.Core;
using Cerberix.Serialization.Core;

namespace Cerberix.Crypto.DotNet
{
    public static class SHA512CryptHashProviderFactory
    {
        public static ICryptHashProvider NewInstance(IByteConverter byteConverter)
        {
            return NewInstance(
                byteConverter: byteConverter,
                hasher: SHA512.Create()
                );
        }

        public static ICryptHashProvider NewInstance(IByteConverter byteConverter, SHA512 hasher)
        {
            return new Logic.SHA512CryptHashProvider(
                byteConverter: byteConverter,
                hasher: hasher
                );
        }
    }
}
