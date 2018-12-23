using System.Security.Cryptography;
using Cerberix.Crypto.Core;
using Cerberix.Serialization.Core;

namespace Cerberix.Crypto.DotNet
{
    public static class SHA256CryptHashProviderFactory
    {
        public static ICryptHashProvider NewInstance(IByteConverter byteConverter)
        {
            return NewInstance(
                byteConverter: byteConverter,
                hasher: SHA256.Create()
                );
        }

        public static ICryptHashProvider NewInstance(IByteConverter byteConverter, SHA256 hasher)
        {
            return new Logic.SHA256CryptHashProvider(
                byteConverter: byteConverter,
                hasher: hasher
                );
        }
    }
}
