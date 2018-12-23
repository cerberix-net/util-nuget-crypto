using System.Security.Cryptography;
using Cerberix.Crypto.Core;
using Cerberix.Serialization.Core;

namespace Cerberix.Crypto.DotNet
{
    public static class MD5CryptHashProviderFactory
    {
        public static ICryptHashProvider NewInstance(IByteConverter byteConverter)
        {
            return NewInstance(
                byteConverter: byteConverter,
                hasher: MD5.Create()
                );
        }

        public static ICryptHashProvider NewInstance(IByteConverter byteConverter, MD5 hasher)
        {
            return new Logic.MD5CryptHashProvider(
                byteConverter: byteConverter,
                hasher: hasher
                );
        }
    }
}
