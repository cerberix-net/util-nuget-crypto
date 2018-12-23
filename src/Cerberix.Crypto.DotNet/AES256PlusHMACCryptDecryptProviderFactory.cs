using Cerberix.Crypto.Core;
using Cerberix.Serialization.Core;

namespace Cerberix.Crypto.DotNet
{
    public static class AES256PlusHMACCryptDecryptProviderFactory
    {
        public static ICryptDecryptProvider NewInstance(
            IBase64Converter base64Converter,
            IByteConverter byteConverter,
            string cryptKeyValue,
            string hmacSaltValue
            )
        {
            return new Logic.AES256PlusHMACCryptDecryptProvider(
                base64Converter: base64Converter,
                byteConverter: byteConverter,
                cryptKeyValue: cryptKeyValue,
                hmacSaltValue: hmacSaltValue
                );
        }
    }
}
