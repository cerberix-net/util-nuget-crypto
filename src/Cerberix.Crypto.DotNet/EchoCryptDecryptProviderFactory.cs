using Cerberix.Crypto.Core;

namespace Cerberix.Crypto.DotNet
{
    public static class EchoCryptDecryptProviderFactory
    {
        public static ICryptDecryptProvider GetInstance()
        {
            return new Logic.EchoCryptDecryptProvider();
        }
    }
}
