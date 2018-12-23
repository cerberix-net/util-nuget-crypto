using Cerberix.Crypto.Core;

namespace Cerberix.Crypto.DotNet
{
    public static class EchoCryptProviderFactory
    {
        public static ICryptProvider NewInstance()
        {
            return new Logic.EchoCryptDecryptProvider();
        }
    }
}
