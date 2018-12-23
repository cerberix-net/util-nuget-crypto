using Cerberix.Crypto.Core;

namespace Cerberix.Crypto.DotNet
{
    public static class SystemRngProviderFactory
    {
        public static IPsuedoRandomNumberGenerator NewInstance()
        {
            return new Logic.SystemRngProvider();
        }
    }
}
