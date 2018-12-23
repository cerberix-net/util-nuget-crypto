using Cerberix.Crypto.Core;

namespace Cerberix.Crypto.BCryptNet
{
    public static class BCryptNetHashVerifyProviderFactory
    {
        public static ICryptHashVerifyProvider NewInstance()
        {
            return new Logic.BCryptNetHashVerifyProvider();
        }
    }
}
