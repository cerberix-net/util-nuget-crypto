using Cerberix.Crypto.Core;

namespace Cerberix.Crypto.BCryptNet
{
    public static class BCryptNetHashProviderFactory
    {
        public static ICryptHashProvider NewInstance(int workFactor)
        {
            return new Logic.BCryptNetHashProvider(workFactor: workFactor);
        }
    }
}
