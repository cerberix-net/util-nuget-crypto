using System;
using BC = BCrypt.Net.BCrypt;

namespace Cerberix.Crypto.BCryptNet
{
    public static class Factory
    {
        public static class CryptHashPump
        {
            public static ICryptHashProvider NewInstance(int workFactor)
            {
                return new BCryptNetHashProvider(workFactor: workFactor);
            }

            /// <summary>
            ///		Implements Bcrypt provider (ICryptHashProvider)
            /// </summary>
            private class BCryptNetHashProvider : ICryptHashProvider
            {
                private readonly int WorkFactor;

                public BCryptNetHashProvider(int workFactor)
                {
                    WorkFactor = workFactor;
                }

                public string Hash(string clearText)
                {
                    if (clearText == null)
                    {
                        throw new ArgumentNullException("clearText");
                    }

                    var result = BC.HashPassword(clearText, WorkFactor);
                    return result;
                }
            }
        }

        public static class CryptHashVerifyPump
        {
            public static ICryptHashVerifyProvider NewInstance()
            {
                return new BCryptNetHashVerifyProvider();
            }

            private class BCryptNetHashVerifyProvider : ICryptHashVerifyProvider
            {
                public bool Verify(string clearText, string hashText)
                {
                    if (clearText == null)
                    {
                        throw new ArgumentNullException("clearText");
                    }
                    if (hashText == null)
                    {
                        throw new ArgumentNullException("hashText");
                    }

                    bool result = BC.Verify(clearText, hashText);
                    return result;
                }
            }
        }
    }
}