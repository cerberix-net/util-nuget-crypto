using BC = BCrypt.Net.BCrypt;
using System;
using Cerberix.Crypto.Core;

namespace Cerberix.Crypto.BCryptNet.Logic
{
    internal class BCryptNetHashVerifyProvider : ICryptHashVerifyProvider
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
