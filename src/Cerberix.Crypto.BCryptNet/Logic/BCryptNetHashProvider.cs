using BC = BCrypt.Net.BCrypt;
using Cerberix.Crypto.Core;
using System;

namespace Cerberix.Crypto.BCryptNet.Logic
{
    /// <summary>
    ///		Implements Bcrypt provider (ICryptHashProvider)
    /// </summary>
    internal class BCryptNetHashProvider : ICryptHashProvider
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
