using System;
using Cerberix.Crypto.Core;

namespace Cerberix.Crypto.DotNet.Logic
{
    /// <summary>
    ///		Implements cleartext cipher (ICryptProvider, ICryptDecryptProvider)
    /// </summary>
    internal class EchoCryptDecryptProvider : ICryptProvider, ICryptDecryptProvider
	{
		public string Crypt(string clearText)
		{
            if (clearText == null)
            {
                throw new ArgumentNullException("clearText");
            }

			return clearText;
		}

		public string Decrypt(string cipherText)
		{
            if (cipherText == null)
            {
                throw new ArgumentNullException("cipherText");
            }

            return cipherText;
		}
	}
}
