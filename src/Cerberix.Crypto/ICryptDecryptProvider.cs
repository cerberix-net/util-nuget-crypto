namespace Cerberix.Crypto
{
	public interface ICryptDecryptProvider
    {
        /// <summary>
        ///     Decrypt cipherText string -> clearText.
        /// </summary>
        /// <param name="cipherText">The cipher text.</param>
        /// <returns>The clear text result.</returns>
		string Decrypt(string cipherText);
	}
}
