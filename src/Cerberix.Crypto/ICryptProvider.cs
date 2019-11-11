namespace Cerberix.Crypto
{
    public interface ICryptProvider
    {
        /// <summary>
        ///     Crypt clearText string -> cipherText.
        /// </summary>
        /// <param name="clearText">The clear text.</param>
        /// <returns>The cipher text result.</returns>
        string Crypt(string clearText);
    }
}
