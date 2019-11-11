namespace Cerberix.Crypto
{
    public interface ICryptHashProvider
	{
        /// <summary>
        ///     Given clearText, produce a hashText result.
        /// </summary>
        /// <param name="clearText">The clearText message</param>
        /// <returns>The hashText result</returns>
		string Hash(string clearText);
	}
}
