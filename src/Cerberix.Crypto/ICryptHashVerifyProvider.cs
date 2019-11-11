namespace Cerberix.Crypto
{
    public interface ICryptHashVerifyProvider
    {
        /// <summary>
        ///     Given clearText, produce a True/False verification.
        /// </summary>
        /// <param name="clearText">The clearText message</param>
        /// <param name="hashText">The hashText to verify</param>
        /// <returns>True when the verification succeeds, false otherwise.</returns>
        bool Verify(string clearText, string hashText);
    }
}
