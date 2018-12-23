using System;
using Cerberix.Crypto.Core;
using NUnit.Framework;

namespace Cerberix.Crypto.DotNet.Logic.Tests
{
    [TestFixture]
    public class EchoCryptDecryptProviderTests
    {
        [Test]
        public void CryptWhenGivenNullExpectArgumentNullException()
        {
            //  arrange
            ICryptProvider crypt = EchoCryptProviderFactory.NewInstance();

            //  act
            Assert.Throws<ArgumentNullException>(() => crypt.Crypt(null));
        }

        [Test]
        public void CryptWhenGivenEmptyValueExpectEmptyValue()
        {
            //  arrange
            ICryptProvider crypt = EchoCryptProviderFactory.NewInstance();

            //  act
            string actual = crypt.Crypt(string.Empty);

            //  assert
            Assert.IsNotNull(actual);
            Assert.AreEqual(string.Empty, actual);
        }

        [Test]
        public void CryptWhenGivenSomeValueExpectSomeValue()
        {
            //  arrange
            ICryptProvider crypt = EchoCryptProviderFactory.NewInstance();

            //  act
            string actual = crypt.Crypt("echo");

            //  assert
            Assert.IsNotNull(actual);
            Assert.AreEqual("echo", actual);
        }

        [Test]
        public void DecryptWhenGivenNullExpectArgumentNullException()
        {
            //  arrange
            ICryptDecryptProvider crypt = EchoCryptDecryptProviderFactory.GetInstance();

            //  act
            Assert.Throws<ArgumentNullException>(() => crypt.Decrypt(null));
        }

        [Test]
        public void DecryptWhenGivenEmptyValueExpectEmptyValue()
        {
            //  arrange
            ICryptDecryptProvider crypt = EchoCryptDecryptProviderFactory.GetInstance();

            //  act
            string actual = crypt.Decrypt(string.Empty);

            //  assert
            Assert.IsNotNull(actual);
            Assert.AreEqual(string.Empty, actual);
        }

        [Test]
        public void DecryptWhenGivenSomeValueExpectSomeValue()
        {
            //  arrange
            ICryptDecryptProvider crypt = EchoCryptDecryptProviderFactory.GetInstance();

            //  act
            string actual = crypt.Decrypt("echo");

            //  assert
            Assert.IsNotNull(actual);
            Assert.AreEqual("echo", actual);
        }
    }
}