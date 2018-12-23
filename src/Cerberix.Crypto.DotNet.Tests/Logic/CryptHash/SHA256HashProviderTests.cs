using System;
using Cerberix.Crypto.Core;
using Cerberix.Serialization.Core;
using Moq;
using NUnit.Framework;

namespace Cerberix.Crypto.DotNet.Logic.Tests
{
    [TestFixture]
    public class SHA256HashProviderTests
    {
        [Test]
        public void HashWhenGivenNullExpectArgumentNullException()
        {
            //  arrange
            var mockByteConverter = new Mock<IByteConverter>(MockBehavior.Strict);

            ICryptHashProvider hash = SHA256CryptHashProviderFactory.NewInstance(
                byteConverter: mockByteConverter.Object
                );

            //  act
            Assert.Throws<ArgumentNullException>(() => hash.Hash(null));

            //  verify
            mockByteConverter.Verify();
        }

        [Test]
        public void HashWhenGivenEmptyValueExpectHashValue()
        {
            //  arrange
            var mockByteConverter = new Mock<IByteConverter>(MockBehavior.Strict);
            mockByteConverter.Setup(m => m.ConvertToBytes(string.Empty)).Returns(new byte[0]).Verifiable();

            ICryptHashProvider hash = SHA256CryptHashProviderFactory.NewInstance(
                byteConverter: mockByteConverter.Object
                );

            //  act
            string actual = hash.Hash(string.Empty);

            //  assert
            Assert.IsNotNull(actual);
            Assert.AreEqual("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", actual);

            //  verify
            mockByteConverter.Verify();
        }

        [Test]
        public void HashWhenGivenSomeValueExpectHashValue()
        {
            //  arrange
            var mockByteConverter = new Mock<IByteConverter>(MockBehavior.Strict);
            mockByteConverter.Setup(m => m.ConvertToBytes("abc")).Returns(new byte[] { 97, 98, 99 }).Verifiable();

            ICryptHashProvider hash = SHA256CryptHashProviderFactory.NewInstance(
                byteConverter: mockByteConverter.Object
                );

            //  act
            string actual = hash.Hash("abc");

            //  assert
            Assert.IsNotNull(actual);
            Assert.AreEqual("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", actual);

            //  verify
            mockByteConverter.Verify();
        }
    }
}
