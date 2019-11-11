using System;
using Cerberix.Serialization;
using Moq;
using NUnit.Framework;

namespace Cerberix.Crypto.DotNet.Tests
{
    [TestFixture]
    public class SHA512HashProviderTests
    {
        [Test]
        public void HashWhenGivenNullExpectArgumentNullException()
        {
            //  arrange
            var mockByteConverter = new Mock<IByteConverter>(MockBehavior.Strict);

            ICryptHashProvider hash = Factory.SHA512Pump.NewInstance(
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

            ICryptHashProvider hash = Factory.SHA512Pump.NewInstance(
                byteConverter: mockByteConverter.Object
                );

            //  act
            string actual = hash.Hash(string.Empty);

            //  assert
            Assert.IsNotNull(actual);
            Assert.AreEqual("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", actual);

            //  verify
            mockByteConverter.Verify();
        }

        [Test]
        public void HashWhenGivenSomeValueExpectHashValue()
        {
            //  arrange
            var mockByteConverter = new Mock<IByteConverter>(MockBehavior.Strict);
            mockByteConverter.Setup(m => m.ConvertToBytes("abc")).Returns(new byte[] { 97, 98, 99 }).Verifiable();

            ICryptHashProvider hash = Factory.SHA512Pump.NewInstance(
                byteConverter: mockByteConverter.Object
                );

            //  act
            string actual = hash.Hash("abc");

            //  assert
            Assert.IsNotNull(actual);
            Assert.AreEqual("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", actual);

            //  verify
            mockByteConverter.Verify();
        }
    }
}
