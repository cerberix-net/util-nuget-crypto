using System;
using Cerberix.Serialization;
using Moq;
using NUnit.Framework;

namespace Cerberix.Crypto.DotNet.Tests
{
    [TestFixture]
    public class MD5CryptHashProviderTests
    {
        [Test]
        public void HashWhenGivenNullExpectArgumentNullException()
        {
            //  arrange
            var mockByteConverter = new Mock<IByteConverter>(MockBehavior.Strict);

            ICryptHashProvider hash = Factory.MD5Pump.NewInstance(
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

            ICryptHashProvider hash = Factory.MD5Pump.NewInstance(
                byteConverter: mockByteConverter.Object
                );

            //  act
            string actual = hash.Hash(string.Empty);

            //  assert
            Assert.IsNotNull(actual);
            Assert.AreEqual("d41d8cd98f00b204e9800998ecf8427e", actual);

            //  verify
            mockByteConverter.Verify();
        }

        [Test]
        public void HashWhenGivenSomeValueExpectHashValue()
        {
            //  arrange
            var mockByteConverter = new Mock<IByteConverter>(MockBehavior.Strict);
            mockByteConverter.Setup(m => m.ConvertToBytes("abc")).Returns(new byte[] { 97, 98, 99 }).Verifiable();

            ICryptHashProvider hash = Factory.MD5Pump.NewInstance(
                byteConverter: mockByteConverter.Object
                );

            //  act
            string actual = hash.Hash("abc");

            //  assert
            Assert.IsNotNull(actual);
            Assert.AreEqual("900150983cd24fb0d6963f7d28e17f72", actual);

            //  verify
            mockByteConverter.Verify();
        }
    }
}