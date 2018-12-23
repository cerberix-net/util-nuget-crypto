using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Cerberix.Crypto.Core;
using Cerberix.Serialization.Core;
using Moq;
using NUnit.Framework;

namespace Cerberix.Crypto.DotNet.Logic.Tests
{
    [TestFixture]
    public class AES256PlusHMACCryptDecryptProviderTests
    {
        private const string MockHmacSaltValue = "nOk(o$QIL!Y_SNHLb<i~4vL<rsa0YB1w";
        private const string MockCryptKeyValue = "3cF*h:8%|kUQDz,{8d!{^WZ5WiqS>E1g";

        private const string MockAbcClearTextValue = "abc";
        private const string MockLotionClearTextValue = "loción";
        private const string MockLoroIpsumClearTextValue = "Ut est etiam invenire maluisset, ea porro debitis indoctum vim, ad eos error invidunt constituto. Eu velit quando fabellas sea. Sea fabellas dignissim at, lorem falli mundi sea eu. Ut eum gloriatur sadipscing, ius te expetenda omittantur";

        [Test]
        public void CryptWhenGivenNullBase64ConverterExpectArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AES256PlusHMACCryptProviderFactory.NewInstance(
                base64Converter: null,
                byteConverter: new Mock<IByteConverter>(MockBehavior.Strict).Object,
                cryptKeyValue: MockCryptKeyValue,
                hmacSaltValue: MockHmacSaltValue
                ));
        }

        [Test]
        public void CryptWhenGivenNullByteConverterExpectArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AES256PlusHMACCryptProviderFactory.NewInstance(
                base64Converter: new Mock<IBase64Converter>(MockBehavior.Strict).Object,
                byteConverter: null,
                cryptKeyValue: MockCryptKeyValue,
                hmacSaltValue: MockHmacSaltValue
                ));
        }

        [Test]
        public void CryptWhenGivenNullCryptKeyValueExpectArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AES256PlusHMACCryptProviderFactory.NewInstance(
                base64Converter: new Mock<IBase64Converter>(MockBehavior.Strict).Object,
                byteConverter: new Mock<IByteConverter>(MockBehavior.Strict).Object,
                cryptKeyValue: null,
                hmacSaltValue: MockHmacSaltValue
                ));
        }

        [Test]
        public void CryptWhenGivenInvalidCryptKeyValueExpectArgumentException()
        {
            Assert.Throws<ArgumentException>(() => AES256PlusHMACCryptProviderFactory.NewInstance(
                base64Converter: new Mock<IBase64Converter>(MockBehavior.Strict).Object,
                byteConverter: new Mock<IByteConverter>(MockBehavior.Strict).Object,
                cryptKeyValue: MockAbcClearTextValue,
                hmacSaltValue: MockHmacSaltValue
                ));
        }

        [Test]
        public void CryptWhenGivenNullHmacSaltValueExpectArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AES256PlusHMACCryptProviderFactory.NewInstance(
                base64Converter: new Mock<IBase64Converter>(MockBehavior.Strict).Object,
                byteConverter: new Mock<IByteConverter>(MockBehavior.Strict).Object,
                cryptKeyValue: MockCryptKeyValue,
                hmacSaltValue: null
                ));
        }

        [Test]
        public void CryptWhenGivenInvalidHmacSaltValueExpectArgumentException()
        {
            Assert.Throws<ArgumentException>(() => AES256PlusHMACCryptProviderFactory.NewInstance(
                base64Converter: new Mock<IBase64Converter>(MockBehavior.Strict).Object,
                byteConverter: new Mock<IByteConverter>(MockBehavior.Strict).Object,
                cryptKeyValue: MockHmacSaltValue,
                hmacSaltValue: MockAbcClearTextValue
                ));
        }

        [Test]
        public void CryptWhenGivenNullClearTextExpectArgumentNullException()
        {
            ICryptProvider crypt = AES256PlusHMACCryptProviderFactory.NewInstance(
                base64Converter: new Mock<IBase64Converter>(MockBehavior.Strict).Object,
                byteConverter: new Mock<IByteConverter>(MockBehavior.Strict).Object,
                cryptKeyValue: MockCryptKeyValue,
                hmacSaltValue: MockHmacSaltValue
                );

            Assert.Throws<ArgumentNullException>(() => crypt.Crypt(clearText: null));
        }

        [Test]
        public void CryptWhenGivenEmptyClearTextExpectArgumentException()
        {
            var mockByteConverter = new Mock<IByteConverter>(MockBehavior.Strict);
            mockByteConverter.Setup(m => m.ConvertToBytes(It.IsAny<string>())).Returns((string input) =>
            {
                return UTF8Encoding.UTF8.GetBytes(input);
            }).Verifiable();

            ICryptProvider crypt = AES256PlusHMACCryptProviderFactory.NewInstance(
                base64Converter: new Mock<IBase64Converter>(MockBehavior.Strict).Object,
                byteConverter: mockByteConverter.Object,
                cryptKeyValue: MockCryptKeyValue,
                hmacSaltValue: MockHmacSaltValue
                );

            Assert.Throws<ArgumentException>(() => crypt.Crypt(clearText: string.Empty));
        }

        [Test]
        public void CryptWhenGivenAbcClearTextValueExpectResult()
        {
            var mockBase64Converter = new Mock<IBase64Converter>(MockBehavior.Strict);
            mockBase64Converter.Setup(m => m.ToBase64String(It.IsAny<IReadOnlyCollection<byte>>())).Returns((IReadOnlyCollection<byte> input) =>
            {
                return Convert.ToBase64String(input.ToArray());
            }).Verifiable();

            var mockByteConverter = new Mock<IByteConverter>(MockBehavior.Strict);
            mockByteConverter.Setup(m => m.ConvertToBytes(It.IsAny<string>())).Returns((string input) =>
            {
                return UTF8Encoding.UTF8.GetBytes(input);
            }).Verifiable();

            ICryptProvider crypt = AES256PlusHMACCryptProviderFactory.NewInstance(
                base64Converter: mockBase64Converter.Object,
                byteConverter: mockByteConverter.Object,
                cryptKeyValue: MockCryptKeyValue,
                hmacSaltValue: MockHmacSaltValue
                );

            string actual = crypt.Crypt(clearText: MockAbcClearTextValue);

            Assert.IsNotNull(actual);

            mockByteConverter.Verify();
            mockBase64Converter.Verify();
        }

        [Test]
        public void CryptWhenGivenLoroIpsumClearTextValueExpectResult()
        {
            var mockBase64Converter = new Mock<IBase64Converter>(MockBehavior.Strict);
            mockBase64Converter.Setup(m => m.ToBase64String(It.IsAny<IReadOnlyCollection<byte>>())).Returns((IReadOnlyCollection<byte> input) =>
            {
                return Convert.ToBase64String(input.ToArray());
            }).Verifiable();

            var mockByteConverter = new Mock<IByteConverter>(MockBehavior.Strict);
            mockByteConverter.Setup(m => m.ConvertToBytes(It.IsAny<string>())).Returns((string input) =>
            {
                return UTF8Encoding.UTF8.GetBytes(input);
            }).Verifiable();

            ICryptProvider crypt = AES256PlusHMACCryptProviderFactory.NewInstance(
                base64Converter: mockBase64Converter.Object,
                byteConverter: mockByteConverter.Object,
                cryptKeyValue: MockCryptKeyValue,
                hmacSaltValue: MockHmacSaltValue
                );

            string actual = crypt.Crypt(clearText: MockLoroIpsumClearTextValue);

            Assert.IsNotNull(actual);

            mockByteConverter.Verify();
            mockBase64Converter.Verify();
        }

        [Test]
        public void CryptWhenGivenLotionClearTextValueExpectResult()
        {
            var mockBase64Converter = new Mock<IBase64Converter>(MockBehavior.Strict);
            mockBase64Converter.Setup(m => m.ToBase64String(It.IsAny<IReadOnlyCollection<byte>>())).Returns((IReadOnlyCollection<byte> input) =>
            {
                return Convert.ToBase64String(input.ToArray());
            }).Verifiable();

            var mockByteConverter = new Mock<IByteConverter>(MockBehavior.Strict);
            mockByteConverter.Setup(m => m.ConvertToBytes(It.IsAny<string>())).Returns((string input) =>
            {
                return UTF8Encoding.UTF8.GetBytes(input);
            }).Verifiable();

            ICryptProvider crypt = AES256PlusHMACCryptProviderFactory.NewInstance(
                base64Converter: mockBase64Converter.Object,
                byteConverter: mockByteConverter.Object,
                cryptKeyValue: MockCryptKeyValue,
                hmacSaltValue: MockHmacSaltValue
                );

            string actual = crypt.Crypt(clearText: MockLotionClearTextValue);

            Assert.IsNotNull(actual);

            mockByteConverter.Verify();
            mockBase64Converter.Verify();
        }

        [Test]
        public void CryptDecryptWhenGivenAbcClearTextValueExpectResult()
        {
            var mockBase64Converter = new Mock<IBase64Converter>(MockBehavior.Strict);
            mockBase64Converter.Setup(m => m.ToBase64String(It.IsAny<IReadOnlyCollection<byte>>())).Returns((IReadOnlyCollection<byte> input) =>
            {
                return Convert.ToBase64String(input.ToArray());
            }).Verifiable();
            mockBase64Converter.Setup(m => m.FromBase64String(It.IsAny<string>())).Returns((string input) =>
            {
                return Convert.FromBase64String(input);
            }).Verifiable();

            var mockByteConverter = new Mock<IByteConverter>(MockBehavior.Strict);
            mockByteConverter.Setup(m => m.ConvertToBytes(It.IsAny<string>())).Returns((string input) =>
            {
                return UTF8Encoding.UTF8.GetBytes(input);
            }).Verifiable();
            mockByteConverter.Setup(m => m.ConvertToString(It.IsAny<IReadOnlyCollection<byte>>())).Returns((IReadOnlyCollection<byte> input) =>
            {
                return UTF8Encoding.UTF8.GetString(input.ToArray());
            }).Verifiable();

            ICryptProvider crypt = AES256PlusHMACCryptProviderFactory.NewInstance(
                base64Converter: mockBase64Converter.Object,
                byteConverter: mockByteConverter.Object,
                cryptKeyValue: MockCryptKeyValue,
                hmacSaltValue: MockHmacSaltValue
                );

            string cipherText = crypt.Crypt(clearText: MockAbcClearTextValue);

            ICryptDecryptProvider decrypt = AES256PlusHMACCryptDecryptProviderFactory.NewInstance(
                base64Converter: mockBase64Converter.Object,
                byteConverter: mockByteConverter.Object,
                cryptKeyValue: MockCryptKeyValue,
                hmacSaltValue: MockHmacSaltValue
                );

            string actual = decrypt.Decrypt(cipherText: cipherText);

            Assert.IsNotNull(actual);
            Assert.AreEqual(MockAbcClearTextValue, actual);

            mockByteConverter.Verify();
            mockBase64Converter.Verify();
        }

        [Test]
        public void CryptDecryptWhenGivenLoroIpsumClearTextValueExpectResult()
        {
            var mockBase64Converter = new Mock<IBase64Converter>(MockBehavior.Strict);
            mockBase64Converter.Setup(m => m.ToBase64String(It.IsAny<IReadOnlyCollection<byte>>())).Returns((IReadOnlyCollection<byte> input) =>
            {
                return Convert.ToBase64String(input.ToArray());
            }).Verifiable();
            mockBase64Converter.Setup(m => m.FromBase64String(It.IsAny<string>())).Returns((string input) =>
            {
                return Convert.FromBase64String(input);
            }).Verifiable();

            var mockByteConverter = new Mock<IByteConverter>(MockBehavior.Strict);
            mockByteConverter.Setup(m => m.ConvertToBytes(It.IsAny<string>())).Returns((string input) =>
            {
                return UTF8Encoding.UTF8.GetBytes(input);
            }).Verifiable();
            mockByteConverter.Setup(m => m.ConvertToString(It.IsAny<IReadOnlyCollection<byte>>())).Returns((IReadOnlyCollection<byte> input) =>
            {
                return UTF8Encoding.UTF8.GetString(input.ToArray());
            }).Verifiable();

            ICryptProvider crypt = AES256PlusHMACCryptProviderFactory.NewInstance(
                base64Converter: mockBase64Converter.Object,
                byteConverter: mockByteConverter.Object,
                cryptKeyValue: MockCryptKeyValue,
                hmacSaltValue: MockHmacSaltValue
                );

            string cipherText = crypt.Crypt(clearText: MockLoroIpsumClearTextValue);

            ICryptDecryptProvider decrypt = AES256PlusHMACCryptDecryptProviderFactory.NewInstance(
                base64Converter: mockBase64Converter.Object,
                byteConverter: mockByteConverter.Object,
                cryptKeyValue: MockCryptKeyValue,
                hmacSaltValue: MockHmacSaltValue
                );

            string actual = decrypt.Decrypt(cipherText: cipherText);

            Assert.IsNotNull(actual);
            Assert.AreEqual(MockLoroIpsumClearTextValue, actual);

            mockByteConverter.Verify();
            mockBase64Converter.Verify();
        }

        [Test]
        public void CryptDecryptWhenGivenLotionClearTextValueExpectResult()
        {
            var mockBase64Converter = new Mock<IBase64Converter>(MockBehavior.Strict);
            mockBase64Converter.Setup(m => m.ToBase64String(It.IsAny<IReadOnlyCollection<byte>>())).Returns((IReadOnlyCollection<byte> input) =>
            {
                return Convert.ToBase64String(input.ToArray());
            }).Verifiable();
            mockBase64Converter.Setup(m => m.FromBase64String(It.IsAny<string>())).Returns((string input) =>
            {
                return Convert.FromBase64String(input);
            }).Verifiable();

            var mockByteConverter = new Mock<IByteConverter>(MockBehavior.Strict);
            mockByteConverter.Setup(m => m.ConvertToBytes(It.IsAny<string>())).Returns((string input) =>
            {
                return UTF8Encoding.UTF8.GetBytes(input);
            }).Verifiable();
            mockByteConverter.Setup(m => m.ConvertToString(It.IsAny<IReadOnlyCollection<byte>>())).Returns((IReadOnlyCollection<byte> input) =>
            {
                return UTF8Encoding.UTF8.GetString(input.ToArray());
            }).Verifiable();

            ICryptProvider crypt = AES256PlusHMACCryptProviderFactory.NewInstance(
                base64Converter: mockBase64Converter.Object,
                byteConverter: mockByteConverter.Object,
                cryptKeyValue: MockCryptKeyValue,
                hmacSaltValue: MockHmacSaltValue
                );

            string cipherText = crypt.Crypt(clearText: MockLotionClearTextValue);

            ICryptDecryptProvider decrypt = AES256PlusHMACCryptDecryptProviderFactory.NewInstance(
                base64Converter: mockBase64Converter.Object,
                byteConverter: mockByteConverter.Object,
                cryptKeyValue: MockCryptKeyValue,
                hmacSaltValue: MockHmacSaltValue
                );

            string actual = decrypt.Decrypt(cipherText: cipherText);

            Assert.IsNotNull(actual);
            Assert.AreEqual(MockLotionClearTextValue, actual);

            mockByteConverter.Verify();
            mockBase64Converter.Verify();
        }

        [Test]
        public void DecryptWhenGivenAbcClearTextValueExpectResult()
        {
            var mockBase64Converter = new Mock<IBase64Converter>(MockBehavior.Strict);
            mockBase64Converter.Setup(m => m.FromBase64String(It.IsAny<string>())).Returns((string input) =>
            {
                return Convert.FromBase64String(input);
            }).Verifiable();

            var mockByteConverter = new Mock<IByteConverter>(MockBehavior.Strict);
            mockByteConverter.Setup(m => m.ConvertToBytes(It.IsAny<string>())).Returns((string input) =>
            {
                return UTF8Encoding.UTF8.GetBytes(input);
            }).Verifiable();
            mockByteConverter.Setup(m => m.ConvertToString(It.IsAny<IReadOnlyCollection<byte>>())).Returns((IReadOnlyCollection<byte> input) =>
            {
                return UTF8Encoding.UTF8.GetString(input.ToArray());
            }).Verifiable();

            ICryptDecryptProvider decrypt = AES256PlusHMACCryptDecryptProviderFactory.NewInstance(
                base64Converter: mockBase64Converter.Object,
                byteConverter: mockByteConverter.Object,
                cryptKeyValue: MockCryptKeyValue,
                hmacSaltValue: MockHmacSaltValue
                );

            string actual = decrypt.Decrypt(cipherText: "TTTuaZk5ehdGu34qzAmJoAQkjDQw2HfYE1bTlx7M4eOuMT6f0YpNbhG0o6sLWz04iLX+OwWMhGi/GFJBi7PdXw==");

            Assert.IsNotNull(actual);
            Assert.AreEqual(MockAbcClearTextValue, actual);

            mockByteConverter.Verify();
            mockBase64Converter.Verify();
        }

        [Test]
        public void DecryptWhenGivenLoroIpsumClearTextValueExpectResult()
        {
            var mockBase64Converter = new Mock<IBase64Converter>(MockBehavior.Strict);
            mockBase64Converter.Setup(m => m.FromBase64String(It.IsAny<string>())).Returns((string input) =>
            {
                return Convert.FromBase64String(input);
            }).Verifiable();

            var mockByteConverter = new Mock<IByteConverter>(MockBehavior.Strict);
            mockByteConverter.Setup(m => m.ConvertToBytes(It.IsAny<string>())).Returns((string input) =>
            {
                return UTF8Encoding.UTF8.GetBytes(input);
            }).Verifiable();
            mockByteConverter.Setup(m => m.ConvertToString(It.IsAny<IReadOnlyCollection<byte>>())).Returns((IReadOnlyCollection<byte> input) =>
            {
                return UTF8Encoding.UTF8.GetString(input.ToArray());
            }).Verifiable();

            ICryptDecryptProvider decrypt = AES256PlusHMACCryptDecryptProviderFactory.NewInstance(
                base64Converter: mockBase64Converter.Object,
                byteConverter: mockByteConverter.Object,
                cryptKeyValue: MockCryptKeyValue,
                hmacSaltValue: MockHmacSaltValue
                );

            string actual = decrypt.Decrypt(cipherText: "6sPrdQTiPsOTiSfVeHrC+A6i3HFqLzzfa/sUKHYSiNyoCbomQKVbu9eUucmI0Y63mW1E1A3aX/q2etkd37ssB7fbZ7ZzR/Upcg7qUIH0C0N/UufUQfTbbrpOXdAy9oFXJBxusXypoFZZxQ1lJW3b58vUbiWhNr09P/GWnkJBNbhLhGD+XUmvgBWxU7E12dsCEXw8A3CdfOnqwIcik8VUqjHqZtjhxryoIxFKJ7vtuwahqka1sXPQQ6+MaXPTIrcZwAex1gr47gH92SdwrSCtJv5vZwXtej0jQEOHPJKUnP34YPa55f+seT6lJBxtjmvyeRpNlts5dxqXRRrTeD+vGQRtnh3xqICHpJJJaHY8U6/ohumhvmCs6sRfqJApUewO");

            Assert.IsNotNull(actual);
            Assert.AreEqual(MockLoroIpsumClearTextValue, actual);

            mockByteConverter.Verify();
            mockBase64Converter.Verify();
        }

        [Test]
        public void DecryptWhenGivenLotionClearTextValueExpectResult()
        {
            var mockBase64Converter = new Mock<IBase64Converter>(MockBehavior.Strict);
            mockBase64Converter.Setup(m => m.FromBase64String(It.IsAny<string>())).Returns((string input) =>
            {
                return Convert.FromBase64String(input);
            }).Verifiable();

            var mockByteConverter = new Mock<IByteConverter>(MockBehavior.Strict);
            mockByteConverter.Setup(m => m.ConvertToBytes(It.IsAny<string>())).Returns((string input) =>
            {
                return UTF8Encoding.UTF8.GetBytes(input);
            }).Verifiable();
            mockByteConverter.Setup(m => m.ConvertToString(It.IsAny<IReadOnlyCollection<byte>>())).Returns((IReadOnlyCollection<byte> input) =>
            {
                return UTF8Encoding.UTF8.GetString(input.ToArray());
            }).Verifiable();

            ICryptDecryptProvider decrypt = AES256PlusHMACCryptDecryptProviderFactory.NewInstance(
                base64Converter: mockBase64Converter.Object,
                byteConverter: mockByteConverter.Object,
                cryptKeyValue: MockCryptKeyValue,
                hmacSaltValue: MockHmacSaltValue
                );

            string actual = decrypt.Decrypt(cipherText: "5lA6sJloOSSLp1nlSERxucKHC0k2cagNe7FPk+YBBJhnyd0g1yFebxqZzPWsNI4v+PD0CaViHnUTROyWjgdGNA==");

            Assert.IsNotNull(actual);
            Assert.AreEqual(MockLotionClearTextValue, actual);

            mockByteConverter.Verify();
            mockBase64Converter.Verify();
        }
    }
}