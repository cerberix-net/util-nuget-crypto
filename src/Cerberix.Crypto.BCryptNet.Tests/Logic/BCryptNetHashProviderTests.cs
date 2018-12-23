using System;
using Cerberix.Crypto.Core;
using NUnit.Framework;

namespace Cerberix.Crypto.BCryptNet.Logic.Tests
{
    [TestFixture]
    public class BCryptNetHashProviderTests
    {
        private const int MockWorkFactor = 10;

        [Test]
        public void BCryptHashWhenGivenNullExpectArgumentNullException()
        {
            ICryptHashProvider hasher = BCryptNetHashProviderFactory.NewInstance(workFactor: MockWorkFactor);
            Assert.Throws<ArgumentNullException>(() => hasher.Hash(clearText: null));
        }

        [Test]
        public void BCryptHashWhenGivenEmptyStringExpectResult()
        {
            ICryptHashProvider hasher = BCryptNetHashProviderFactory.NewInstance(workFactor: MockWorkFactor);
            string actual = hasher.Hash(clearText: string.Empty);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual.Length > 0);
        }

        [Test]
        public void BCryptHashWhenGivenSomeStringExpectResult()
        {
            ICryptHashProvider hasher = BCryptNetHashProviderFactory.NewInstance(workFactor: MockWorkFactor);
            string actual = hasher.Hash(clearText: "abc");

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual.Length > 0);
        }

        [Test]
        public void BCryptHashWhenGivenAnotherStringExpectResult()
        {
            ICryptHashProvider hasher = BCryptNetHashProviderFactory.NewInstance(workFactor: MockWorkFactor);
            string actual = hasher.Hash(
                clearText: "Ut est etiam invenire maluisset, ea porro debitis indoctum vim, ad eos error invidunt constituto. Eu velit quando fabellas sea. Sea fabellas dignissim at, lorem falli mundi sea eu. Ut eum gloriatur sadipscing, ius te expetenda omittantur"
                );

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual.Length > 0);
        }
    }
}