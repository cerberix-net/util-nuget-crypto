using Cerberix.Crypto.Core;
using NUnit.Framework;

namespace Cerberix.Crypto.BCryptNet.Logic.Tests
{
    [TestFixture]
    public class BCryptNetHashVerifyProviderTests
    {
        private const int MockWorkFactor = 10;

        [Test]
        public void BCryptHashVerifyWhenGivenEmptyStringExpectResult()
        {
            const string clearText = "";

            ICryptHashProvider hasher = BCryptNetHashProviderFactory.NewInstance(workFactor: MockWorkFactor);
            string hashText = hasher.Hash(clearText: clearText);

            ICryptHashVerifyProvider verifier = BCryptNetHashVerifyProviderFactory.NewInstance();
            bool actual = verifier.Verify(clearText: clearText, hashText: hashText);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual);
        }

        [Test]
        public void BCryptHashVerifyWhenGivenSomeStringExpectResult()
        {
            const string clearText = "abc";

            ICryptHashProvider hasher = BCryptNetHashProviderFactory.NewInstance(workFactor: MockWorkFactor);
            string hashText = hasher.Hash(clearText: clearText);

            ICryptHashVerifyProvider verifier = BCryptNetHashVerifyProviderFactory.NewInstance();
            bool actual = verifier.Verify(clearText: clearText, hashText: hashText);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual);
        }

        [Test]
        public void BCryptHashVerifyWhenGivenAnotherStringExpectResult()
        {
            const string clearText = "Ut est etiam invenire maluisset, ea porro debitis indoctum vim, ad eos error invidunt constituto. Eu velit quando fabellas sea. Sea fabellas dignissim at, lorem falli mundi sea eu. Ut eum gloriatur sadipscing, ius te expetenda omittantur";

            ICryptHashProvider hasher = BCryptNetHashProviderFactory.NewInstance(workFactor: MockWorkFactor);
            string hashText = hasher.Hash(clearText: clearText);

            ICryptHashVerifyProvider verifier = BCryptNetHashVerifyProviderFactory.NewInstance();
            bool actual = verifier.Verify(clearText: clearText, hashText: hashText);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual);
        }

        [Test]
        public void BCryptHashVerifyWhenGivenEmptyStringPlusHash01ExpectResult()
        {
            ICryptHashVerifyProvider verifier = BCryptNetHashVerifyProviderFactory.NewInstance();
            bool actual = verifier.Verify(
                clearText: string.Empty, 
                hashText: "$2a$08$ngecfrBdgIQxm2RVGg5NAOpI4ia9vO8COjmgFZcto/DXz2O8V84P."
                );

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual);
        }

        [Test]
        public void BCryptHashVerifyWhenGivenEmptyStringPlusHash02ExpectResult()
        {
            ICryptHashVerifyProvider verifier = BCryptNetHashVerifyProviderFactory.NewInstance();
            bool actual = verifier.Verify(
                clearText: string.Empty, 
                hashText: "$2a$08$VCmc/.X7dL7FP1P1SOYM3.FC8Ba7x6BkykohAnwiXYB6KJWc7ECd2"
                );

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual);
        }

        [Test]
        public void BCryptHashVerifyWhenGivenEmptyStringPlusHash03ExpectResult()
        {
            ICryptHashVerifyProvider verifier = BCryptNetHashVerifyProviderFactory.NewInstance();
            bool actual = verifier.Verify(
                clearText: string.Empty, 
                hashText: "$2a$08$zclji7Sgcl6f526kQG95aeL423qLlvKKlJcmHLz1E3cIcbyAQIwmy"
                );

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual);
        }

        [Test]
        public void BCryptHashVerifyWhenGivenSomeStringPlusHash01ExpectResult()
        {
            ICryptHashVerifyProvider verifier = BCryptNetHashVerifyProviderFactory.NewInstance();
            bool actual = verifier.Verify(
                clearText: "abc", 
                hashText: "$2a$08$64mZKD29PXMpmoyvQx4hXOWHCt6xfg/qO3kB9DDPb5OQWSQW8es3m"
                );

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual);
        }

        [Test]
        public void BCryptHashVerifyWhenGivenSomeStringPlusHash02ExpectResult()
        {
            ICryptHashVerifyProvider verifier = BCryptNetHashVerifyProviderFactory.NewInstance();
            bool actual = verifier.Verify(
                clearText: "abc", 
                hashText: "$2a$08$ODV6dmmIhB5xJICDx7WzC.UcJWFW/TrKZdzQQNMvB.UZRTlkYelQ."
                );

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual);
        }

        [Test]
        public void BCryptHashVerifyWhenGivenSomeStringPlusHash03ExpectResult()
        {
            ICryptHashVerifyProvider verifier = BCryptNetHashVerifyProviderFactory.NewInstance();
            bool actual = verifier.Verify(
                clearText: "abc", 
                hashText: "$2a$08$56wBcuHHq8pwOZE6EkbXveCSsfpDUdWr1I7Cf6J5p30KgV3RAkU92"
                );

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual);
        }

        [Test]
        public void BCryptHashVerifyWhenGivenAnotherStringPlusHash01ExpectResult()
        {
            ICryptHashVerifyProvider verifier = BCryptNetHashVerifyProviderFactory.NewInstance();
            bool actual = verifier.Verify(
                clearText: "Ut est etiam invenire maluisset, ea porro debitis indoctum vim, ad eos error invidunt constituto. Eu velit quando fabellas sea. Sea fabellas dignissim at, lorem falli mundi sea eu. Ut eum gloriatur sadipscing, ius te expetenda omittantur", 
                hashText: "$2a$08$VBQkRgQTpwZ4LVqGglxQGOZhTgKL6JJ35YnJZFsSLUtEn5TrfvCgO"
                );

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual);
        }

        [Test]
        public void BCryptHashVerifyWhenGivenAnotherStringPlusHash02ExpectResult()
        {
            ICryptHashVerifyProvider verifier = BCryptNetHashVerifyProviderFactory.NewInstance();
            bool actual = verifier.Verify(
                clearText: "Ut est etiam invenire maluisset, ea porro debitis indoctum vim, ad eos error invidunt constituto. Eu velit quando fabellas sea. Sea fabellas dignissim at, lorem falli mundi sea eu. Ut eum gloriatur sadipscing, ius te expetenda omittantur", 
                hashText: "$2a$08$3gt82YGR/ZVVp3kNoomw/ughH8fXiCtKZzViDN2zW88fUF3dieCbm"
                );

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual);
        }

        [Test]
        public void BCryptHashVerifyWhenGivenAnotherStringPlusHash03ExpectResult()
        {
            ICryptHashVerifyProvider verifier = BCryptNetHashVerifyProviderFactory.NewInstance();
            bool actual = verifier.Verify(
                clearText: "Ut est etiam invenire maluisset, ea porro debitis indoctum vim, ad eos error invidunt constituto. Eu velit quando fabellas sea. Sea fabellas dignissim at, lorem falli mundi sea eu. Ut eum gloriatur sadipscing, ius te expetenda omittantur", 
                hashText: "$2a$08$XF7BKJuRFjUIs2ocx21PuOuctERuiL79MhhQ8tlcRmloYcB4lbWyG"
                );

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual);
        }

        [Test]
        public void BCryptHashVerifyWhenGivenLotionStringPlusHash01ExpectResult()
        {
            ICryptHashVerifyProvider verifier = BCryptNetHashVerifyProviderFactory.NewInstance();
            bool actual = verifier.Verify(
                clearText: "loción", 
                hashText: "$2a$08$O7sxEzE6yxCdldEet1nHM.6ixw8vj3I0G9YmAVqOJ3Q8HvCcn1HSy"
                );

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual);
        }

        [Test]
        public void BCryptHashVerifyWhenGivenLotionStringPlusHash02ExpectResult()
        {
            ICryptHashVerifyProvider verifier = BCryptNetHashVerifyProviderFactory.NewInstance();
            bool actual = verifier.Verify(
                clearText: "loción", 
                hashText: "$2a$08$oUIMCE789f3vcjCg9eTJeeyewgVgDHzzvxEKysXX.TnYS5myqm0mi"
                );

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual);
        }

        [Test]
        public void BCryptHashVerifyWhenGivenLotionStringPlusHash03ExpectResult()
        {
            ICryptHashVerifyProvider verifier = BCryptNetHashVerifyProviderFactory.NewInstance();
            bool actual = verifier.Verify(
                clearText: "loción", 
                hashText: "$2a$08$0P7Yx0hyCi97PuC//eCEaOSItPpDaiYWNMqJ9aPk4G7Jy.8C68KP."
                );

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual);
        }
    }
}