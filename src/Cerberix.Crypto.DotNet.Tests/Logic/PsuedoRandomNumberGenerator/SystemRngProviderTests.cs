using System;
using Cerberix.Crypto.Core;
using NUnit.Framework;

namespace Cerberix.Crypto.DotNet.Logic.Tests
{
    [TestFixture]
    public class SystemRngProviderTests
    {
        //
        //  Next()
        //

        [Test]
        public void Test__SystemRng__Next__ExpectSomeIntegerValues()
        {
            const int numGenerations = 1000000; // test one meellion iterations

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();

            for (var i = 0; i < numGenerations; i++)
            {
                var actual = generator.Next();

                Assert.IsNotNull(actual);
                Assert.IsTrue(actual >= 0);
                Assert.IsTrue(actual < int.MaxValue);
            }
        }

        [Test]
        public void Test__SystemRng__NextMaxValue01__ExpectException()
        {
            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            Assert.Throws<ArgumentOutOfRangeException>(() => generator.Next(-1));
        }

        [Test]
        public void Test__SystemRng__NextMaxValue02__ExpectException()
        {
            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            Assert.Throws<ArgumentOutOfRangeException>(() => generator.Next(int.MinValue));
        }

        [Test]
        public void Test__SystemRng__NextMaxValue__ExpectAreEqual()
        {
            const int maxValue = 0;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.Next(maxValue);

            Assert.IsNotNull(actual);
            Assert.AreEqual(actual, maxValue);
        }

        [Test]
        public void Test__SystemRng__NextMaxValue01__ExpectLessThan()
        {
            const int maxValue = 1;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.Next(maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
        }

        [Test]
        public void Test__SystemRng__NextMaxValue02__ExpectLessThan()
        {
            const int maxValue = 100;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.Next(maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
        }

        [Test]
        public void Test__SystemRng__NextMaxValue03__ExpectLessThan()
        {
            const int maxValue = 1000000;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.Next(maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
        }

        [Test]
        public void Test__SystemRng__NextMaxValue04__ExpectLessThan()
        {
            const int maxValue = int.MaxValue;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.Next(maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
        }

        [Test]
        public void Test__SystemRng__NextMinMaxValue01__ExpectException()
        {
            const int minValue = 1;
            const int maxValue = -1;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            Assert.Throws<ArgumentOutOfRangeException>(() => generator.Next(minValue, maxValue));
        }

        [Test]
        public void Test__SystemRng__NextMinMaxValue02__ExpectException()
        {
            const int minValue = 2;
            const int maxValue = 1;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            Assert.Throws<ArgumentOutOfRangeException>(() => generator.Next(minValue, maxValue));
        }

        [Test]
        public void Test__SystemRng__NextMinMaxValue01__ExpectAreEqual()
        {
            const int inputValue = 0;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.Next(inputValue, inputValue);

            Assert.IsNotNull(actual);
            Assert.AreEqual(actual, inputValue);
        }

        [Test]
        public void Test__SystemRng__NextMinMaxValue02__ExpectAreEqual()
        {
            const int inputValue = 1;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.Next(inputValue, inputValue);

            Assert.IsNotNull(actual);
            Assert.AreEqual(actual, inputValue);
        }

        [Test]
        public void Test__SystemRng__NextMinMaxValue03__ExpectAreEqual()
        {
            const int inputValue = -1;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.Next(inputValue, inputValue);

            Assert.IsNotNull(actual);
            Assert.AreEqual(actual, inputValue);
        }

        [Test]
        public void Test__SystemRng__NextMinMaxValue01__ExpectRange()
        {
            const int minValue = 1;
            const int maxValue = 2;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.Next(minValue, maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
            Assert.IsTrue(actual >= minValue);
        }

        [Test]
        public void Test__SystemRng__NextMinMaxValue02__ExpectRange()
        {
            const int minValue = 0;
            const int maxValue = int.MaxValue;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.Next(minValue, maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
            Assert.IsTrue(actual >= minValue);
        }

        [Test]
        public void Test__SystemRng__NextMinMaxValue03__ExpectRange()
        {
            const int minValue = -1;
            const int maxValue = 0;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.Next(minValue, maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
            Assert.IsTrue(actual >= minValue);
        }

        [Test]
        public void Test__SystemRng__NextMinMaxValue04__ExpectRange()
        {
            const int minValue = int.MinValue;
            const int maxValue = -1;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.Next(minValue, maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
            Assert.IsTrue(actual >= minValue);
        }

        [Test]
        public void Test__SystemRng__NextMinMaxValue05__ExpectRange()
        {
            const int minValue = -1;
            const int maxValue = 1;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.Next(minValue, maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
            Assert.IsTrue(actual >= minValue);
        }

        [Test]
        public void Test__SystemRng__NextMinMaxValue06__ExpectRange()
        {
            const int minValue = int.MinValue;
            const int maxValue = int.MaxValue;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.Next(minValue, maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
            Assert.IsTrue(actual >= minValue);
        }

        //
        //  NextDouble()
        //

        [Test]
        public void Test__SystemRng__NextDouble__ExpectSomeIntegerValues()
        {
            const int numGenerations = 1000000; // test one meellion iterations

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();

            for (var i = 0; i < numGenerations; i++)
            {
                var actual = generator.NextDouble();

                Assert.IsNotNull(actual);
                Assert.IsTrue(actual >= 0.00);
                Assert.IsTrue(actual < 1.00);
            }
        }

        [Test]
        public void Test__SystemRng__NextDoubleMaxValue01__ExpectException()
        {
            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            Assert.Throws<ArgumentOutOfRangeException>(() => generator.NextDouble(-1.00));
        }

        [Test]
        public void Test__SystemRng__NextDoubleMaxValue02__ExpectException()
        {
            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            Assert.Throws<ArgumentOutOfRangeException>(() => generator.NextDouble(double.MinValue));
        }

        [Test]
        public void Test__SystemRng__NextDoubleMaxValue__ExpectAreEqual()
        {
            const double maxValue = 0.00;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(maxValue);

            Assert.IsNotNull(actual);
            Assert.AreEqual(actual, maxValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMaxValue01__ExpectLessThan()
        {
            const double maxValue = 1.00;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMaxValue02__ExpectLessThan()
        {
            const double maxValue = 100.00;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMaxValue03__ExpectLessThan()
        {
            const double maxValue = 1000000.00;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMaxValue04__ExpectLessThan()
        {
            const double maxValue = 1000.01;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMaxValue05__ExpectLessThan()
        {
            const double maxValue = 999.98;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMaxValue06__ExpectLessThan()
        {
            const double maxValue = double.MaxValue;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMinMaxValue01__ExpectException()
        {
            const double minValue = 1.00;
            const double maxValue = -1.00;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            Assert.Throws<ArgumentOutOfRangeException>(() => generator.NextDouble(minValue, maxValue));
        }

        [Test]
        public void Test__SystemRng__NextDoubleMinMaxValue02__ExpectException()
        {
            const double minValue = 2.00;
            const double maxValue = 1.00;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            Assert.Throws<ArgumentOutOfRangeException>(() => generator.NextDouble(minValue, maxValue));
        }

        [Test]
        public void Test__SystemRng__NextDoubleMinMaxValue03__ExpectException()
        {
            const double minValue = 2.22;
            const double maxValue = -3.34;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            Assert.Throws<ArgumentOutOfRangeException>(() => generator.NextDouble(minValue, maxValue));
        }

        [Test]
        public void Test__SystemRng__NextDoubleMinMaxValue01__ExpectAreEqual()
        {
            const double inputValue = 0.00;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(inputValue, inputValue);

            Assert.IsNotNull(actual);
            Assert.AreEqual(actual, inputValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMinMaxValue02__ExpectAreEqual()
        {
            const double inputValue = 1.00;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(inputValue, inputValue);

            Assert.IsNotNull(actual);
            Assert.AreEqual(actual, inputValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMinMaxValue03__ExpectAreEqual()
        {
            const double inputValue = -1.00;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(inputValue, inputValue);

            Assert.IsNotNull(actual);
            Assert.AreEqual(actual, inputValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMinMaxValue04__ExpectAreEqual()
        {
            const double inputValue = 2.22;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(inputValue, inputValue);

            Assert.IsNotNull(actual);
            Assert.AreEqual(actual, inputValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMinMaxValue05__ExpectAreEqual()
        {
            const double inputValue = -3.34;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(inputValue, inputValue);

            Assert.IsNotNull(actual);
            Assert.AreEqual(actual, inputValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMinMaxValue06__ExpectAreEqual()
        {
            const double inputValue = double.MaxValue;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(inputValue, inputValue);

            Assert.IsNotNull(actual);
            Assert.AreEqual(actual, inputValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMinMaxValue01__ExpectRange()
        {
            const double minValue = 1.00;
            const double maxValue = 2.00;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(minValue, maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
            Assert.IsTrue(actual >= minValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMinMaxValue02__ExpectRange()
        {
            const double minValue = 0.00;
            const double maxValue = double.MaxValue;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(minValue, maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
            Assert.IsTrue(actual >= minValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMinMaxValue03__ExpectRange()
        {
            const double minValue = -1.00;
            const double maxValue = 0.00;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(minValue, maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
            Assert.IsTrue(actual >= minValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMinMaxValue04__ExpectRange()
        {
            const double minValue = double.MinValue;
            const double maxValue = -1.00;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(minValue, maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
            Assert.IsTrue(actual >= minValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMinMaxValue05__ExpectRange()
        {
            const double minValue = -1.00;
            const double maxValue = 1.00;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(minValue, maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
            Assert.IsTrue(actual >= minValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMinMaxValue06__ExpectRange()
        {
            const double minValue = 0.01;
            const double maxValue = 0.02;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(minValue, maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
            Assert.IsTrue(actual >= minValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMinMaxValue07__ExpectRange()
        {
            const double minValue = 0.99;
            const double maxValue = 1.11;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(minValue, maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
            Assert.IsTrue(actual >= minValue);
        }

        [Test]
        public void Test__SystemRng__NextDoubleMinMaxValue08__ExpectRange()
        {
            const double minValue = double.MinValue;
            const double maxValue = double.MaxValue;

            IPsuedoRandomNumberGenerator generator = SystemRngProviderFactory.NewInstance();
            var actual = generator.NextDouble(minValue, maxValue);

            Assert.IsNotNull(actual);
            Assert.IsTrue(actual < maxValue);
            Assert.IsTrue(actual >= minValue);
        }
    }
}