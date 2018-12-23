using System;
using Cerberix.Crypto.Core;

namespace Cerberix.Crypto.DotNet.Logic
{
    internal class SystemRngProvider : IPsuedoRandomNumberGenerator
	{
		private readonly Random _Random;
		private readonly object _Lock;

        public SystemRngProvider()
		{
			_Lock = new object();

			lock(_Lock)
				_Random = new Random();
		}

		public int Next()
		{
			int result;

			lock (_Lock)
				result = _Random.Next();

			return result;
		}

		public int Next(int maxValue)
		{
			int result;

			lock (_Lock)
				result = _Random.Next(maxValue);
			return result;
		}

		public int Next(int minValue, int maxValue)
		{
			int result;

			lock (_Lock)
				result = _Random.Next(minValue, maxValue);
			
			return result;
		}

		public double NextDouble()
		{
			double result;

			lock(_Lock)
				result = _Random.NextDouble();

			return result;
		}

		public double NextDouble(double maxValue)
		{
			if (maxValue < 0.00)
				throw new ArgumentOutOfRangeException("maxValue must be greater than or equal to zero.");

			double result;

			lock(_Lock)
				result = _Random.NextDouble() * maxValue;

			return result;
		}

		public double NextDouble(double minValue, double maxValue)
		{
			if (maxValue < minValue)
				throw new ArgumentOutOfRangeException("maxValue must be greater than or equal to minValue");

			double result;

			lock (_Lock)
				result = (_Random.NextDouble()*(maxValue - minValue)) + minValue;

			return result;
		}

        public void Dispose()
		{
			//
			// do nothing, rely on automagic garbage collection
			//
		}
	}
}
