using System;

namespace Cerberix.Crypto.Core
{
	public interface IPsuedoRandomNumberGenerator : IDisposable
	{
		/// <summary>
		///		Next Integer
		/// </summary>
		int Next();

		/// <summary>
		///		Next Integer (not to exceed maxValue, must equal or exceed zero)
		/// </summary>
		int Next(int maxValue);

		/// <summary>
		///		Next Integer (not to exceed maxValue, must equal or exceed minValue)
		/// </summary>
		int Next(int minValue, int maxValue);

		/// <summary>
		///		Next Double
		/// </summary>
		double NextDouble();

		/// <summary>
		///		Next Double (not to exceed maxValue, must equal or exceed zero)
		/// </summary>
		double NextDouble(double maxValue);

		/// <summary>
		///		Next Double (not to exceed maxValue, must equal or exceed minValue)
		/// </summary>
		double NextDouble(double minValue, double maxValue);
	}
}
