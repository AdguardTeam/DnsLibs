using System;

namespace Adguard.Dns.Provider
{
	/// <summary>
	/// Class for defining the required dns libs dll
	/// </summary>
	public interface IDnsLibsDllProvider : IDisposable
	{
		/// <summary>
		/// Gets or sets dnslibs dll path
		/// </summary>
		string DnsLibsDllPath { get; }

		/// <summary>
		/// Invokes function (with non-void return) with the specified <see cref="functionName"/>
		/// and passed parameters, and return the result with the specified type
		/// </summary>
		/// <param name="functionName">Function name</param>
		/// <param name="args">Collection of parameters</param>
		/// <typeparam name="TReturn">Return type</typeparam>
		/// <returns>Function result</returns>
		TReturn InvokeFunction<TReturn>(string functionName, params object[] args);

		/// <summary>
		/// Invokes function (with void return) with the specified <see cref="functionName"/>
		/// and passed parameters
		/// </summary>
		/// <param name="functionName">Function name</param>
		/// <param name="args">Collection of parameters</param>
		void InvokeFunction(string functionName, params object[] args);
	}
}
