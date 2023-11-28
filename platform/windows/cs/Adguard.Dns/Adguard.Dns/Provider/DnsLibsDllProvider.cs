using AdGuard.Utils.Base.DriverInstaller;
using AdGuard.Utils.Base.Interop;
using AdGuard.Utils.Base.Logging;
using AdGuard.Utils.Base.Utils;
using System;
using System.Collections.Generic;
using System.IO;

namespace Adguard.Dns.Provider
{
	/// <summary>
	/// Dnslibs dll provider 
	/// </summary>
	public class DnsLibsDllProvider : IDnsLibsDllProvider
	{
		private const string WIN32_DNS_LIBS_DLL_NAME = @"x86\AdguardDns.dll";
		private const string WIN64_DNS_LIBS_DLL_NAME = @"x64\AdguardDns.dll";

		/// <summary>
		/// The main dll names were changed to "win32" versions for all kinds of architectures
		/// due to https://jira.adguard.com/browse/AG-17629
		/// </summary>
		private static readonly Dictionary<ArchitectureLocal, KeyValuePair<string, string>> DNS_LIBS_DLL_PATHES_MAP =
			new Dictionary<ArchitectureLocal, KeyValuePair<string, string>>
			{
				{
					ArchitectureLocal.X86,
					new KeyValuePair<string, string>(
						Path.Combine(
							AppDomain.CurrentDomain.BaseDirectory,
							WIN32_DNS_LIBS_DLL_NAME),
						Path.Combine(
							AppDomain.CurrentDomain.BaseDirectory,
							WIN64_DNS_LIBS_DLL_NAME))},
				{
					ArchitectureLocal.X64,
					new KeyValuePair<string, string>(
						Path.Combine(
							AppDomain.CurrentDomain.BaseDirectory,
							WIN64_DNS_LIBS_DLL_NAME),
						Path.Combine(
							AppDomain.CurrentDomain.BaseDirectory,
							WIN32_DNS_LIBS_DLL_NAME))

				},
				{
					ArchitectureLocal.Arm,
					new KeyValuePair<string, string>(
						Path.Combine(
							AppDomain.CurrentDomain.BaseDirectory,
							WIN32_DNS_LIBS_DLL_NAME),
						Path.Combine(
							AppDomain.CurrentDomain.BaseDirectory,
							WIN64_DNS_LIBS_DLL_NAME))
				},
				{
					ArchitectureLocal.Arm64,
					new KeyValuePair<string, string>(
						Path.Combine(
							AppDomain.CurrentDomain.BaseDirectory,
							WIN64_DNS_LIBS_DLL_NAME),
						Path.Combine(
							AppDomain.CurrentDomain.BaseDirectory,
							WIN32_DNS_LIBS_DLL_NAME))
				}
			};

		/// <summary>
		/// Gets the Dll functions instance
		/// </summary>
		// ReSharper disable once InconsistentNaming
		private readonly DynamicDllFunctions m_DnsDynamicDllFunctions;

		/// <summary>
		/// Dns libs dll provider
		/// </summary>
		public DnsLibsDllProvider()
		{
			DnsLibsDllPath = GetDnsLibsDllPath();
			DynamicDllFunctions dnsLibsDllFunctions = new DynamicDllFunctions(DnsLibsDllPath);
			m_DnsDynamicDllFunctions = dnsLibsDllFunctions;
		}

		/// <summary>
		/// Invokes function (with non-void return) with the specified <see cref="functionName"/>
		/// and passed parameters, and return the result with the specified type
		/// </summary>
		/// <param name="functionName">Function name</param>
		/// <param name="args">Collection of parameters</param>
		/// <typeparam name="TReturn">Return type</typeparam>
		/// <returns>Function result</returns>
		public TReturn InvokeFunction<TReturn>(string functionName, params object[] args)
		{
			TReturn result = m_DnsDynamicDllFunctions.InvokeFunction<TReturn>(functionName, args);
			return result;
		}

		/// <summary>
		/// Invokes function (with void return) with the specified <see cref="functionName"/>
		/// and passed parameters
		/// </summary>
		/// <param name="functionName">Function name</param>
		/// <param name="args">Collection of parameters</param>
		public void InvokeFunction(string functionName, params object[] args)
		{
			m_DnsDynamicDllFunctions.InvokeFunction(functionName, args);
		}

		private static readonly Lazy<DnsLibsDllProvider> LAZY =
			new Lazy<DnsLibsDllProvider>(() => new DnsLibsDllProvider());

		#region Singleton

		/// <summary>
		/// Gets a singleton instance of <see cref="DnsLibsDllProvider"/> object
		/// </summary>
		public static IDnsLibsDllProvider Instance
		{
			get { return LAZY.Value; }
		}

		#endregion

		/// <summary>
		/// Gets or sets dnslibs dll path
		/// </summary>
		public string DnsLibsDllPath { get; private set; }

		/// <summary>
		/// Gets the cert utils dll name, according to the operation system's architecture
		/// <exception cref="InvalidOperationException">Thrown, if
		/// current OS architecture is not recognized</exception>
		/// </summary>
		private string GetDnsLibsDllPath()
		{
			ArchitectureLocal architecture = WindowsTools.GetOsArchitecture();
			if (!DNS_LIBS_DLL_PATHES_MAP.TryGetValue(
					architecture, out KeyValuePair<string, string> dnsLibsDllPathPair))
			{
				throw new InvalidOperationException(
					$"Can't get DnsLibs dll name path because of wrong architecture type - {architecture}");
			}

			string dllName =
				GetDnsLibsDllPath(dnsLibsDllPathPair.Key, dnsLibsDllPathPair.Value);
			return dllName;
		}

		/// <summary>
		/// Gets the cert utils dll name, according to the passed prior and aux dll names
		/// <exception cref="InvalidOperationException">Thrown, if
		/// current OS architecture is not recognized</exception>
		/// </summary>
		private static string GetDnsLibsDllPath(string priorDllName, string auxDllName)
		{
			string dnsLibsDllName;
			try
			{
				using (new DynamicDllFunctions(priorDllName))
				{
					dnsLibsDllName = priorDllName;
				}
			}
			catch (InvalidOperationException ex)
			{
				Logger.QuietWarn(ex, "Simple detection of OS bitness failed: {0}({1}), IntPtr size is {2}",
					Environment.Is64BitOperatingSystem,
					Environment.Is64BitProcess,
					IntPtr.Size);
				dnsLibsDllName = auxDllName;
			}

			return dnsLibsDllName;
		}

		public void Dispose()
		{
			m_DnsDynamicDllFunctions?.Dispose();
		}
	}
}