using AdGuard.Utils.Base.DriverInstaller;
using System;
using System.Collections.Generic;
using System.IO;
using AdGuard.Utils.Base.DllProvider;

namespace Adguard.Dns.Provider
{
	/// <summary>
	/// Dnslibs dll provider 
	/// </summary>
	public class DnsLibsDllProvider : LibsDllProviderBase
	{
		private const string WIN32_DNS_LIBS_DLL_NAME = @"x86\AdguardDns.dll";
		private const string WIN64_DNS_LIBS_DLL_NAME = @"x64\AdguardDns.dll";

		/// <summary>
		/// The main dll names were changed to "win32" versions for all kinds of architectures
		/// due to https://jira.adguard.com/browse/AG-17629
		/// </summary>
		private static readonly Dictionary<ArchitectureLocal, string> DNS_LIBS_DLL_PATHES_MAP =
			new Dictionary<ArchitectureLocal, string>
			{
				{
					ArchitectureLocal.X86,
						Path.Combine(
							AppDomain.CurrentDomain.BaseDirectory,
							WIN32_DNS_LIBS_DLL_NAME)
                },
				{
					ArchitectureLocal.X64,
						Path.Combine(
							AppDomain.CurrentDomain.BaseDirectory,
							WIN64_DNS_LIBS_DLL_NAME)
				},
				{
					ArchitectureLocal.Arm,
						Path.Combine(
							AppDomain.CurrentDomain.BaseDirectory,
							WIN32_DNS_LIBS_DLL_NAME)
				},
				{
					ArchitectureLocal.Arm64,
						Path.Combine(
							AppDomain.CurrentDomain.BaseDirectory,
							WIN64_DNS_LIBS_DLL_NAME)
				}
			};

		/// <summary>
		/// Dns libs dll provider
		/// </summary>
		public DnsLibsDllProvider() : base(DNS_LIBS_DLL_PATHES_MAP)
		{
		}

		private static readonly Lazy<DnsLibsDllProvider> LAZY =
			new Lazy<DnsLibsDllProvider>(() => new DnsLibsDllProvider());

		#region Singleton

		/// <summary>
		/// Gets a singleton instance of <see cref="DnsLibsDllProvider"/> object
		/// </summary>
		public static ILibsDllProvider Instance
		{
			get { return LAZY.Value; }
		}

		#endregion

		/// <summary>
		/// Gets or sets dnslibs dll path
		/// </summary>
		public string DnsLibsDllPath { get; private set; }
	}
}