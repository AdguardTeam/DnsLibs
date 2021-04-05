#define LOG_TO_FILE
#define UNINSTALL_REDIRECT_DRIVER

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using Adguard.Dns.Api;
using Adguard.Dns.Api.DnsProxyServer.Callbacks;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.Logging;

namespace Adguard.Dns.TestApp
{
    internal class Program
    {
        private static ILogProvider m_LogProvider;
        private static IDnsApi m_DnsApi;
        private const string REDIRECTOR_EXECUTABLE_RELATIVE_PATH = @"CoreLibs\Adguard.Core.SampleApp.exe";
        private const string CORE_TOOLS_EXECUTABLE_RELATIVE_PATH = @"CoreLibs\Adguard.Core.Tools.exe";
        private const string ARG_DRV_UNINSTALL = "/drv_uninstall";
        private const string SDNS_FILTER_RELATIVE_PATH = @"Resources\sdnsFilter.txt";
        private const int DNS_PROXY_PORT = 18090;
        private static Process m_CoreProcess;

        public static void Main(string[] args)
        {
            string redirectorAppExecutablePath = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                REDIRECTOR_EXECUTABLE_RELATIVE_PATH);
            bool isRedirectorExist = File.Exists(redirectorAppExecutablePath);
            try
            {
                m_LogProvider = new ColoredConsoleLogProvider();
                LogProvider.SetCurrentLogProvider(m_LogProvider);

#if LOG_TO_FILE
                ConsoleToFileRedirector.Start("Logs");
#endif
                m_DnsApi = DnsApi.Instance;
                m_DnsApi.InitLogger(LogLevel.Debug);
                DnsProxySettings dnsProxySettings = CreateDnsProxySettings();
                IDnsProxyServerCallbackConfiguration dnsProxyServerCallbackConfiguration =
                    new DnsProxyServerCallbackConfiguration();

                int dnsProxyProcessId = Process.GetCurrentProcess().Id;
                if (isRedirectorExist)
                {
                    m_CoreProcess =
                        WindowsTools.CreateProcess(
                            redirectorAppExecutablePath,
                            string.Format("{0} {1}", dnsProxyProcessId, DNS_PROXY_PORT),
                            true);
                    m_CoreProcess.Start();
                }

                dnsProxySettings.HandleDNSSuffixes = true;
                dnsProxySettings.OptimisticCache = true;

                m_DnsApi.StartDnsFiltering(new DnsApiConfiguration
                {
                    IsEnabled = true,
                    DnsProxySettings = dnsProxySettings,
                    DnsProxyServerCallbackConfiguration = dnsProxyServerCallbackConfiguration
                });

                Console.ReadLine();
            }
            finally
            {
                m_DnsApi.StopDnsFiltering();
                if (isRedirectorExist && m_CoreProcess != null)
                {
                    m_CoreProcess.StandardInput.WriteLine("Switching off the core sample app...");
                    m_CoreProcess.Kill();
#if UNINSTALL_REDIRECT_DRIVER
                    UninstallRedirectDriver();
#endif
                }

                ConsoleToFileRedirector.Stop();
            }
        }

        private static void UninstallRedirectDriver()
        {
            string coreToolsExecutablePath = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                CORE_TOOLS_EXECUTABLE_RELATIVE_PATH);
            Process coreToolsProcess = WindowsTools.CreateProcess(
                coreToolsExecutablePath,
                ARG_DRV_UNINSTALL, true);
            coreToolsProcess.Start();
        }

        private static UpstreamOptions CreateUpstreamOptions()
        {
            UpstreamOptions upstreamOptions = new UpstreamOptions
            {
                Address = "94.140.14.14",
                Bootstrap = new List<string>(),
                TimeoutMs = 5000,
                Id = 42,
                OutboundInterfaceIndex = 0
            };

            return upstreamOptions;
        }

        private static DnsProxySettings CreateDnsProxySettings()
        {
            List<ListenerSettings> listeners = new List<ListenerSettings>();
            foreach (AGDnsApi.ag_listener_protocol protocol in
                (AGDnsApi.ag_listener_protocol[])Enum.GetValues(typeof(AGDnsApi.ag_listener_protocol)))
            foreach (IPAddress listenerAddress in new []{ IPAddress.Loopback, IPAddress.IPv6Loopback })
            {
                ListenerSettings listener = new ListenerSettings
                {
                    EndPoint = new IPEndPoint(listenerAddress, DNS_PROXY_PORT),
                    Protocol = protocol,
                    IsPersistent = true,
                    IdleTimeoutMs = 3000
                };

                listeners.Add(listener);
            }

            DnsProxySettings dnsProxySettings = new DnsProxySettings
            {
                Upstreams = new List<UpstreamOptions>
                {
                    CreateUpstreamOptions()
                },
                Fallbacks = new List<UpstreamOptions>(),
                UserDNSSuffixes = new List<string>(),
                Dns64 = new Dns64Settings
                {
                    Upstreams = new List<UpstreamOptions>(),
                    MaxTries = 5,
                    WaitTimeMs = 2000
                },
                BlockedResponseTtlSec = 0,
                BlockingMode = AGDnsApi.ag_dnsproxy_blocking_mode.DEFAULT,
                BlockIpv6 = true,
                CustomBlockingIpv4 = null,
                CustomBlockingIpv6 = null,
                DnsCacheSize = 128,
                EngineParams = new EngineParams
                {
                    FilterParams = new List<FilterParams>
                    {
                        new FilterParams
                        {
                            Id = 0,
                            Data = Path.Combine(
                                AppDomain.CurrentDomain.BaseDirectory,
                                SDNS_FILTER_RELATIVE_PATH),
                            InMemory = false
                        }
                    }
                },
                Listeners = listeners,
                Ipv6Available = false
            };

            return dnsProxySettings;
        }
    }
}