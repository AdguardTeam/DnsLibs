using System;
using System.Collections.Generic;
using System.Net;
using Adguard.Dns.Api;
using Adguard.Dns.Api.DnsProxyServer.Callbacks;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.Logging;

//#define LOG_TO_FILE

namespace Adguard.Dns.TestApp
{
    internal class Program
    {
        private static ILogProvider m_LogProvider;
        private static IDnsApi m_DnsApi;

        public static void Main(string[] args)
        {
            m_LogProvider = new ColoredConsoleLogProvider();
            LogProvider.SetCurrentLogProvider(m_LogProvider);

#if LOG_TO_FILE
            ConsoleToFileRedirector.Start("Logs");
#endif
            m_DnsApi = DnsApi.Instance;
            m_DnsApi.InitLogger(LogLevel.Trace);
            DnsProxySettings dnsProxySettings = CreateDnsProxySettings();
            IDnsProxyServerCallbackConfiguration dnsProxyServerCallbackConfiguration =
                new DnsProxyServerCallbackConfiguration();
            m_DnsApi.StartDnsFiltering(new DnsApiConfiguration
            {
                IsEnabled = true,
                DnsProxySettings = dnsProxySettings,
                DnsProxyServerCallbackConfiguration = dnsProxyServerCallbackConfiguration
            });
            Console.ReadLine();
            m_DnsApi.StopDnsFiltering();
            ConsoleToFileRedirector.Stop();
        }

        private static UpstreamOptions CreateUpstreamOptions()
        {
            UpstreamOptions upstreamOptions = new UpstreamOptions
            {
                Address = "8.8.8.8:53",
                Bootstrap = new List<string>(),
                TimeoutMs = 500,
                ResolvedIpAddress = null,
                Id = 42
            };

            return upstreamOptions;
        }

        private static DnsProxySettings CreateDnsProxySettings()
        {
            DnsProxySettings dnsProxySettings = new DnsProxySettings
            {
                Upstreams = new List<UpstreamOptions>
                {
                    CreateUpstreamOptions()
                },
                Fallbacks = new List<UpstreamOptions>
                {
                    CreateUpstreamOptions()
                },
                Dns64 = new Dns64Settings
                {
                    Upstreams = new List<UpstreamOptions>
                    {
                        CreateUpstreamOptions()
                    },
                    MaxTries = 5,
                    WaitTimeMs = 1000
                },
                BlockedResponseTtlSec = 5,
                BlockingMode = AGDnsApi.ag_dnsproxy_blocking_mode.DEFAULT,
                BlockIpv6 = false,
                CustomBlockingIpv4 = null,
                CustomBlockingIpv6 = null,
                DnsCacheSize = 500,
                EngineParams = new EngineParams
                {
                    FilterParams = new Dictionary<int, string>
                    {
                        {0, @"c:\ProgramData\Adguard (Debug)\Temp\sdnsFilter.txt"}
                    }
                },
                Listeners = new List<ListenerSettings>
                {
                    new ListenerSettings
                    {
                        EndPoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"),45),
                        IsPersistent = true,
                        IdleTimeoutMs = 500,
                        Protocol = AGDnsApi.ag_listener_protocol.TCP
                    }
                },
                Ipv6Available = true
            };

            return dnsProxySettings;
        }
    }
}