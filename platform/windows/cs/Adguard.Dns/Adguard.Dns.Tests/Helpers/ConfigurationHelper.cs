using System.Collections.Generic;
using System.Net;
using Adguard.Dns.Api.DnsProxyServer.Configs;

namespace Adguard.Dns.Tests.Helpers
{
    internal class ConfigurationHelper
    {
        internal static UpstreamOptions CreateUpstreamOptions()
        {
            UpstreamOptions upstreamOptions = new UpstreamOptions
            {
                Address = "8.8.8.8:53",
                Bootstrap = new List<string>(),
                TimeoutMs = 500,
                ResolvedIpAddress = null,
                Id = 42,
                OutboundInterfaceIndex = 0
            };

            return upstreamOptions;
        }

        internal static DnsProxySettings CreateDnsProxySettings()
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
                UserDNSSuffixes = new List<string>(),
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
                    FilterParams = new List<FilterParams>
                    {
                        new FilterParams
                        {
                            Id = 0,
                            Data = "blablabla",
                            InMemory = true
                        }
                    }
                },
                Listeners = new List<ListenerSettings>
                {
                    new ListenerSettings
                    {
                        EndPoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"),45),
                        IsPersistent = true,
                        IdleTimeoutMs = 500
                    }
                },
                Ipv6Available = true,
                OptimisticCache = false,
                EnableDNSSECOK = false,
                EnableRetransmissionHandling = false
            };

            return dnsProxySettings;
        }
    }
}