using System;
using Adguard.Dns.Api.DnsProxyServer.Callbacks;
using Adguard.Dns.Api.DnsProxyServer.EventArgs;

namespace Adguard.Dns.TestApp
{
    public class DnsProxyServerCallbackConfiguration : IDnsProxyServerCallbackConfiguration
    {
        public void OnDnsRequestProcessed(object sender, DnsRequestProcessedEventArgs args)
        {
            Console.Out.WriteLine("OnDnsRequestProcessed called, args - {0}", args);
        }
    }
}