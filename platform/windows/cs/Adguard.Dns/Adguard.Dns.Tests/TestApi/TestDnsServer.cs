using System.Collections.Generic;
using Adguard.Dns.Api.DnsProxyServer.Callbacks;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.DnsProxyServer;
using Adguard.Dns.Tests.Helpers;
using NUnit.Framework;

namespace Adguard.Dns.Tests.TestApi
{
    [TestFixture]
    public class TestDnsServer
    {
        [Test]
        public void TestSupportApiVersion()
        {
            Assert.DoesNotThrow(AGDnsApi.ValidateApi);
        }

        [Test]
        public void TestDnsProxyServer()
        {
            DnsProxySettings currentDnsProxySettings = new DnsProxySettings();
            IDnsProxyServerCallbackConfiguration callback = new DnsProxyServerCallbackConfiguration();
            Assert.DoesNotThrow(() =>
            {
                IDnsProxyServer server = new DnsProxyServer.DnsProxyServer(currentDnsProxySettings, callback);
            });
        }

        [Test]
        public void TestGetCurrentDnsProxySettings()
        {
            DnsProxySettings defaultDnsProxySettings = DnsProxyServer.DnsProxyServer.GetDefaultDnsProxySettings();
            defaultDnsProxySettings.Upstreams.Add(new UpstreamOptions
            {
                Address = "8.8.8.8:53",
                Id = 1,
                Bootstrap = new List<string>()
            });
            IDnsProxyServerCallbackConfiguration callback = new DnsProxyServerCallbackConfiguration();
            Assert.DoesNotThrow(() =>
            {
                IDnsProxyServer server = new DnsProxyServer.DnsProxyServer(defaultDnsProxySettings, callback);
                server.Start();
            });
        }
    }
}