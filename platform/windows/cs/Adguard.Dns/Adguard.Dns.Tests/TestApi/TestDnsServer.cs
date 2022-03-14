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

    }
}