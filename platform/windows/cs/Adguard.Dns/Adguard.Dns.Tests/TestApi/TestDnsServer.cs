using Adguard.Dns.Api;
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
        public void TestGetDefaultSettings()
        {
            DnsProxySettings defaultDnsProxySettings = DnsApi.Instance.GetDefaultDnsProxySettings();
            Assert.IsNotNull(defaultDnsProxySettings);
            Assert.IsNotNull(defaultDnsProxySettings.Upstreams);
            Assert.IsNotNull(defaultDnsProxySettings.Fallbacks);
            Assert.IsNotNull(defaultDnsProxySettings.Listeners);
            Assert.IsNotNull(defaultDnsProxySettings.EngineParams);
            Assert.IsNotNull(defaultDnsProxySettings.Dns64);
            Assert.IsNotNull(defaultDnsProxySettings.OutboundProxySettings);
        }

        [Test]
        public void TestGetCurrentDnsProxySettings()
        {
            DnsProxySettings defaultDnsProxySettings = DnsApi.Instance.GetDefaultDnsProxySettings();
            DnsApi.Instance.StartDnsFiltering(new DnsApiConfiguration
            {
                IsEnabled = true,
                DnsProxySettings = defaultDnsProxySettings,
                DnsProxyServerCallbackConfiguration = new DnsProxyServerCallbackConfiguration()
            });
            DnsProxySettings currentDnsProxySettings = DnsApi.Instance.GetCurrentDnsProxySettings();
            Assert.IsNotNull(currentDnsProxySettings);
            Assert.IsNotNull(currentDnsProxySettings.Upstreams);
            Assert.IsNotNull(currentDnsProxySettings.Fallbacks);
            Assert.IsNotNull(currentDnsProxySettings.UserDNSSuffixes);
            Assert.IsNotNull(currentDnsProxySettings.Listeners);
            Assert.IsNotNull(currentDnsProxySettings.EngineParams); 
            Assert.IsNotNull(currentDnsProxySettings.Dns64);
            Assert.IsNotNull(currentDnsProxySettings.OutboundProxySettings);
            Assert.AreEqual(defaultDnsProxySettings, currentDnsProxySettings);
            DnsApi.Instance.StopDnsFiltering();
            currentDnsProxySettings = DnsApi.Instance.GetCurrentDnsProxySettings();
            Assert.IsNull(currentDnsProxySettings);
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