using System;
using System.Collections.Generic;
using System.Net;
using Adguard.Dns.Api.DnsProxyServer.Callbacks;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.Api.DnsProxyServer.EventArgs;
using Adguard.Dns.DnsProxyServer;
using Adguard.Dns.Helpers;
using Adguard.Dns.Utils;
using AdGuard.Utils.Collections;
using AdGuard.Utils.Interop;
using NUnit.Framework;

namespace Adguard.Dns.Tests.Helpers
{
    [TestFixture]
    class TestDnsApiConverter
    {
        // Initialized properties without which working is impossible
        [Test]
        public void TestDnsProxySettingsConverter()
        {
            DnsProxySettings dnsSettings = new DnsProxySettings
            {
                Upstreams = new List<UpstreamOptions>
                {
                    new UpstreamOptions
                    {
                        Id = 1,
                        Bootstrap = new List<string>()
                    },
                    new UpstreamOptions
                    {
                        Id = 2,
                        Bootstrap = new List<string>()
                    },
                    new UpstreamOptions
                    {
                    Id = 3,
                    Bootstrap = new List<string>
                    {
                        "bootStrapBegin",
                        "bootStrapEnd"
                    }
                }
                },
                Fallbacks = new List<UpstreamOptions>()
                {
                    new UpstreamOptions
                    {
                        Bootstrap = new List<string>()
                    }
                },
                BlockedResponseTtlSec = 64,
                Dns64 = new Dns64Settings
                {
                    Upstreams = new List<UpstreamOptions>()
                },
                EngineParams = new EngineParams
                {
                    FilterParams = new List<FilterParams>()
                },
                Listeners = new List<ListenerSettings>
                {
                    new ListenerSettings
                    {
                        EndPoint = new IPEndPoint(1234567, 9898)
                    }
                },
                FallbackDomains = new List<string>
                {
                    "Test.com"
                },
                Ipv6Available = true,
                BlockIpv6 = true,
                BlockingMode = new AGDnsApi.ag_dnsproxy_blocking_mode(),
                CustomBlockingIpv4 = "CustomBlockingIpv4Test",
                CustomBlockingIpv6 = "CustomBlockingIpv6Test",
                DnsCacheSize = 23,
                OptimisticCache = true
            };
            Queue<IntPtr> allocatedPointers = new Queue<IntPtr>();

            AGDnsApi.ag_dnsproxy_settings nativeDnsSettings =
                DnsApiConverter.ToNativeObject(dnsSettings, allocatedPointers);
            Assert.AreNotEqual(IntPtr.Zero, nativeDnsSettings.fallbacks.entries);
            Assert.AreNotEqual(IntPtr.Zero, nativeDnsSettings.fallbackDomains.entries);
            Assert.AreNotEqual(IntPtr.Zero, nativeDnsSettings.listeners.entries);
            Assert.AreNotEqual(IntPtr.Zero, nativeDnsSettings.upstreams.entries);
            Assert.AreEqual(nativeDnsSettings.BlockedResponseTtlSec, dnsSettings.BlockedResponseTtlSec);

            DnsProxySettings dnsSettingsConverted =  DnsApiConverter.FromNativeObject(nativeDnsSettings);
            Assert.AreEqual(dnsSettingsConverted.FallbackDomains, dnsSettings.FallbackDomains);
            Assert.AreEqual(dnsSettingsConverted.BlockedResponseTtlSec, dnsSettings.BlockedResponseTtlSec);
            bool isUpstreamsEqual = CollectionUtils.ListsEquals(dnsSettingsConverted.Upstreams, dnsSettings.Upstreams);
            Assert.IsTrue(isUpstreamsEqual);
        }

        [Test]
        public void TestUpstreamOptionsConverter()
        {
            IDnsProxyServerCallbackConfiguration dnsCallback = new DnsProxyServerCallbackConfiguration();
            DnsProxySettings currentDnsProxySettings = new DnsProxySettings();
            IDnsProxyServer proxyServer = new DnsProxyServer.DnsProxyServer(currentDnsProxySettings, dnsCallback);

            AGDnsApi.AGDnsProxyServerCallbacks serverCallbackNative =
                DnsApiConverter.ToNativeObject(dnsCallback, proxyServer);
            Assert.NotNull(serverCallbackNative);
        }

        [Test]
        public void TestDnsStampConverter()
        {
            DnsStamp dnsStamp = new DnsStamp
            {
                ProtoType = new AGDnsApi.ag_stamp_proto_type(),
                ServerAddress = "addressTest",
                ProviderName = "Nametest",
                DoHPath = "DoHPathTest",
                Hashes = new List<byte[]>
                {
                    new byte[] {12, 34, 15},
                    new byte[] {10, 8, 16, 3}
                },
                Properties = new AGDnsApi.ag_server_informal_properties()
            };
            Queue<IntPtr> allocatedPointers = new Queue<IntPtr>();
            AGDnsApi.ag_dns_stamp stampNative = DnsApiConverter.ToNativeObject(dnsStamp, allocatedPointers);
            string address = MarshalUtils.PtrToString(stampNative.ServerAddress);
            Assert.AreEqual(address, dnsStamp.ServerAddress);

            DnsStamp dnsStampConverted = DnsApiConverter.FromNativeObject(stampNative);
            Assert.AreEqual(dnsStamp.ServerAddress, dnsStampConverted.ServerAddress);
            Assert.AreEqual(dnsStamp.Hashes, dnsStampConverted.Hashes);
            // use CollectionsEquals after updated Utils to compare dnsStamp.Hashes. ListsEquals doesn't work
            Assert.AreEqual(dnsStamp.Hashes.Capacity, dnsStampConverted.Hashes.Capacity);
        }

        [Test]
        public void TestDnsRequestProcessedConverter()
        {
            AGDnsApi.ag_dns_request_processed_event dnsRequestNative = new AGDnsApi.ag_dns_request_processed_event();
            DnsRequestProcessedEventArgs dnsRequest = DnsApiConverter.FromNativeObject(dnsRequestNative);
            Assert.IsNotNull(dnsRequest);
        }

        [Test]
        public void TestCertificateVerificationCallbackConverter()
        {
            ICertificateVerificationCallback certificateVerificationCallback = new CertificateVerificationCallback();
            AGDnsApi.cbd_onCertificateVerification certificate =
                DnsApiConverter.ToNativeObject(certificateVerificationCallback);
            Assert.NotNull(certificate);
        }

        [Test]
        public void TestCertificateVerificationEventConverter()
        {
            AGDnsApi.ag_certificate_verification_event coreArgsС = new AGDnsApi.ag_certificate_verification_event();
            CertificateVerificationEventArgs certificate = DnsApiConverter.FromNativeObject(coreArgsС);
            Assert.IsNotNull(certificate);
        }
    }
}
