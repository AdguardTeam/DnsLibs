﻿using System;
using System.Collections.Generic;
using System.Net;
using Adguard.Dns.Api.DnsProxyServer.Callbacks;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.Api.DnsProxyServer.EventArgs;
using Adguard.Dns.Api.FilteringLogAction;
using Adguard.Dns.DnsProxyServer;
using Adguard.Dns.Helpers;
using Adguard.Dns.Provider;
using Adguard.Dns.Tests.TestUtils;
using Adguard.Dns.Utils;
using AdGuard.Utils.Base.Collections;
using AdGuard.Utils.Base.Interop;
using NUnit.Framework;

namespace Adguard.Dns.Tests.Helpers
{
    [TestFixture]
    class TestDnsApiConverter
    {
	    private DnsLibsDllProvider m_DnsLibsDllProvider;

		[OneTimeSetUp]
	    public void SetUp()
	    {
		    m_DnsLibsDllProvider = (DnsLibsDllProvider)DnsLibsDllProvider.Instance;
	    }

        [OneTimeTearDown]
	    public void TearDown()
	    {
            m_DnsLibsDllProvider.Dispose();
	    }

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
                        Bootstrap = new List<string>(),
                        Fingerprints = new List<string>()
                    },
                    new UpstreamOptions
                    {
                        Id = 2,
                        Bootstrap = new List<string>(),
                        Fingerprints = new List<string>()
                    },
                    new UpstreamOptions
                    {
                        Id = 3,
                        Bootstrap = new List<string>
                        {
                            "bootStrapBegin",
                            "bootStrapEnd"
                        },
                        Fingerprints = new List<string>()
                        {
                            "fingerprintsBegin",
                            "fingerprintsEnd"
                        },
                    }
                },
                Fallbacks = new List<UpstreamOptions>()
                {
                    new UpstreamOptions
                    {
                        Bootstrap = new List<string>
                        {
                            "1.1.1.1",
                            "8.8.8.8",
                            "9.9.9.9"
                        },
                        Fingerprints = new List<string>()
                    }
                },
                BlockedResponseTtlSec = 64,
                Dns64 = new Dns64Settings
                {
                    Upstreams = new List<UpstreamOptions>
                    {
                        new UpstreamOptions
                        {
                            Bootstrap = new List<string>
                            {
                                "1.1.1.1",
                                "8.8.8.8",
                                "9.9.9.9"
                            },
                            Fingerprints = new List<string>()
                        }
                    }
                },
                EngineParams = new EngineParams
                {
                    FilterParams = new List<FilterParams>()
                },
                Listeners = new List<ListenerSettings>
                {
                    new ListenerSettings
                    {
                        EndPoint = new IPEndPoint(1234567, 9898),
                        ProxySettingsOverrides = new ProxySettingsOverrides
                        {
                            BlockEch = true
                        }
                    }
                },
                FallbackDomains = new List<string>
                {
                    "Test.com"
                },
                Ipv6Available = true,
                BlockIpv6 = true,
                AdblockRulesBlockingMode = AGDnsApi.ag_dnsproxy_blocking_mode.AGBM_ADDRESS,
                HostsRulesBlockingMode = AGDnsApi.ag_dnsproxy_blocking_mode.AGBM_ADDRESS,
                CustomBlockingIpv4 = "1.2.3.4",
                CustomBlockingIpv6 = "::AA",
                DnsCacheSize = 23,
                UpstreamTimeoutMs = 42,
                OptimisticCache = true,
                OutboundProxySettings = new OutboundProxySettings
                {
                    Protocol = AGDnsApi.ag_outbound_proxy_protocol.AGOPP_SOCKS5,
                    Address = "127.0.0.1",
                    AuthInfo = new OutboundProxyAuthInfo
                    {
                        Password = "123",
                        Username = "username"
                    },
                    Port = 6754,
                    Bootstrap = new List<string>
                    {
                        "https://94.140.14.14",
                        "https://94.140.15.15"
                    },
                    TrustAnyCertificate = true
                }
            };

            Queue<IntPtr> allocatedPointers = new Queue<IntPtr>();
            AGDnsApi.ag_dnsproxy_settings nativeDnsSettings =
                DnsApiConverter.ToNativeObject(dnsSettings, allocatedPointers);
            Assert.AreNotEqual(IntPtr.Zero, nativeDnsSettings.fallbacks.data);
            Assert.AreNotEqual(IntPtr.Zero, nativeDnsSettings.fallbackDomains.data);
            Assert.AreNotEqual(IntPtr.Zero, nativeDnsSettings.listeners.data);
            Assert.AreNotEqual(IntPtr.Zero, nativeDnsSettings.upstreams.data);
            Assert.AreEqual(nativeDnsSettings.BlockedResponseTtlSec, dnsSettings.BlockedResponseTtlSec);
            Assert.AreEqual(nativeDnsSettings.Ipv6Available, dnsSettings.Ipv6Available);
            Assert.AreEqual(nativeDnsSettings.BlockIpv6, dnsSettings.BlockIpv6);
            Assert.AreEqual(nativeDnsSettings.AdblockRulesBlockingMode, dnsSettings.AdblockRulesBlockingMode);
            Assert.AreEqual(nativeDnsSettings.HostsRulesBlockingMode, dnsSettings.HostsRulesBlockingMode);
            Assert.AreEqual(MarshalUtils.PtrToString(nativeDnsSettings.CustomBlockingIpv4), dnsSettings.CustomBlockingIpv4);
            Assert.AreEqual(MarshalUtils.PtrToString(nativeDnsSettings.CustomBlockingIpv6), dnsSettings.CustomBlockingIpv6);
            Assert.AreEqual(nativeDnsSettings.DnsCacheSize, dnsSettings.DnsCacheSize);
            Assert.AreEqual(nativeDnsSettings.UpstreamTimeoutMs, dnsSettings.UpstreamTimeoutMs);
            Assert.AreEqual(nativeDnsSettings.OptimisticCache, dnsSettings.OptimisticCache);

            DnsProxySettings dnsSettingsConverted =  DnsApiConverter.FromNativeObject(nativeDnsSettings);
            Assert.AreEqual(dnsSettings.FallbackDomains, dnsSettingsConverted.FallbackDomains);
            Assert.AreEqual( dnsSettings.BlockedResponseTtlSec, dnsSettingsConverted.BlockedResponseTtlSec);
            Assert.AreEqual( dnsSettings.CustomBlockingIpv4, dnsSettingsConverted.CustomBlockingIpv4);
            Assert.AreEqual( dnsSettings.CustomBlockingIpv6, dnsSettingsConverted.CustomBlockingIpv6);
            Assert.AreEqual( dnsSettings.AdblockRulesBlockingMode, dnsSettingsConverted.AdblockRulesBlockingMode);
            Assert.AreEqual(dnsSettings.HostsRulesBlockingMode, dnsSettingsConverted.HostsRulesBlockingMode);
            IEqualityComparer<UpstreamOptions> upstreamEqualityComparer = new TestUpstreamEqualityComparer();
            bool isUpstreamsEqual = CollectionUtils.CollectionsEquals(
                dnsSettingsConverted.Upstreams,
                dnsSettings.Upstreams,
                upstreamEqualityComparer);
            Assert.IsTrue(isUpstreamsEqual);
            bool isFallbacksEqual = CollectionUtils.CollectionsEquals(
                dnsSettingsConverted.Fallbacks,
                dnsSettings.Fallbacks,
                upstreamEqualityComparer);
            Assert.IsTrue(isFallbacksEqual);
            bool isDns64UpstreamsEqual = CollectionUtils.CollectionsEquals(
                dnsSettingsConverted.Dns64.Upstreams,
                dnsSettings.Dns64.Upstreams,
                upstreamEqualityComparer);
            Assert.IsTrue(isDns64UpstreamsEqual);
            Assert.AreEqual(
                dnsSettings.OutboundProxySettings.Protocol,
                dnsSettingsConverted.OutboundProxySettings.Protocol);
            Assert.AreEqual(
                dnsSettings.OutboundProxySettings.Address,
                dnsSettingsConverted.OutboundProxySettings.Address);
            Assert.AreEqual(
                dnsSettings.OutboundProxySettings.AuthInfo.Password,
                dnsSettingsConverted.OutboundProxySettings.AuthInfo.Password);
            Assert.AreEqual(
                dnsSettings.OutboundProxySettings.AuthInfo.Username,
                dnsSettingsConverted.OutboundProxySettings.AuthInfo.Username);
            Assert.AreEqual(
                dnsSettings.OutboundProxySettings.Port,
                dnsSettingsConverted.OutboundProxySettings.Port);
            bool isBootstrapEquals = CollectionUtils.CollectionsEquals(
                dnsSettings.OutboundProxySettings.Bootstrap,
                dnsSettingsConverted.OutboundProxySettings.Bootstrap);
            Assert.IsTrue(isBootstrapEquals);
            Assert.AreEqual(
                dnsSettings.OutboundProxySettings.TrustAnyCertificate,
                dnsSettingsConverted.OutboundProxySettings.TrustAnyCertificate);
            Assert.AreEqual(dnsSettings.Listeners.Count,
	            dnsSettingsConverted.Listeners.Count);
            Assert.AreEqual(dnsSettings.Listeners[0].EndPoint,
	            dnsSettingsConverted.Listeners[0].EndPoint);
            Assert.AreEqual(dnsSettings.Listeners[0].ProxySettingsOverrides.BlockEch, 
                dnsSettingsConverted.Listeners[0].ProxySettingsOverrides.BlockEch);

        }

        [Test]
        public void TestDnsProxyServerConverter()
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
                ProtoType = AGDnsApi.ag_stamp_proto_type.DOH,
                ServerAddress = "addressTest",
                ProviderName = "Nametest",
                DoHPath = "DoHPathTest",
                Hashes = new List<byte[]>
                {
                    new byte[] {12, 34, 15},
                    new byte[] {10, 8, 16, 3}
                },
                Properties = AGDnsApi.ag_server_informal_properties.AGSIP_NO_LOG
            };
            Queue<IntPtr> allocatedPointers = new Queue<IntPtr>();
            AGDnsApi.ag_dns_stamp stampNative = DnsApiConverter.ToNativeObject(dnsStamp, allocatedPointers);
            string address = MarshalUtils.PtrToString(stampNative.ServerAddress);
            Assert.AreEqual(address, dnsStamp.ServerAddress);

            DnsStamp dnsStampConverted = DnsApiConverter.FromNativeObject(stampNative);
            Assert.AreEqual(dnsStamp.ServerAddress, dnsStampConverted.ServerAddress);
            Assert.AreEqual(dnsStamp.Hashes.Count, dnsStampConverted.Hashes.Count);
            for (int i = 0; i < dnsStamp.Hashes.Count; i++)
            {
                Assert.IsTrue(CollectionUtils.CollectionsEquals(dnsStamp.Hashes[i], dnsStampConverted.Hashes[i]));
            }
            Assert.AreEqual(dnsStamp.Hashes.Capacity, dnsStampConverted.Hashes.Capacity);
            Assert.AreEqual(dnsStamp.Properties, dnsStampConverted.Properties);
            Assert.AreEqual(dnsStamp.DoHPath, dnsStampConverted.DoHPath);
            Assert.AreEqual(dnsStamp.ProtoType, dnsStampConverted.ProtoType);
            Assert.AreEqual(dnsStamp.ProviderName, dnsStampConverted.ProviderName);
        }

        [Test]
        public void TestDnsRequestProcessedConverter()
        {
            AGDnsApi.ag_dns_request_processed_event dnsRequestNative = new AGDnsApi.ag_dns_request_processed_event();
            DnsRequestProcessedEventArgs dnsRequest = DnsApiConverter.FromNativeObject(dnsRequestNative);
            Assert.NotNull(dnsRequest);
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
            AGDnsApi.ag_certificate_verification_event coreArgsC = new AGDnsApi.ag_certificate_verification_event();
            CertificateVerificationEventArgs certificate = DnsApiConverter.FromNativeObject(coreArgsC);
            Assert.NotNull(certificate);
        }

        [Test]
        public void TestUpstreamOptionsConverter()
        {
	        Queue<IntPtr> allocatedPointers = null;
	        try
	        {
		        allocatedPointers = new Queue<IntPtr>();
		        UpstreamOptions upstreamOptions = new UpstreamOptions
		        {
			        Bootstrap = new List<string>(),
			        Fingerprints = new List<string>(),
			        Address = "8.8.8.8:53",
		        };

		        AGDnsApi.ag_upstream_options upstreamOptionsC = DnsApiConverter.ToNativeObject(upstreamOptions, allocatedPointers);
                Assert.NotNull(upstreamOptionsC);
                Assert.AreEqual(upstreamOptions.Address, 
	                MarshalUtils.PtrToString(upstreamOptionsC.Address));
	        }
	        finally
	        {
		        MarshalUtils.SafeFreeHGlobal(allocatedPointers);
	        }
        }

        [Test]
        public void TestFilteringLogActionConverter()
        {
	        AGDnsApi.ag_dns_filtering_log_action actionC = new AGDnsApi.ag_dns_filtering_log_action
	        {
		        AllowedOptions = AGDnsApi.ag_rule_generation_options.AGRGO_IMPORTANT,
		        RequiredOptions = AGDnsApi.ag_rule_generation_options.AGRGO_IMPORTANT,
                IsBlocking = false,
                Templates = new MarshalUtils.ag_buffer()
            };

	        FilteringLogAction filteringLog = DnsApiConverter.FromNativeObject(actionC);
            Assert.NotNull(filteringLog);
            Assert.AreEqual(actionC.AllowedOptions, filteringLog.AllowedOptions);
            Assert.AreEqual(actionC.RequiredOptions, filteringLog.RequiredOptions);
            Assert.AreEqual(actionC.IsBlocking, filteringLog.IsBlocking);
        }
    }
}