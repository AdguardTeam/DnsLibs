using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Adguard.Dns.Api.DnsProxyServer.Callbacks;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.Api.DnsProxyServer.EventArgs;
using Adguard.Dns.Api.FilteringLogAction;
using Adguard.Dns.DnsProxyServer;
using Adguard.Dns.Utils;
using AdGuard.Utils.Base.Interop;

namespace Adguard.Dns.Helpers
{
    // ReSharper disable once InconsistentNaming
    /// <summary>
    /// Helper class, which provides converting from the native objects (from AGDnsApi)
    /// to the managed objects and visa versa
    /// </summary>
    internal static class DnsApiConverter
    {
        #region Constants

        private static readonly Dictionary<AddressFamily, uint> ADDRESSES_FAMILY_LENGTH =
            new Dictionary<AddressFamily, uint>
            {
                {AddressFamily.InterNetwork, 4},
                {AddressFamily.InterNetworkV6, 16}
            };

        #endregion

        #region Dns server config

        #region ToNativeObject

        /// <summary>
        /// Converts the managed <see cref="dnsProxySettings"/>
        /// (<seealso cref="DnsProxySettings"/>) to the native <see cref="AGDnsApi.ag_dnsproxy_settings"/> object
        /// </summary>
        /// <param name="dnsProxySettings"><see cref="DnsProxySettings"/> instance to convert</param>
        /// <param name="allocatedPointers">List of pointers, which were allocated.
        /// Pointers, which will be referred to a newly allocated memory
        /// (within the process of marshaling the string to the pointer)
        /// will be added to this list.
        /// If this list is not specified (null),
        /// a new created pointer will not be added anywhere</param>
        /// The resulting pointer (<seealso cref="IntPtr"/>) must be freed
        /// with <see cref="MarshalUtils.SafeFreeHGlobal(IntPtr)"/>>
        /// <returns>An instance of <see cref="AGDnsApi.ag_dnsproxy_settings"/></returns>
        internal static AGDnsApi.ag_dnsproxy_settings ToNativeObject(
            DnsProxySettings dnsProxySettings,
            Queue<IntPtr> allocatedPointers)
        {
            MarshalUtils.ag_buffer upstreamsC = MarshalUtils.ListToAgList(
                dnsProxySettings.Upstreams,
                ToNativeObject,
                allocatedPointers);

            MarshalUtils.ag_buffer fallbacksC = MarshalUtils.ListToAgList(
                dnsProxySettings.Fallbacks,
                ToNativeObject,
                allocatedPointers);

            MarshalUtils.ag_buffer fallbackDomains = MarshalUtils.ListToAgList(
                dnsProxySettings.FallbackDomains,
                MarshalUtils.StringToPtr,
                allocatedPointers);

            IntPtr pDns64C = IntPtr.Zero;
            if (dnsProxySettings.Dns64 != null)
            {
                AGDnsApi.ag_dns64_settings dns64C =
                    ToNativeObject(dnsProxySettings.Dns64, allocatedPointers);
                pDns64C = MarshalUtils.StructureToPtr(dns64C, allocatedPointers);
            }

            AGDnsApi.ag_filter_engine_params filterEngineParamsC =
                ToNativeObject(dnsProxySettings.EngineParams, allocatedPointers);
            MarshalUtils.ag_buffer listenersC = MarshalUtils.ListToAgList(
                dnsProxySettings.Listeners,
                ToNativeObject,
                allocatedPointers);

            IntPtr pOutboundProxySessionC = IntPtr.Zero;
            if (dnsProxySettings.OutboundProxySettings != null)
            {
                AGDnsApi.ag_outbound_proxy_settings outboundProxySettingsC =
                    ToNativeObject(dnsProxySettings.OutboundProxySettings, allocatedPointers);
                pOutboundProxySessionC = MarshalUtils.StructureToPtr(outboundProxySettingsC, allocatedPointers);
            }

            AGDnsApi.ag_dnsproxy_settings dnsProxySettingsC = new AGDnsApi.ag_dnsproxy_settings
            {
                upstreams = upstreamsC,
                fallbacks = fallbacksC,
                pDns64 = pDns64C,
                FilterParams = filterEngineParamsC,
                listeners = listenersC,
                outbound_proxy = pOutboundProxySessionC,
                fallbackDomains = fallbackDomains,
            };

            MarshalUtils.CopyPropertiesToFields(dnsProxySettings, ref dnsProxySettingsC);
            MarshalUtils.AllStringsToPtrs(dnsProxySettings, ref dnsProxySettingsC, allocatedPointers);
            return dnsProxySettingsC;
        }

        private static AGDnsApi.ag_filter_engine_params ToNativeObject(
            EngineParams engineParams,
            Queue<IntPtr> allocatedPointers)
        {
            MarshalUtils.ag_buffer filterParamsC = MarshalUtils.ListToAgList(
                engineParams.FilterParams,
                ToNativeObject,
                allocatedPointers);
            AGDnsApi.ag_filter_engine_params filterEngineParamsC = new AGDnsApi.ag_filter_engine_params
            {
                filters = filterParamsC
            };

            return filterEngineParamsC;
        }

        private static AGDnsApi.ag_outbound_proxy_settings ToNativeObject(
            OutboundProxySettings outboundProxySettings,
            Queue<IntPtr> allocatedPointers)
        {
            IntPtr pOutboundProxyAuthInfoC = IntPtr.Zero;
            if (outboundProxySettings.AuthInfo != null)
            {
                AGDnsApi.ag_outbound_proxy_auth_info outboundProxyAuthInfoC = ToNativeObject(
                    outboundProxySettings.AuthInfo,
                    allocatedPointers);
                pOutboundProxyAuthInfoC = MarshalUtils.StructureToPtr(
                    outboundProxyAuthInfoC,
                    allocatedPointers);
            }

            MarshalUtils.ag_buffer bootstrapC = MarshalUtils.ListToAgList(
                outboundProxySettings.Bootstrap,
                MarshalUtils.StringToPtr,
                allocatedPointers);

            AGDnsApi.ag_outbound_proxy_settings outboundProxySettingsC =
                new AGDnsApi.ag_outbound_proxy_settings
            {
                auth_info = pOutboundProxyAuthInfoC,
                bootstrap = bootstrapC
            };

            MarshalUtils.CopyPropertiesToFields(outboundProxySettings, ref outboundProxySettingsC);
            MarshalUtils.AllStringsToPtrs(
                outboundProxySettings,
                ref outboundProxySettingsC,
                allocatedPointers);

            return outboundProxySettingsC;
        }

        private static AGDnsApi.ag_outbound_proxy_auth_info ToNativeObject(
            OutboundProxyAuthInfo outboundProxyAuthInfo,
            Queue<IntPtr> allocatedPointers)
        {
            AGDnsApi.ag_outbound_proxy_auth_info outboundProxyAuthInfoC =
                new AGDnsApi.ag_outbound_proxy_auth_info();
            MarshalUtils.CopyPropertiesToFields(outboundProxyAuthInfo, ref outboundProxyAuthInfoC);
            MarshalUtils.AllStringsToPtrs(
                outboundProxyAuthInfo,
                ref outboundProxyAuthInfoC,
                allocatedPointers);
            return outboundProxyAuthInfoC;
        }

        private static AGDnsApi.ag_dns64_settings ToNativeObject(
            Dns64Settings dns64,
            Queue<IntPtr> allocatedPointers)
        {
            MarshalUtils.ag_buffer dns64upstreamsC = MarshalUtils.ListToAgList(
                dns64.Upstreams,
                ToNativeObject,
                allocatedPointers);

            AGDnsApi.ag_dns64_settings dns64C = new AGDnsApi.ag_dns64_settings
            {
                upstreams = dns64upstreamsC
            };

            MarshalUtils.CopyPropertiesToFields(dns64, ref dns64C);
            return dns64C;
        }

        /// <summary>
        /// Converts the managed <see cref="listenerSettings"/>
        /// (<seealso cref="ListenerSettings"/>) to the native <see cref="AGDnsApi.ag_listener_settings"/> object
        /// </summary>
        /// <param name="listenerSettings"><see cref="ListenerSettings"/> instance to convert</param>
        /// <param name="allocatedPointers">List of pointers, which were allocated.
        /// Pointers, which will be referred to a newly allocated memory
        /// (within the process of marshaling the string to the pointer)
        /// will be added to this list.
        /// If this list is not specified (null),
        /// a new created pointer will not be added anywhere</param>
        /// The resulting pointer (<seealso cref="IntPtr"/>) must be freed
        /// with <see cref="MarshalUtils.SafeFreeHGlobal(IntPtr)"/>>
        /// <returns>An instance of <see cref="AGDnsApi.ag_listener_settings"/></returns>
        private static AGDnsApi.ag_listener_settings ToNativeObject(
            ListenerSettings listenerSettings,
            Queue<IntPtr> allocatedPointers)
        {
            ushort port = (ushort) listenerSettings.EndPoint.Port;
            IntPtr address = MarshalUtils.StringToPtr(
                listenerSettings.EndPoint.Address.ToString(),
                allocatedPointers);
            AGDnsApi.ag_proxy_settings_overrides settingsOverridesC =
                ToNativeObject(
                    listenerSettings.ProxySettingsOverrides,
                    allocatedPointers);
            AGDnsApi.ag_listener_settings listenerSettingsC = new AGDnsApi.ag_listener_settings
            {
                address = address,
                port = port,
                settings_overrides = settingsOverridesC
            };

            MarshalUtils.CopyPropertiesToFields(listenerSettings, ref listenerSettingsC);
            return listenerSettingsC;
        }

        private static AGDnsApi.ag_proxy_settings_overrides ToNativeObject(
            ProxySettingsOverrides proxySettingsOverrides,
            Queue<IntPtr> allocatedPointers)
        {
            AGDnsApi.ag_proxy_settings_overrides proxySettingsOverridesC = 
                new AGDnsApi.ag_proxy_settings_overrides();
            if (proxySettingsOverrides.BlockEch.HasValue)
            {
                IntPtr pBlockEch = LocalMarshalUtils.WriteBoolToPtr(
                    proxySettingsOverrides.BlockEch.Value,
                    allocatedPointers);
                proxySettingsOverridesC.pBlock_ech = pBlockEch;
            }
            
            return proxySettingsOverridesC;
        }

        private static AGDnsApi.ag_filter_params ToNativeObject(
            FilterParams filterParams,
            Queue<IntPtr> allocatedPointers)
        {
            AGDnsApi.ag_filter_params filterParamsC = new AGDnsApi.ag_filter_params();
            MarshalUtils.CopyPropertiesToFields(filterParams, ref filterParamsC);
            MarshalUtils.AllStringsToPtrs(filterParams, ref filterParamsC, allocatedPointers);
            return filterParamsC;
        }

        internal static AGDnsApi.ag_upstream_options ToNativeObject(
            UpstreamOptions upstreamOptions,
            Queue<IntPtr> allocatedPointers)
        {
            MarshalUtils.ag_buffer bootstrapC = MarshalUtils.ListToAgList(
                upstreamOptions.Bootstrap,
                MarshalUtils.StringToPtr,
                allocatedPointers);

            MarshalUtils.ag_buffer fingerprintsC = MarshalUtils.ListToAgList(
                upstreamOptions.Fingerprints,
                MarshalUtils.StringToPtr,
                allocatedPointers);

            byte[] addressBytes = null;
            if (upstreamOptions.ResolvedIpAddress!= null)
            {
                addressBytes = upstreamOptions.ResolvedIpAddress.GetAddressBytes();
            }

            MarshalUtils.ag_buffer addressC = MarshalUtils.BytesToAgBuffer(addressBytes);
            allocatedPointers?.Enqueue(addressC.data);
            AGDnsApi.ag_upstream_options upstreamOptionsC = new AGDnsApi.ag_upstream_options
            {
                bootstrap = bootstrapC,
                resolved_ip_address = addressC,
                fingerprints = fingerprintsC
            };

            MarshalUtils.CopyPropertiesToFields(upstreamOptions, ref upstreamOptionsC);
            MarshalUtils.AllStringsToPtrs(upstreamOptions, ref upstreamOptionsC, allocatedPointers);
            return upstreamOptionsC;
        }

        internal static AGDnsApi.AGDnsProxyServerCallbacks ToNativeObject(
            IDnsProxyServerCallbackConfiguration dnsProxyServerCallbackConfiguration,
            IDnsProxyServer proxyServer)
        {
            CertificateVerificationCallback certificateVerificationCallback = new CertificateVerificationCallback();
            ProxyServerCallbacksAdapter proxyServerCallbacksAdapter =
                new ProxyServerCallbacksAdapter(
                    dnsProxyServerCallbackConfiguration,
                    certificateVerificationCallback,
                    proxyServer);
            return proxyServerCallbacksAdapter.DnsProxyServerCallbacks;
        }

        public static AGDnsApi.ag_dns_stamp ToNativeObject(
            DnsStamp dnsStamp,
            Queue<IntPtr> allocatedPointers)
        {
            MarshalUtils.ag_buffer publicKeyC = MarshalUtils.BytesToAgBuffer(dnsStamp.PublicKey);
            MarshalUtils.ag_buffer hashesC = MarshalUtils.ListToAgList(
                dnsStamp.Hashes,
                (x, y) => MarshalUtils.BytesToAgBuffer(x),
                allocatedPointers);
            AGDnsApi.ag_dns_stamp dnsStampC = new AGDnsApi.ag_dns_stamp
            {
                ProtoType = dnsStamp.ProtoType,
                ServerAddress = MarshalUtils.StringToPtr(dnsStamp.ServerAddress),
                ProviderName = MarshalUtils.StringToPtr(dnsStamp.ProviderName),
                DoHPath = MarshalUtils.StringToPtr(dnsStamp.DoHPath),
                server_public_key = publicKeyC,
                hashes = hashesC,
                Properties = dnsStamp.Properties
            };
            return dnsStampC;
        }

        #endregion

        #region FromNativeObject

        internal static DnsProxySettings FromNativeObject(
            AGDnsApi.ag_dnsproxy_settings dnsProxySettingsC)
        {
            List<UpstreamOptions> upstreams = MarshalUtils.AgListToList<AGDnsApi.ag_upstream_options, UpstreamOptions>(
                dnsProxySettingsC.upstreams,
                FromNativeObject);

            List<UpstreamOptions> fallbacks = MarshalUtils.AgListToList<AGDnsApi.ag_upstream_options, UpstreamOptions>(
                dnsProxySettingsC.fallbacks,
                FromNativeObject);

            List<string> fallbackDomains = MarshalUtils.AgListToList<IntPtr, string>(
                dnsProxySettingsC.fallbackDomains,
                MarshalUtils.PtrToString);

            Dns64Settings dns64 = MarshalUtils.PtrToClass<Dns64Settings, AGDnsApi.ag_dns64_settings>(
                dnsProxySettingsC.pDns64,
                FromNativeObject);
            EngineParams engineParams = FromNativeObject(dnsProxySettingsC.FilterParams);
            List<ListenerSettings> listeners =
                MarshalUtils.AgListToList<AGDnsApi.ag_listener_settings, ListenerSettings>(
                    dnsProxySettingsC.listeners,
                    FromNativeObject);
            OutboundProxySettings outboundProxySettings =
                MarshalUtils.PtrToClass<OutboundProxySettings, AGDnsApi.ag_outbound_proxy_settings>(
                    dnsProxySettingsC.outbound_proxy,
                    FromNativeObject);

            DnsProxySettings dnsProxySettings = new DnsProxySettings
            {
                Upstreams = upstreams,
                Fallbacks = fallbacks,
                FallbackDomains = fallbackDomains,
                Dns64 = dns64,
                EngineParams = engineParams,
                Listeners = listeners,
                OutboundProxySettings = outboundProxySettings
            };

            MarshalUtils.CopyFieldsToProperties(dnsProxySettingsC, dnsProxySettings);
            MarshalUtils.AllPtrsToStrings(dnsProxySettingsC, dnsProxySettings);
            return dnsProxySettings;
        }

        private static Dns64Settings FromNativeObject(AGDnsApi.ag_dns64_settings dns64C)
        {
            List<UpstreamOptions> dns64Upstreams =
                MarshalUtils.AgListToList<AGDnsApi.ag_upstream_options, UpstreamOptions>(
                    dns64C.upstreams,
                    FromNativeObject);

            Dns64Settings dns64 = new Dns64Settings
            {
                Upstreams = dns64Upstreams
            };

            MarshalUtils.CopyFieldsToProperties(dns64C, dns64);
            return dns64;
        }

        private static OutboundProxySettings FromNativeObject(
            AGDnsApi.ag_outbound_proxy_settings outboundProxySettingsC)
        {
            OutboundProxyAuthInfo authInfo =
                MarshalUtils.PtrToClass<OutboundProxyAuthInfo, AGDnsApi.ag_outbound_proxy_auth_info>(
                    outboundProxySettingsC.auth_info,
                    FromNativeObject);

            List<string> bootstrap = MarshalUtils.AgListToList<IntPtr, string>(
                outboundProxySettingsC.bootstrap,
                MarshalUtils.PtrToString);
            OutboundProxySettings outboundProxySettings = new OutboundProxySettings
            {
                AuthInfo = authInfo,
                Bootstrap = bootstrap
            };

            MarshalUtils.CopyFieldsToProperties(outboundProxySettingsC, outboundProxySettings);
            MarshalUtils.AllPtrsToStrings(outboundProxySettingsC, outboundProxySettings);
            return outboundProxySettings;
        }

        private static OutboundProxyAuthInfo FromNativeObject(
            AGDnsApi.ag_outbound_proxy_auth_info outboundProxyAuthInfoC)
        {
            OutboundProxyAuthInfo outboundProxyAuthInfo = new OutboundProxyAuthInfo();
            MarshalUtils.CopyFieldsToProperties(outboundProxyAuthInfoC, outboundProxyAuthInfo);
            MarshalUtils.AllPtrsToStrings(outboundProxyAuthInfoC, outboundProxyAuthInfo);
            return outboundProxyAuthInfo;
        }

        private static ListenerSettings FromNativeObject(AGDnsApi.ag_listener_settings listenerSettingsC)
        {
            IPAddress address = CreateIpAddress(listenerSettingsC.address);
            int port = listenerSettingsC.port;
            IPEndPoint endPoint = CreateEndPoint(address, port);
            ProxySettingsOverrides proxySettingsOverrides = 
                FromNativeObject(listenerSettingsC.settings_overrides);
            ListenerSettings listenerSettings = new ListenerSettings
            {
                EndPoint = endPoint,
                ProxySettingsOverrides = proxySettingsOverrides
            };

            MarshalUtils.CopyFieldsToProperties(listenerSettingsC, listenerSettings);
            return listenerSettings;
        }
        
        private static ProxySettingsOverrides FromNativeObject(
            AGDnsApi.ag_proxy_settings_overrides proxySettingsOverridesC)
        {
            ProxySettingsOverrides proxySettingsOverrides = new ProxySettingsOverrides();
            if (proxySettingsOverridesC.pBlock_ech != IntPtr.Zero)
            {
                bool blockEch = LocalMarshalUtils.ReadBoolFromPtr(proxySettingsOverridesC.pBlock_ech);
                proxySettingsOverrides.BlockEch = blockEch;
            }
            
            return proxySettingsOverrides;
        }

        private static EngineParams FromNativeObject(AGDnsApi.ag_filter_engine_params filterEngineParamsC)
        {
            List<FilterParams> filterParams =
                MarshalUtils.AgListToList<AGDnsApi.ag_filter_params, FilterParams>(
                filterEngineParamsC.filters,
                FromNativeObject);

            EngineParams engineParams = new EngineParams
            {
                FilterParams = filterParams
            };

            return engineParams;
        }

        private static FilterParams FromNativeObject(AGDnsApi.ag_filter_params filterParamsC)
        {
            FilterParams filterParams = new FilterParams();
            MarshalUtils.AllPtrsToStrings(filterParamsC, filterParams);
            MarshalUtils.CopyFieldsToProperties(filterParamsC, filterParams);
            return filterParams;
        }

        private static UpstreamOptions FromNativeObject(AGDnsApi.ag_upstream_options upstreamOptionsC)
        {
            List<string> bootstrap = MarshalUtils.AgListToList<IntPtr, string>(
                upstreamOptionsC.bootstrap,
                MarshalUtils.PtrToString);
            
            List<string> fingerprints = MarshalUtils.AgListToList<IntPtr, string>(
                upstreamOptionsC.fingerprints,
                MarshalUtils.PtrToString);

            IPAddress serverAddress = CreateIpAddress(upstreamOptionsC.resolved_ip_address);
            UpstreamOptions upstreamOptions = new UpstreamOptions
            {
                Bootstrap = bootstrap,
                Fingerprints = fingerprints,
                ResolvedIpAddress = serverAddress
            };

            MarshalUtils.CopyFieldsToProperties(upstreamOptionsC, upstreamOptions);
            MarshalUtils.AllPtrsToStrings(upstreamOptionsC, upstreamOptions);
            return upstreamOptions;
        }

        internal static DnsStamp FromNativeObject(AGDnsApi.ag_dns_stamp agDnsStampC)
        {
            byte[] publicKey = MarshalUtils.AgBufferToBytes(agDnsStampC.server_public_key);
            List<byte[]> hashes = MarshalUtils.AgListToList<MarshalUtils.ag_buffer, byte[]>(
                agDnsStampC.hashes,
                MarshalUtils.AgBufferToBytes);
            DnsStamp dnsStamp = new DnsStamp
            {
                PublicKey = publicKey,
                Hashes = hashes
            };
            MarshalUtils.AllPtrsToStrings(agDnsStampC, dnsStamp);
            MarshalUtils.CopyFieldsToProperties(agDnsStampC, dnsStamp);
            return dnsStamp;
        }

        #endregion

        #endregion

        #region Server event arguments

        internal static CertificateVerificationEventArgs FromNativeObject(
            AGDnsApi.ag_certificate_verification_event coreArgsC)
        {
            byte[] certBytes = MarshalUtils.AgBufferToBytes(coreArgsC.pCertificate);
            List<byte[]> chain = MarshalUtils.AgListToList<MarshalUtils.ag_buffer, byte[]>(
                coreArgsC.chain,
                MarshalUtils.AgBufferToBytes);
            CertificateVerificationEventArgs eventArgs = new CertificateVerificationEventArgs
            {
                Certificate = certBytes,
                Chain = chain
            };

            return eventArgs;
        }

        internal static DnsRequestProcessedEventArgs FromNativeObject(
            AGDnsApi.ag_dns_request_processed_event coreArgsC)
        {
            List<string> rules = MarshalUtils.AgListToList<IntPtr, string>(
                coreArgsC.rules,
                MarshalUtils.PtrToString);
            List<int> filterListIds = MarshalUtils.AgListToList<int, int>(
                coreArgsC.filter_list_ids,
                filterId => filterId);

            long? upstreamId = MarshalUtils.ReadNullableInt(coreArgsC.pUpstreamId);
            DnsRequestProcessedEventArgs eventArgs = new DnsRequestProcessedEventArgs
            {
                UpstreamId = upstreamId.HasValue ? (int?)upstreamId.Value : null,
                Rules = rules,
                FilterListIds = filterListIds
            };

            MarshalUtils.AllPtrsToStrings(coreArgsC, eventArgs);
            MarshalUtils.CopyFieldsToProperties(coreArgsC, eventArgs);
            return eventArgs;
        }

        internal static AGDnsApi.ag_dns_request_processed_event ToNativeObject(
            DnsRequestProcessedEventArgs dnsRequestProcessedEventArgs,
            Queue<IntPtr> allocatedPointers)
        {
            MarshalUtils.ag_buffer rules = MarshalUtils.ListToAgList(
                dnsRequestProcessedEventArgs.Rules,
                MarshalUtils.StringToPtr,
                allocatedPointers);
            MarshalUtils.ag_buffer filterListIds = MarshalUtils.ListToAgList(
                dnsRequestProcessedEventArgs.FilterListIds,
                ToNativeObject,
                allocatedPointers);
            IntPtr pUpstreamId = dnsRequestProcessedEventArgs.UpstreamId.HasValue 
                ? ToNativeObject(dnsRequestProcessedEventArgs.UpstreamId.Value, allocatedPointers) 
                : IntPtr.Zero;
            AGDnsApi.ag_dns_request_processed_event argsC = new AGDnsApi.ag_dns_request_processed_event
            {
                rules = rules,
                filter_list_ids = filterListIds,
                pUpstreamId = pUpstreamId
            };

            MarshalUtils.AllStringsToPtrs(dnsRequestProcessedEventArgs, ref argsC, allocatedPointers);
            MarshalUtils.CopyPropertiesToFields(dnsRequestProcessedEventArgs, ref argsC);
            return argsC;
        }

        private static IntPtr ToNativeObject(int value, Queue<IntPtr> allocatedPointers)
        {
            IntPtr ptr = Marshal.AllocHGlobal(sizeof(int));
            Marshal.WriteInt32(ptr, value);
            allocatedPointers.Enqueue(ptr);
            return ptr;
        }

        internal static AGDnsApi.cbd_onCertificateVerification ToNativeObject(
            ICertificateVerificationCallback certificateVerificationCallback)
        {
            TestUpstreamCallbacksAdapter testUpstreamCallbacksAdapter =
                new TestUpstreamCallbacksAdapter(certificateVerificationCallback);
            return testUpstreamCallbacksAdapter.OnTestUpstreamCallback;
        }

        internal static AGDnsApi.ag_dns_message_info ToNativeObject(DnsMessageInfo dnsMessageInfo)
        {
	        AGDnsApi.ag_dns_message_info converted = new AGDnsApi.ag_dns_message_info
	        {
		        transparent = dnsMessageInfo.Transparent
	        };

	        return converted;
        }

		#endregion

		#region Helper methods

		/// <summary>
		/// Creates the <see cref="IPAddress"/> object from the specified pointer to address byte array,
		/// addressLength
		/// </summary>
		/// <param name="agAddress">The <see cref="MarshalUtils.ag_buffer"/> instance</param>
		/// <exception cref="ArgumentException">Thrown,
		/// if passed <see cref="MarshalUtils.ag_buffer.size"/> is not acceptable</exception>
		/// <returns><see cref="IPAddress"/> object or null if the pointer is null or addressLength is zero</returns>
		private static IPAddress CreateIpAddress(MarshalUtils.ag_buffer agAddress)
        {
            if (agAddress.data == IntPtr.Zero ||
                agAddress.size == 0)
            {
                return null;
            }

            byte[] address = new byte[agAddress.size];
            Marshal.Copy(agAddress.data, address, 0, (int)agAddress.size);
            AddressFamily addressFamily = ADDRESSES_FAMILY_LENGTH
                .FirstOrDefault(addressPair => addressPair.Value == agAddress.size).Key;

            if (addressFamily == AddressFamily.Unknown)
            {
                string message = "Cannot create IPAddress because of unacceptable address length value";
                throw new ArgumentException(message, "agAddress");
            }

            IPAddress ipAddress = new IPAddress(address);
            return ipAddress;
        }

        /// <summary>
        /// Creates the <see cref="IPAddress"/> object from the specified pointer to address string
        /// </summary>
        /// <param name="pAddress">The pointer to the address string
        /// (<seealso cref="IntPtr"/>)</param>
        /// <exception cref="ArgumentException">Thrown,
        /// if passed <see cref="MarshalUtils.ag_buffer.size"/> is not acceptable</exception>
        /// <returns><see cref="IPAddress"/> object or null if the pointer is null or addressLength is zero</returns>
        private static IPAddress CreateIpAddress(IntPtr pAddress)
        {
            if (pAddress == IntPtr.Zero)
            {
                return null;
            }

            string address = MarshalUtils.PtrToString(pAddress);
            IPAddress ipAddress = IPAddress.Parse(address);
            return ipAddress;
        }

        /// <summary>
        /// Creates the <see cref="IPEndPoint"/> object from the specified <see cref="address"/> and <see cref="port"/>
        /// </summary>
        /// <param name="address">Address
        /// <seealso cref="IPAddress"/><see cref="IPAddress"/> instance</param>
        /// <param name="port">Port</param>
        /// <returns><see cref="IPEndPoint"/> object or null if port is zero</returns>
        private static IPEndPoint CreateEndPoint(IPAddress address, int port)
        {
            if (port == 0)
            {
                return null;
            }

            IPEndPoint ipEndPoint = new IPEndPoint(address, port);
            return ipEndPoint;
        }

        #endregion

        #region Rules generation

        internal static FilteringLogAction FromNativeObject(AGDnsApi.ag_dns_filtering_log_action actionC)
        {
            List<string> ruleTemplates = MarshalUtils.AgListToList<IntPtr, string>(
                actionC.Templates, MarshalUtils.PtrToString);
            FilteringLogAction filteringLogAction = new FilteringLogAction
            {
                RuleTemplates = ruleTemplates
            };

            MarshalUtils.CopyFieldsToProperties(actionC, filteringLogAction);
            return filteringLogAction;
        }

        #endregion
    }
}
