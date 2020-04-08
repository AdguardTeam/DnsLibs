using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Adguard.Dns.Api.DnsProxyServer.Callbacks;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.Api.DnsProxyServer.EventArgs;
using Adguard.Dns.DnsProxyServer;
using Adguard.Dns.Utils;

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
            AGDnsApi.ag_list upstreamsC = MarshalUtils.ListToAgList(
                dnsProxySettings.Upstreams,
                ToNativeObject,
                allocatedPointers);
            
            AGDnsApi.ag_list fallbacksC = MarshalUtils.ListToAgList(
                dnsProxySettings.Fallbacks,
                ToNativeObject,
                allocatedPointers);

            AGDnsApi.ag_dns64_settings dns64C = ToNativeObject(dnsProxySettings.Dns64, allocatedPointers);
            IntPtr pDns64C = MarshalUtils.StructureToPtr(dns64C, allocatedPointers);
            AGDnsApi.ag_engine_params engineParamsC = ToNativeObject(dnsProxySettings.EngineParams, allocatedPointers);
            AGDnsApi.ag_list listenersC = MarshalUtils.ListToAgList(
                dnsProxySettings.Listeners,
                ToNativeObject,
                allocatedPointers);

            AGDnsApi.ag_dnsproxy_settings dnsProxySettingsC = new AGDnsApi.ag_dnsproxy_settings
            {
                upstreams = upstreamsC,
                fallbacks = fallbacksC,
                pDns64 = pDns64C,
                engine_params = engineParamsC,
                listeners = listenersC,
            };
            
            MarshalUtils.CopyPropertiesToFields(dnsProxySettings, ref dnsProxySettingsC);
            MarshalUtils.AllStringsToPtrs(dnsProxySettings, ref dnsProxySettingsC, allocatedPointers);
            return dnsProxySettingsC;
        }
                
        private static AGDnsApi.ag_engine_params ToNativeObject(
            EngineParams engineParams, 
            Queue<IntPtr> allocatedPointers)
        {
            List<KeyValuePair<uint, string>> filterParams = engineParams.FilterParams.ToList();
            AGDnsApi.ag_list filterParamsC = MarshalUtils.ListToAgList(
                filterParams,
                ToNativeObject,
                allocatedPointers);
            AGDnsApi.ag_engine_params engineParamsC = new AGDnsApi.ag_engine_params
            {
                filters = filterParamsC
            };
            
            return engineParamsC;
        }

        private static AGDnsApi.ag_dns64_settings ToNativeObject(
            Dns64Settings dns64, 
            Queue<IntPtr> allocatedPointers)
        {
            AGDnsApi.ag_list dns64upstreamsC = MarshalUtils.ListToAgList(
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
            uint port = (uint) listenerSettings.EndPoint.Port;
            byte[] addressBytes = listenerSettings.EndPoint.Address.GetAddressBytes();
            AGDnsApi.ag_buffer addressC = MarshalUtils.BytesToAgBuffer(addressBytes, allocatedPointers);
            AGDnsApi.ag_listener_settings listenerSettingsC = new AGDnsApi.ag_listener_settings
            {
                address = addressC,
                port = port
            };
            
            MarshalUtils.CopyPropertiesToFields(listenerSettings, ref listenerSettingsC);
            return listenerSettingsC;
        }

        private static AGDnsApi.ag_filter_params ToNativeObject(
            KeyValuePair<uint, string> filterParams, 
            Queue<IntPtr> allocatedPointers)
        {
            AGDnsApi.ag_filter_params filterParamsC = new AGDnsApi.ag_filter_params
            {
                id = filterParams.Key,
                path = MarshalUtils.StringToPtr(filterParams.Value)
            };

            return filterParamsC;
        }

        internal static AGDnsApi.ag_upstream_options ToNativeObject(
            UpstreamOptions upstreamOptions, 
            Queue<IntPtr> allocatedPointers)
        {
            AGDnsApi.ag_list bootstrapC = MarshalUtils.ListToAgList(
                upstreamOptions.Bootstrap,
                MarshalUtils.StringToPtr,
                allocatedPointers);

            byte[] addressBytes = null;
            if (upstreamOptions.ServerAddress!= null)
            {
                addressBytes = upstreamOptions.ServerAddress.GetAddressBytes();
            }
            
            AGDnsApi.ag_buffer addressC = MarshalUtils.BytesToAgBuffer(addressBytes, allocatedPointers);
            AGDnsApi.ag_upstream_options upstreamOptionsC = new AGDnsApi.ag_upstream_options
            {
                bootstrap = bootstrapC,
                resolved_server_ip = addressC
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

            Dns64Settings dns64 = FromNativeObject(dnsProxySettingsC.pDns64);
            EngineParams engineParams = FromNativeObject(dnsProxySettingsC.engine_params);
            List<ListenerSettings> listeners = 
                MarshalUtils.AgListToList<AGDnsApi.ag_listener_settings, ListenerSettings>(
                    dnsProxySettingsC.listeners,
                    FromNativeObject);
            DnsProxySettings dnsProxySettings = new DnsProxySettings
            {
                Upstreams = upstreams,
                Fallbacks = fallbacks,
                Dns64 = dns64,
                EngineParams = engineParams,
                Listeners = listeners,
            };
            
            MarshalUtils.CopyFieldsToProperties(dnsProxySettingsC, dnsProxySettings);
            MarshalUtils.AllPtrsToStrings(dnsProxySettingsC, dnsProxySettings);
            return dnsProxySettings;
        }

        private static Dns64Settings FromNativeObject(IntPtr pDns64C)
        {
            AGDnsApi.ag_dns64_settings dns64C = MarshalUtils.PtrToStructure<AGDnsApi.ag_dns64_settings>(pDns64C);
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

        private static ListenerSettings FromNativeObject(AGDnsApi.ag_listener_settings listenerSettingsC)
        {
            IPAddress address = CreateIpAddress(listenerSettingsC.address);
            int port = (int) listenerSettingsC.port;
            IPEndPoint endPoint = CreateEndPoint(address, port);
            ListenerSettings listenerSettings = new ListenerSettings
            {
                EndPoint = endPoint
            };
            
            MarshalUtils.CopyFieldsToProperties(listenerSettingsC, listenerSettings);
            return listenerSettings;
        }

        private static EngineParams FromNativeObject(AGDnsApi.ag_engine_params engineParamsC)
        {
            List<KeyValuePair<uint, string>> filterParamsList = 
                MarshalUtils.AgListToList<AGDnsApi.ag_filter_params, KeyValuePair<uint, string>>(
                engineParamsC.filters,
                FromNativeObject);
            
            Dictionary<uint, string> filterParams = new Dictionary<uint, string>();
            foreach (KeyValuePair<uint, string> filterParam in filterParamsList)
            {
                if (filterParams.ContainsKey(filterParam.Key))
                {
                    string newValue = string.Format("{0}, {1}",
                        filterParams[filterParam.Key],
                        filterParam.Value);
                    filterParams[filterParam.Key] = newValue;
                    continue;
                }

                filterParams[filterParam.Key] = filterParam.Value;
            }

            EngineParams engineParams = new EngineParams
            {
                FilterParams = filterParams
            };
            
            return engineParams;
        }

        private static KeyValuePair<uint, string> FromNativeObject(AGDnsApi.ag_filter_params filterParamsC)
        {
            string path = MarshalUtils.PtrToString(filterParamsC.path);
            KeyValuePair<uint, string> filterParams = new KeyValuePair<uint, string>(filterParamsC.id, path);
            return filterParams;
        }

        private static UpstreamOptions FromNativeObject(AGDnsApi.ag_upstream_options upstreamOptionsC)
        {
            List<string> bootstrap = MarshalUtils.AgListToList<IntPtr, string>(
                upstreamOptionsC.bootstrap,
                MarshalUtils.PtrToString);

            IPAddress serverAddress = CreateIpAddress(upstreamOptionsC.resolved_server_ip);
            UpstreamOptions upstreamOptions = new UpstreamOptions
            {
                Bootstrap = bootstrap,
                ServerAddress = serverAddress
            };
            
            MarshalUtils.CopyFieldsToProperties(upstreamOptionsC, upstreamOptions);
            MarshalUtils.AllPtrsToStrings(upstreamOptionsC, upstreamOptions);
            return upstreamOptions;
        }

        internal static DnsStamp FromNativeObject(AGDnsApi.ag_dns_stamp agDnsStampC)
        {
            DnsStamp dnsStamp = new DnsStamp();
            MarshalUtils.AllPtrsToStrings(agDnsStampC, dnsStamp);
            MarshalUtils.CopyFieldsToProperties(agDnsStampC, dnsStamp);
            return dnsStamp;
        }

        #endregion

        #endregion

        #region Server event arguments
        
        internal static CertificateVerificationEventArgs FromNativeObject(
            AGDnsApi.ag_certificate_verification_event coreArgsС)
        {
            byte[] certBytes = MarshalUtils.AgBufferToBytes(coreArgsС.pCertificate);
            List<byte[]> chain = MarshalUtils.AgListToList<AGDnsApi.ag_buffer, byte[]>(
                coreArgsС.chain,
                MarshalUtils.AgBufferToBytes);
            CertificateVerificationEventArgs eventArgs = new CertificateVerificationEventArgs
            {
                Certificate = certBytes,
                Chain = chain
            };

            return eventArgs;
        }

        internal static DnsRequestProcessedEventArgs FromNativeObject(
            AGDnsApi.ag_dns_request_processed_event coreArgsС)
        {
            List<string> rules = MarshalUtils.AgListToList<IntPtr, string>(
                coreArgsС.rules,
                MarshalUtils.PtrToString);
            
            List<int> filterListIds = MarshalUtils.AgListToList<IntPtr, int>(
                coreArgsС.filter_list_ids,
                MarshalUtils.PtrToInt);

            DnsRequestProcessedEventArgs eventArgs = new DnsRequestProcessedEventArgs
            {
                Rules = rules,
                FilterListIds = filterListIds
            };
            
            MarshalUtils.AllPtrsToStrings(coreArgsС, eventArgs);
            MarshalUtils.CopyFieldsToProperties(coreArgsС, eventArgs);
            return eventArgs;
        }
        
        internal static AGDnsApi.cbd_onCertificateVerification ToNativeObject(
            ICertificateVerificationCallback certificateVerificationCallback)
        {
            TestUpstreamCallbacksAdapter testUpstreamCallbacksAdapter =
                new TestUpstreamCallbacksAdapter(certificateVerificationCallback);
            return testUpstreamCallbacksAdapter.OnTestUpstreamCallback;
        }

        #endregion

        #region Helper methods

        /// <summary>
        /// Creates the <see cref="IPAddress"/> object from the specified pointer to address byte array,
        /// addressLength
        /// </summary>
        /// <param name="agAddress">The <see cref="AGDnsApi.ag_buffer"/> instance</param>
        /// <exception cref="ArgumentException">Thrown,
        /// if passed <see cref="AGDnsApi.ag_buffer.size"/> is not acceptable</exception>
        /// <returns><see cref="IPAddress"/> object or null if the pointer is null or addressLength is zero</returns>
        private static IPAddress CreateIpAddress(AGDnsApi.ag_buffer agAddress)
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
    }
}
