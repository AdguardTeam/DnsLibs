using System;
using System.Runtime.InteropServices;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.Helpers;

// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Global
// ReSharper disable IdentifierTypo

namespace Adguard.Dns
{
    // ReSharper disable once InconsistentNaming
    public static class AGDnsApi
    {
        #region Constants

        /// <summary>
        /// The DnsLibs dll name.
        /// The entry point to the AdGuard native world
        /// </summary>
        private const string DnsLibName = "AdguardDns.dll";

        /// <summary>
        /// The current API version hash with which the ProxyServer was tested
        /// </summary>
        private const string API_VERSION_HASH = "f17340a032722da854ce2ba0314180ae5f4a39cb0e237d07e7a42b01355acbc5";
        #endregion

        #region API Functions

        /// <summary>
        /// Initialize the DNS proxy
        /// </summary>
        /// <param name="pDnsProxySettings">Pointer to the
        /// <see cref="ag_dnsproxy_settings"/> object</param>
        /// <param name="pDnsProxyCallbacks">Pointer to the
        /// <see cref="AGDnsProxyServerCallbacks"/> object</param>
        /// <returns>Pointer to the proxy, or <see cref="IntPtr.Zero"/> in case of an error</returns>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ag_dnsproxy_init(
            IntPtr pDnsProxySettings,
            IntPtr pDnsProxyCallbacks);

        /// <summary>
        /// Deinitializes the DNS proxy
        /// </summary>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void ag_dnsproxy_deinit(IntPtr pDnsProxyServer);

        /// <summary>
        /// Returns the current proxy settings.
        /// The caller is responsible for freeing
        /// the returned pointer with <see cref="ag_dnsproxy_settings_free"/>
        /// </summary>
        /// <returns>Pointer to the<see cref="ag_dnsproxy_settings"/> object,
        /// which contains the current DNS proxy settings</returns>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ag_dnsproxy_get_settings(IntPtr pDnsProxyServer);

        /// <summary>
        /// Returns the default proxy settings.
        /// The caller is responsible for freeing
        /// the returned pointer with <see cref="ag_dnsproxy_settings_free"/>
        /// </summary>
        /// <returns>Pointer to the<see cref="ag_dnsproxy_settings"/> object,
        /// which contains the default DNS proxy settings</returns>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ag_dnsproxy_settings_get_default();

        /// <summary>
        /// Free passed <see cref="pDnsProxySettings"/> pointer.
        /// </summary>
        /// <param name="pDnsProxySettings">Pointer to the <see cref="ag_dnsproxy_settings"/>
        /// structure ot free</param>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void ag_dnsproxy_settings_free(IntPtr pDnsProxySettings);

        /// <summary>
        /// Free a specified <see cref="ag_buffer"/> instance.
        /// </summary>
        /// <param name="buf"><see cref="ag_buffer"/> instance to free</param>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void ag_buffer_free(ag_buffer buf);

        /// <summary>
        /// Checks if upstream is valid and available
        /// The caller is responsible for freeing the result with <see cref="ag_str_free"/>
        /// </summary>
        /// <param name="pUpstreamOptions">Pointer to the
        /// <see cref="ag_upstream_options"/> object</param>
        /// <param name="onCertificateVerification">Certificate verification callback
        /// as a <see cref="cbd_onCertificateVerification"/> object</param>
        /// <returns>If it is, no error is returned.
        /// Otherwise this method returns an error with an explanation</returns>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ag_test_upstream(
            IntPtr pUpstreamOptions,
            [MarshalAs(UnmanagedType.FunctionPtr)] cbd_onCertificateVerification onCertificateVerification);

        /// <summary>
        /// Parses a DNS stamp string and returns a instance or an error
        /// The caller is responsible for freeing
        /// the result with <see cref="ag_parse_dns_stamp_result_free"/>
        /// </summary>
        /// <param name="stampStr">DNS stamp string</param>
        /// <returns>Pointer to the stamp instance or an error
        /// (<seealso cref="ag_parse_dns_stamp_result"/>)</returns>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ag_parse_dns_stamp(
            [MarshalAs(
                UnmanagedType.CustomMarshaler,
                MarshalTypeRef = typeof(ManualStringToPtrMarshaler))]
            string stampStr);

        /// <summary>
        /// Free a pointer to the <see cref="ag_parse_dns_stamp_result"/> instance.
        /// </summary>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void ag_parse_dns_stamp_result_free(IntPtr pStampResult);

        /// <summary>
        /// Sets the log verbosity level.
        /// </summary>
        /// <param name="level">Verbosity level
        /// (<seealso cref="ag_log_level"/>)</param>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void ag_set_default_log_level(ag_log_level level);

        /// <summary>
        /// Sets the default callback for logger
        /// </summary>
        /// <param name="callback">Logger default callback
        /// (<seealso cref="cbd_logger_callback_t"/>)</param>
        /// <param name="pAttachment">Attachment of this callback</param>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void ag_logger_set_default_callback(
            [MarshalAs(UnmanagedType.FunctionPtr)]
            cbd_logger_callback_t callback,
            IntPtr pAttachment);

        #endregion

        #region Settings

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ag_dns64_settings
        {
            /// <summary>
            /// The upstreams to use for discovery of DNS64 prefixes (usually the system DNS servers),
            /// represented as a <see cref="ag_list"/> with entries with
            /// the type <see cref="ag_upstream_options"/>
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            internal ag_list upstreams;

            /// <summary>
            /// How many times, at most, to try DNS64 prefixes discovery before giving up
            /// </summary>
            [MarshalAs(UnmanagedType.U4)]
            [NativeName("max_tries")]
            internal UInt32 MaxTries;

            /// <summary>
            /// How long to wait before a dns64 prefixes discovery attempt
            /// </summary>
            [MarshalAs(UnmanagedType.U4)]
            [NativeName("wait_time_ms")]
            internal UInt32 WaitTimeMs;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ag_listener_settings
        {
            /// <summary>
            /// Pointer to a string, which contains address to listen on
            /// </summary>
            internal IntPtr address;

            /// <summary>
            /// Protocol to listen on
            /// </summary>
            [MarshalAs(UnmanagedType.U2)]
            internal UInt16 port;

            /// <summary>
            /// The protocol to listen for
            /// </summary>
            [MarshalAs(UnmanagedType.I4)]
            [NativeName("protocol")]
            internal ag_listener_protocol Protocol;

            /// <summary>
            /// Don't close the TCP connection after sending the first response
            /// </summary>
            [MarshalAs(UnmanagedType.I1)]
            [NativeName("persistent")]
            internal bool IsPersistent;

            /// <summary>
            /// Close the TCP connection this long after the last request received
            /// </summary>
            [MarshalAs(UnmanagedType.U4)]
            [NativeName("idle_timeout_ms")]
            internal UInt32 IdleTimeoutMs;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ag_upstream_options
        {
            /// <summary>
            /// Server address, one of the following kinds:
            /// 8.8.8.8:53 -- plain DNS
            /// tcp://8.8.8.8:53 -- plain DNS over TCP
            /// tls://1.1.1.1 -- DNS-over-TLS
            /// https://dns.adguard.com/dns-query -- DNS-over-HTTPS
            /// sdns://... -- DNS stamp (see https://dnscrypt.info/stamps-specifications)
            /// (<seealso cref="ManualMarshalPtrToStringAttribute"/>)
            /// </summary>
            [ManualMarshalPtrToString]
            [NativeName("address")]
            internal IntPtr Address;

            /// <summary>
            /// List of plain DNS servers to be used to resolve the hostname in upstreams' address,
            /// represented as a <see cref="ag_list"/> with entries with
            /// the type <see cref="IntPtr"/>,
            /// which be further marshall with <see cref="ManualMarshalPtrToStringAttribute"/>
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            internal ag_list bootstrap;

            /// <summary>
            /// Default upstream timeout. Also, it is used as a timeout for bootstrap DNS requests.
            /// timeout = 0 means default.
            /// </summary>
            [MarshalAs(UnmanagedType.U4)]
            [NativeName("timeout_ms")]
            internal UInt32 TimeoutMs;

            /// <summary>
            /// Resolver's IP address.
            /// In the case if it's specified, bootstrap DNS servers won't be used at all.
            /// (<seealso cref="ag_buffer"/>)
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            internal ag_buffer resolved_ip_address;

            /// <summary>
            /// User-provided ID for this upstream
            /// (<seealso cref="ag_buffer"/>)
            /// </summary>
            [MarshalAs(UnmanagedType.I4)]
            [NativeName("id")]
            internal Int32 Id;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ag_filter_params
        {
            /// <summary>
            /// filter id
            /// </summary>
            [NativeName("id")]
            [MarshalAs(UnmanagedType.I4)]
            internal Int32 Id;

            /// <summary>
            /// Path to the filter list file or string with rules, depending on value of in_memory
            /// </summary>
            [NativeName("data")]
            [ManualMarshalPtrToString]
            internal IntPtr Data;

            /// <summary>
            /// If true, data is rules, otherwise data is path to file with rules
            /// </summary>
            [NativeName("in_memory")]
            [MarshalAs(UnmanagedType.I1)]
            internal bool InMemory;
        };

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ag_filter_engine_params
        {
            /// <summary>
            /// List of filters, represented as a <see cref="ag_filter_params"/> structures
            /// </summary>
            internal ag_list filters;
        } ;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ag_dnsproxy_settings
        {
            /// <summary>
            /// List of upstreams,
            /// represented as a <see cref="ag_list"/> with entries with
            /// the type <see cref="ag_upstream_options"/>
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            internal ag_list upstreams;

            /// <summary>
            /// List of fallbacks,
            /// represented as a <see cref="ag_list"/> with entries with
            /// the type <see cref="ag_upstream_options"/>
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            internal ag_list fallbacks;

            /// <summary>
            /// Pointer to the DNS64 settings
            /// (<seealso cref="ag_dns64_settings"/>)
            /// </summary>
            internal IntPtr pDns64;

            /// <summary>
            /// TTL of the record for the blocked domains (in seconds)
            /// </summary>
            [MarshalAs(UnmanagedType.U4)]
            [NativeName("blocked_response_ttl_sec")]
            internal UInt32 BlockedResponseTtlSec;

            /// <summary>
            /// Filtering engine parameters
            /// (<seealso cref="ag_filter_engine_params"/>)
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            [NativeName("filter_params")]
            internal ag_filter_engine_params FilterParams;

            /// <summary>
            /// List of addresses/ports/protocols/etc... to listen on,
            /// represented as a <see cref="ag_list"/> with entries with
            /// the type <see cref="ag_listener_settings"/>
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            internal ag_list listeners;

            /// <summary>
            /// If true, all AAAA requests will be blocked
            /// </summary>
            [MarshalAs(UnmanagedType.I1)]
            [NativeName("block_ipv6")]
            internal bool BlockIpv6;

            /// <summary>
            /// If true, the bootstrappers are allowed to fetch AAAA records
            /// </summary>
            [MarshalAs(UnmanagedType.I1)]
            [NativeName("ipv6_available")]
            internal bool Ipv6Available;

            /// <summary>
            /// How to respond to filtered requests
            /// </summary>
            [MarshalAs(UnmanagedType.I4)]
            [NativeName("blocking_mode")]
            internal ag_dnsproxy_blocking_mode BlockingMode;

            /// <summary>
            /// Custom IPv4 address to return for filtered requests
            /// (<seealso cref="ManualMarshalPtrToStringAttribute"/>)
            /// </summary>
            [ManualMarshalPtrToString]
            [NativeName("custom_blocking_ipv4")]
            internal IntPtr CustomBlockingIpv4;

            /// <summary>
            /// Custom IPv6 address to return for filtered requests
            /// (<seealso cref="ManualMarshalPtrToStringAttribute"/>)
            /// </summary>
            [ManualMarshalPtrToString]
            [NativeName("custom_blocking_ipv6")]
            internal IntPtr CustomBlockingIpv6;

            /// <summary>
            /// Maximum number of cached responses (may be 0)
            /// </summary>
            [MarshalAs(UnmanagedType.U4)]
            [NativeName("dns_cache_size")]
            internal UInt32 DnsCacheSize;

            /// <summary>
            /// Enable optimistic DNS caching
            /// </summary>
            [MarshalAs(UnmanagedType.I1)]
            [NativeName("optimistic_cache")]
            internal bool OptimisticCache;
        }

        /// <summary>
        /// DNS stamp structure
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ag_dns_stamp
        {
            /// <summary>
            /// Protocol
            /// </summary>
            [MarshalAs(UnmanagedType.I4)]
            [NativeName("proto")]
            internal ag_proto_type ProtoType;

            /// <summary>
            /// Server address
            /// </summary>
            [ManualMarshalPtrToString]
            [NativeName("server_addr")]
            internal IntPtr ServerAddress;

            /// <summary>
            /// Provider means different things depending on the stamp type
            /// DNSCrypt: the DNSCrypt provider name
            /// DOH and DOT: server's hostname
            /// Plain DNS: not specified
            /// </summary>
            [ManualMarshalPtrToString]
            [NativeName("provider_name")]
            internal IntPtr ProviderName;

            /// <summary>
            /// (For DoH) absolute URI path, such as /dns-query
            /// </summary>
            [ManualMarshalPtrToString]
            [NativeName("path")]
            internal IntPtr DoHPath;
        };

        /// <summary>
        /// Parsed dns stamp result,
        /// consisted of two parts - the stamp itself (<seealso cref="ag_dns_stamp"/>)
        /// and the pointer to the error if smth went wrong
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ag_parse_dns_stamp_result
        {
            /// <summary>
            /// DNS stamp
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            internal ag_dns_stamp stamp;

            /// <summary>
            /// error
            /// </summary>
            internal IntPtr error;
        };

        #endregion

        #region Callback's events

        /// <summary>
        /// BeforeRequest event data
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ag_certificate_verification_event
        {
            /// <summary>
            /// Session identifier.
            /// Basically, it means a network connection identifier.
            /// </summary>
            internal ag_buffer pCertificate;

            /// <summary>
            /// Request identifier.
            /// Represents as a list of <see cref="ag_buffer"/> elements
            /// There can be multiple requests processed inside a single connection
            /// </summary>
            internal ag_list chain;
        };

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ag_dns_request_processed_event
        {
            /// <summary>
            /// Queried domain name
            /// </summary>
            [ManualMarshalPtrToString]
            [NativeName("domain")]
            internal IntPtr Domain;

            /// <summary>
            /// Query type
            /// </summary>
            [ManualMarshalPtrToString]
            [NativeName("type")]
            internal IntPtr Type;

            /// <summary>
            /// Time when dnsproxy started processing request (epoch in milliseconds)
            /// </summary>
            [MarshalAs(UnmanagedType.I8)]
            [NativeName("start_time")]
            internal Int64 StartTime;

            /// <summary>
            /// Time elapsed on processing (in milliseconds)
            /// </summary>
            [MarshalAs(UnmanagedType.I4)]
            [NativeName("elapsed")]
            internal Int32 Elapsed;

            /// <summary>
            /// DNS answer's status
            /// </summary>
            [ManualMarshalPtrToString]
            [NativeName("status")]
            internal IntPtr Status;

            /// <summary>
            /// DNS Answers string representation
            /// </summary>
            [ManualMarshalPtrToString]
            [NativeName("answer")]
            internal IntPtr Answer;

            /// <summary>
            /// If blocked by CNAME, here will be DNS original answer's string representation
            /// </summary>
            [ManualMarshalPtrToString]
            [NativeName("original_answer")]
            internal IntPtr OriginalAnswer;

            /// <summary>
            /// ID of the upstream that provided this answer
            /// </summary>
            [NativeName("upstream_id")]
            internal IntPtr pUpstreamId;

            /// <summary>
            /// Number of bytes sent to a server
            /// </summary>
            [NativeName("bytes_sent")]
            [MarshalAs(UnmanagedType.I4)]
            internal Int32 BytesSent;

            /// <summary>
            /// Number of bytes received from a server
            /// </summary>
            [NativeName("bytes_received")]
            [MarshalAs(UnmanagedType.I4)]
            internal Int32 BytesReceived;

            /// <summary>
            /// Pointer Filtering rules texts
            /// (<seealso cref="ag_list"/>)
            /// </summary>
            internal ag_list rules;

            /// <summary>
            /// Pointer to the filter lists IDs of corresponding rules
            /// (<seealso cref="ag_list"/>)
            /// </summary>
            internal ag_list filter_list_ids;

            /// <summary>
            /// True if filtering rule is whitelist
            /// </summary>
            [MarshalAs(UnmanagedType.I1)]
            [NativeName("whitelist")]
            internal bool Whitelist;

            /// <summary>
            /// If not {@code null}, contains the error text (occurred while processing the DNS query)
            /// </summary>
            [ManualMarshalPtrToString]
            [NativeName("error")]
            internal IntPtr Error;

            /// <summary>
            /// True if this response was served from the cache
            /// </summary>
            [MarshalAs(UnmanagedType.I1)]
            [NativeName("cache_hit")]
            internal bool CacheHit;
        };

        #endregion

        #region Callbacks

        /// <summary>
        /// ag_dns_request_processed_cb callback delegate
        /// </summary>
        /// <param name="pEvent">The pointer
        /// to the <see cref="ag_dns_request_processed_event"/> info</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void cbd_onDnsRequestProcessed(IntPtr pEvent);

        /// <summary>
        /// onCertificateVerification callback delegate.
        /// </summary>
        /// <param name="pEvent">The pointer
        /// to the <see cref="ag_certificate_verification_event"/> event info</param>
        /// <returns>Certificate verification result
        /// (<seealso cref="ag_certificate_verification_result"/>)</returns>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I4)]
        internal delegate ag_certificate_verification_result
            cbd_onCertificateVerification(IntPtr pEvent);

        /// <summary>
        /// Proxy callbacks configuration object
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct AGDnsProxyServerCallbacks
        {
            [MarshalAs(UnmanagedType.FunctionPtr)]
            internal cbd_onDnsRequestProcessed ag_dns_request_processed_cb;

            [MarshalAs(UnmanagedType.FunctionPtr)]
            internal cbd_onCertificateVerification ag_certificate_verification_cb;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void cbd_logger_callback_t(
            IntPtr attachment,
            IntPtr pName,
            ag_log_level log_level,
            IntPtr pMessage);

        #endregion

        #region Enumerations

        /// <summary>
        /// Logger levels
        /// </summary>
        public enum ag_log_level
        {
            AGLL_TRACE,
            AGLL_DEBUG,
            AGLL_INFO,
            AGLL_WARN,
            AGLL_ERR,
        }

        /// <summary>
        /// Specifies how to respond to filtered requests
        /// </summary>
        public enum ag_dnsproxy_blocking_mode
        {
            /// <summary>
            /// AdBlock-style filters -> NXDOMAIN, hosts-style filters -> unspecified address
            /// </summary>
            DEFAULT,

            /// <summary>
            /// Always return NXDOMAIN
            /// </summary>
            NXDOMAIN,

            /// <summary>
            /// Always return unspecified address
            /// </summary>
            UNSPECIFIED_ADDRESS,

            /// <summary>
            /// Always return custom configured IP address
            /// (<seealso cref="DnsProxySettings"/>)
            /// </summary>
            CUSTOM_ADDRESS
        }

        public enum ag_listener_protocol
        {
            UDP,
            TCP
        }

        /// <summary>
        /// ag_proto_type is a stamp protocol type
        /// </summary>
        public enum ag_proto_type
        {
            /// <summary>
            /// Plain DNS
            /// </summary>
            PLAIN,

            /// <summary>
            /// DNSCrypt
            /// </summary>
            DNSCRYPT,

            /// <summary>
            /// DNS-over-HTTPS
            /// </summary>
            DOH,

            /// <summary>
            /// DNS-over-TLS
            /// </summary>
            TLS
        }

        public enum ag_certificate_verification_result
        {
            AGCVR_OK,

            AGCVR_ERROR_CREATE_CERT,
            AGCVR_ERROR_ACCESS_TO_STORE,
            AGCVR_ERROR_CERT_VERIFICATION,

            AGCVR_COUNT
        }

        #endregion

        #region Validation

        /// <summary>
        /// Gets a CAPI version (number of commits in this file history)
        /// NOTE: The value is stored in ..\\platform/windows/capi/src/ag_dns_h_hash.inc
        /// Return the C API version (hash of this file).
        /// </summary>
        /// <returns>Pointer to the API version hash</returns>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ag_get_capi_version();

        /// <summary>
        /// Free a string, specified by a passed <see cref="pStr"/>
        /// </summary>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void ag_str_free(IntPtr pStr);

        /// <summary>
        /// Validates API version hash against the supported API version hash,
        /// stored in the <see cref="API_VERSION_HASH"/>
        /// </summary>
        /// <exception cref="NotSupportedException">Thrown,
        /// if the API version hash is not supported</exception>
        internal static void ValidateApi()
        {
            IntPtr pCapiVersion = ag_get_capi_version();
            string currentApiVersionHash = MarshalUtils.PtrToString(pCapiVersion);
            if (currentApiVersionHash == API_VERSION_HASH)
            {
                return;
            }

            string message = string.Format(
                "Unsupported API version hash: {2}{0}{2}Expected: {2}{1}{2}",
                currentApiVersionHash,
                API_VERSION_HASH,
                Environment.NewLine);
            throw new NotSupportedException(message);
        }

        #endregion

        #region Crash reporting

        /// <summary>
        /// Disables the SetUnhandledExceptionFilter function.
        /// </summary>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void ag_disable_SetUnhandledExceptionFilter();

        /// <summary>
        /// Enables the SetUnhandledExceptionFilter function.
        /// </summary>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void ag_enable_SetUnhandledExceptionFilter();

        #endregion

        #region Helpers

        /// <summary>
        /// Represents list of elements
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ag_list
        {
            internal IntPtr entries;

            [MarshalAs(UnmanagedType.U4)]
            internal UInt32 num_entries;
        }

        /// <summary>
        /// Helper structure-wrapper for storing the byte buffer (<see cref="data"/>)
        /// with fixed <see cref="size"/>
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ag_buffer
        {
            /// <summary>
            /// Pointer to the byte array
            /// </summary>
            internal IntPtr data;

            /// <summary>
            /// Byte array size
            /// </summary>
            [MarshalAs(UnmanagedType.U4)]
            internal UInt32 size;
        };

        #endregion
    }
}
