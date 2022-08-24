using System;
using System.Runtime.InteropServices;
using AdGuard.Utils.Interop;

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
        private const string API_VERSION_HASH = "ace9ef69345f6013fc258a2d28d4905f876b3fdd2c5940b9b8ee76d07ad51fda";
        #endregion

        #region API Functions

        /// <summary>
        /// Dns proxy initialization result
        /// </summary>
        public enum ag_dnsproxy_init_result
        {
            AGDPIR_OK,
            AGDPIR_WARNING,
            AGDPIR_LISTENER_ERROR,
            AGDPIR_ERROR
        }

        /// <summary>
        /// Initialize the DNS proxy
        /// </summary>
        /// <param name="pDnsProxySettings">Pointer to the
        /// <see cref="ag_dnsproxy_settings"/> object</param>
        /// <param name="pDnsProxyCallbacks">Pointer to the
        /// <see cref="AGDnsProxyServerCallbacks"/> object</param>
        /// <param name="pOutResult">Pointer to the out result
        /// (<seealso cref="ag_dnsproxy_init_result"/>)</param>
        /// <param name="ppOutMessage">Pointer to the out message</param>
        /// <returns>Pointer to the proxy, or <see cref="IntPtr.Zero"/> in case of an error</returns>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ag_dnsproxy_init(
            IntPtr pDnsProxySettings,
            IntPtr pDnsProxyCallbacks,
            IntPtr pOutResult,
            IntPtr ppOutMessage);

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
        /// Free a specified <see cref="MarshalUtils.ag_buffer"/> instance.
        /// </summary>
        /// <param name="buf"><see cref="MarshalUtils.ag_buffer"/> instance to free</param>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void ag_buffer_free([MarshalAs(UnmanagedType.Struct)] MarshalUtils.ag_buffer buf);

        /// <summary>
        /// Checks if upstream is valid and available
        /// The caller is responsible for freeing the result with <see cref="ag_str_free"/>
        /// </summary>
        /// <param name="pUpstreamOptions">Pointer to the
        /// <see cref="ag_upstream_options"/> object</param>
        /// <param name="ipv6Available">Whether IPv6 is available (i.e., bootstrapper is allowed to make AAAA queries)</param>
        /// <param name="onCertificateVerification">Certificate verification callback
        /// as a <see cref="cbd_onCertificateVerification"/> object</param>
        /// <param name="offline">Don't perform online upstream check</param>
        /// <returns>If it is, no error is returned.
        /// Otherwise this method returns an error with an explanation</returns>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ag_test_upstream(
            IntPtr pUpstreamOptions, [MarshalAs(UnmanagedType.I1)] bool Ipv6Available,
            [MarshalAs(UnmanagedType.FunctionPtr)] cbd_onCertificateVerification onCertificateVerification,
            [MarshalAs(UnmanagedType.I1)] bool offline);

        /// <summary>
        /// Parses a DNS stamp string and returns a instance or an error
        /// The caller is responsible for freeing
        /// the result with <see cref="ag_dns_stamp_free"/>
        /// </summary>
        /// <param name="stampStr">DNS stamp string ("sdns://..." string)</param>
        /// <param name="ppEerror">error on output, if an error occurred, contains the error description
        /// (free with <see cref="ag_str_free"/>)</param>
        /// <returns>Pointer to the stamp instance or NULL if an error occurred
        /// (<seealso cref="ag_dns_stamp"/>)</returns>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ag_dns_stamp_from_str(
            [MarshalAs(
                UnmanagedType.CustomMarshaler,
                MarshalTypeRef = typeof(ManualStringToPtrMarshaler))]
            string stampStr,
            IntPtr ppEerror);

        /// <summary>
        /// Free a pointer to the <see cref="ag_dns_stamp"/> instance.
        /// </summary>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void ag_dns_stamp_free(IntPtr pStamp);

        /// <summary>
        /// Convert a DNS stamp to "sdns://..." string.
        /// Free the string with <see cref="ag_str_free"/>
        /// </summary>
        /// <param name="pStamp">Pointer to the stamp instance
        /// (<seealso cref="ag_dns_stamp"/>)</param>
        /// <returns>Pointer to "sdns://..." string.</returns>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ag_dns_stamp_to_str(IntPtr pStamp);

        /// <summary>
        /// Convert a DNS stamp to string that can be used as an upstream URL.
        /// Free the string with <see cref="ag_str_free"/>
        /// </summary>
        /// <param name="pStamp">Pointer to the stamp instance
        /// (<seealso cref="ag_dns_stamp"/>)</param>
        /// <returns>Pointer to "sdns://..." string.</returns>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ag_dns_stamp_pretty_url(IntPtr pStamp);

        /// <summary>
        ///  Convert a DNS stamp to string that can NOT be used as an upstream URL, but may be prettier.
        /// Free the string with <see cref="ag_str_free"/>
        /// </summary>
        /// <param name="pStamp">Pointer to the stamp instance
        /// (<seealso cref="ag_dns_stamp"/>)</param>
        /// <returns>Pointer to "sdns://..." string.</returns>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ag_dns_stamp_prettier_url(IntPtr pStamp);

        /// <summary>
        /// Sets the log verbosity level.
        /// </summary>
        /// <param name="level">Verbosity level
        /// (<seealso cref="ag_log_level"/>)</param>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void ag_set_log_level(ag_log_level level);

        /// <summary>
        /// Sets the default callback for logger
        /// </summary>
        /// <param name="callback">Logger default callback
        /// (<seealso cref="cbd_logger_callback_t"/>)</param>
        /// <param name="pAttachment">Attachment of this callback</param>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void ag_set_log_callback(
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
            /// represented as a <see cref="MarshalUtils.ag_list"/> with entries with
            /// the type <see cref="ag_upstream_options"/>
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            internal MarshalUtils.ag_list upstreams;

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

        public enum ag_outbound_proxy_protocol
        {
            /** Plain HTTP proxy */
            AGOPP_HTTP_CONNECT,

            /** HTTPs proxy */
            AGOPP_HTTPS_CONNECT,

            /** Socks4 proxy */
            AGOPP_SOCKS4,

            /** Socks5 proxy without UDP support */
            AGOPP_SOCKS5,

            /** Socks5 proxy with UDP support */
            AGOPP_SOCKS5_UDP,
        };

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ag_outbound_proxy_auth_info
        {
            [ManualMarshalPtrToString]
            [NativeName("username")]
            internal IntPtr Username;

            [ManualMarshalPtrToString]
            [NativeName("password")]
            internal IntPtr Password;
        };

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ag_outbound_proxy_settings
        {
            /** The proxy protocol */
            [MarshalAs(UnmanagedType.I4)]
            [NativeName("protocol")]
            ag_outbound_proxy_protocol Protocol;

            /** The proxy server IP address or hostname */
            [ManualMarshalPtrToString]
            [NativeName("address")]
            internal IntPtr Address;

            /** The proxy server port */
            [MarshalAs(UnmanagedType.U2)]
            [NativeName("port")]
            internal UInt16 Port;

            /**
             * List of the DNS server URLs to be used to resolve a hostname in the proxy server address.
             * The URLs MUST contain the resolved server addresses, not hostnames.
             * E.g. `https://94.140.14.14` is correct, while `dns.adguard.com:53` is not.
             * MUST NOT be empty in case the `address` is a hostname.
             */
            [MarshalAs(UnmanagedType.Struct)]
            internal MarshalUtils.ag_list bootstrap;

            /** The authentication information (pointer to <see cref="ag_outbound_proxy_auth_info"/>)*/
            internal IntPtr auth_info;

            /** If true and the proxy connection is secure, the certificate won't be verified */
            [MarshalAs(UnmanagedType.I1)]
            [NativeName("trust_any_certificate")]
            internal bool TrustAnyCertificate;

            /**
             * Whether the DNS proxy should ignore the outbound proxy and route queries directly
             * to target hosts even if it's determined as unavailable
             */
            [MarshalAs(UnmanagedType.I1)]
            [NativeName("ignore_if_unavailable")]
            internal bool IgnoreIfUnavailable;
        };

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
            /// quic://dns.adguard.com:8853 -- DNS-over-QUIC
            /// (<seealso cref="ManualMarshalPtrToStringAttribute"/>)
            /// </summary>
            [ManualMarshalPtrToString]
            [NativeName("address")]
            internal IntPtr Address;

            /// <summary>
            /// List of plain DNS servers to be used to resolve the hostname in upstreams' address,
            /// represented as a <see cref="MarshalUtils.ag_list"/> with entries with
            /// the type <see cref="IntPtr"/>,
            /// which be further marshall with <see cref="ManualMarshalPtrToStringAttribute"/>
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            internal MarshalUtils.ag_list bootstrap;

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
            /// (<seealso cref="MarshalUtils.ag_buffer"/>)
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            internal MarshalUtils.ag_buffer resolved_ip_address;

            /// <summary>
            /// User-provided ID for this upstream
            /// (<seealso cref="MarshalUtils.ag_buffer"/>)
            /// </summary>
            [MarshalAs(UnmanagedType.I4)]
            [NativeName("id")]
            internal Int32 Id;

            /// <summary>
            /// Index of the network interface to route traffic through, 0 is default
            /// </summary>
            [MarshalAs(UnmanagedType.U4)]
            [NativeName("outbound_interface_index")]
            internal UInt32 OutboundInterfaceIndex;
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
            internal MarshalUtils.ag_list filters;
        } ;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ag_dnsproxy_settings
        {
            /// <summary>
            /// List of upstreams,
            /// represented as a <see cref="MarshalUtils.ag_list"/> with entries with
            /// the type <see cref="ag_upstream_options"/>
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            internal MarshalUtils.ag_list upstreams;

            /// <summary>
            /// List of fallbacks,
            /// represented as a <see cref="MarshalUtils.ag_list"/> with entries with
            /// the type <see cref="ag_upstream_options"/>
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            internal MarshalUtils.ag_list fallbacks;

            /// <summary>
            /// Requests for these domains will be forwarded directly to the fallback upstreams, if there are any.
            /// A wildcard character, `*`, which stands for any number of characters, is allowed to appear multiple
            /// times anywhere except at the end of the domain (which implies that a domain consisting only of
            /// wildcard characters is invalid).
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            [NativeName("fallback_domains")]
            internal MarshalUtils.ag_list fallbackDomains;

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
            /// represented as a <see cref="MarshalUtils.ag_list"/> with entries with
            /// the type <see cref="ag_listener_settings"/>
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            internal MarshalUtils.ag_list listeners;

            /** Outbound proxy settings (pointer to <see cref="ag_outbound_proxy_settings"/>)*/
            internal IntPtr outbound_proxy;

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
            /// How to respond to requests blocked by AdBlock-style rules
            /// </summary>
            [MarshalAs(UnmanagedType.I4)]
            [NativeName("adblock_rules_blocking_mode")]
            internal ag_dnsproxy_blocking_mode AdblockRulesBlockingMode;

            /// <summary>
            /// How to respond to requests blocked by hosts-style rules
            /// </summary>
            [MarshalAs(UnmanagedType.I4)]
            [NativeName("hosts_rules_blocking_mode")]
            internal ag_dnsproxy_blocking_mode HostsRulesBlockingMode;

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

            /// <summary>
            /// Enable DNSSEC OK extension.
            /// This options tells server that we want to receive DNSSEC records along with normal queries.
            /// If they exist, request processed event will have DNSSEC flag on.
            /// WARNING: may increase data usage and probability of TCP fallbacks.
            /// </summary>
            [MarshalAs(UnmanagedType.I1)]
            [NativeName("enable_dnssec_ok")]
            internal bool EnableDNSSECOK;

            /// <summary>
            /// If enabled, retransmitted requests will be answered using the fallback upstreams only.
            /// </summary>
            [MarshalAs(UnmanagedType.I1)]
            [NativeName("enable_dnssec_ok")]
            internal bool EnableRetransmissionHandling;
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
            internal ag_stamp_proto_type ProtoType;

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

            /// <summary>
            /// The DNSCrypt provider’s Ed25519 public key, as 32 raw bytes. Empty for other types.
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            internal MarshalUtils.ag_buffer server_public_key;

            /// <summary>
            /// Hash is the SHA256 digest of one of the TBS certificate found in the validation chain, typically
            /// the certificate used to sign the resolver’s certificate. Multiple hashes can be provided for seamless
            /// rotations.
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            internal MarshalUtils.ag_list hashes;

            /// <summary>
            /// Server properties
            /// </summary>
            [NativeName("properties")]
            [MarshalAs(UnmanagedType.I4)]
            internal ag_server_informal_properties Properties;
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
            [MarshalAs(UnmanagedType.Struct)]
            internal MarshalUtils.ag_buffer pCertificate;

            /// <summary>
            /// Request identifier.
            /// Represents as a list of <see cref="MarshalUtils.ag_buffer"/> elements
            /// There can be multiple requests processed inside a single connection
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            internal MarshalUtils.ag_list chain;
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
            /// (<seealso cref="MarshalUtils.ag_list"/>)
            /// </summary>
            internal MarshalUtils.ag_list rules;

            /// <summary>
            /// Pointer to the filter lists IDs of corresponding rules
            /// (<seealso cref="MarshalUtils.ag_list"/>)
            /// </summary>
            internal MarshalUtils.ag_list filter_list_ids;

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

            /// <summary>
            /// True if this response has DNSSEC rrsig
            /// </summary>
            [MarshalAs(UnmanagedType.I1)]
            [NativeName("dnssec")]
            internal bool DNSSEC;
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
            ag_log_level log_level,
            IntPtr pMessage,
            UInt32 length);

        #endregion

        #region Enumerations

        /// <summary>
        /// Logger levels
        /// </summary>
        public enum ag_log_level
        {
            AGLL_ERR,
            AGLL_WARN,
            AGLL_INFO,
            AGLL_DEBUG,
            AGLL_TRACE,
        }

        /// <summary>
        /// Specifies how to respond to blocked requests.
        ///
        /// A request is blocked if it matches a blocking AdBlock-style rule,
        ///   * or a blocking hosts-style rule. A blocking hosts-style rule is
        /// a hosts-style rule with a loopback or all-zeroes address.
        ///
        /// Requests matching a hosts-style rule with an address that is
        /// neither loopback nor all-zeroes are always responded
        /// with the address specified by the rule.
        /// </summary>
        public enum ag_dnsproxy_blocking_mode
        {
            /// <summary>
            /// Respond with REFUSED response code
            /// </summary>
            AGBM_REFUSED,

            /// <summary>
            /// Respond with NXDOMAIN response code
            /// </summary>
            AGBM_NXDOMAIN,

            /// <summary>
            /// Respond with an address that is all-zeroes, or
            /// a custom blocking address, if it is specified, or
            /// an empty SOA response if request type is not A/AAAA.
            /// </summary>
            AGBM_ADDRESS
        }

        public enum ag_listener_protocol
        {
            AGLP_UDP,
            AGLP_TCP
        }

        /// <summary>
        /// ag_stamp_proto_type is a stamp protocol type
        /// </summary>
        public enum ag_stamp_proto_type
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
            TLS,

            /// <summary>
            /// DNS-over-QUIC
            /// </summary>
            DOQ
        }

        [Flags]
        public enum ag_server_informal_properties
        {
            /// <summary>
            /// Resolver does DNSSEC validation
            /// </summary>
            AGSIP_DNSSEC = 1 << 0,

            /// <summary>
            /// Resolver does not record logs
            /// </summary>
            AGSIP_NO_LOG = 1 << 1,

            /// <summary>
            /// Resolver doesn't intentionally block domains
            /// </summary>
            AGSIP_NO_FILTER = 1 << 2
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
        /// Return the DNS proxy library version.
        /// Do NOT free the returned string.
        /// </summary>
        /// <returns>Pointer to the API version hash</returns>
        [DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ag_dnsproxy_version();

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
    }
}
