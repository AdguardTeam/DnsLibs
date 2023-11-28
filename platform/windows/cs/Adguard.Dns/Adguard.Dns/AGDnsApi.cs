using System;
using System.Runtime.InteropServices;
using AdGuard.Utils.Base.Interop;

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
		private const string DnsLibName = "AdguardDns";

		/// <summary>
		/// The current API version hash with which the ProxyServer was tested
		/// </summary>
		private const string API_VERSION_HASH = "6fedfaf50a6d05334b8bcf3c54febb1944d9e336987f23c0aeeecea5b4f6e872";

        #endregion

        #region API Functions

        /// <summary>
        /// Dns proxy initialization result
        /// </summary>
        public enum ag_dnsproxy_init_result
        {
            /// <summary>
            /// The DNS proxy is not set
            /// </summary>
            AGDPIR_PROXY_NOT_SET,

            /// <summary>
            /// The event loop is not set
            /// </summary>
            AGDPIR_EVENT_LOOP_NOT_SET,

            /// <summary>
            /// The provided address is invalid
            /// </summary>
            AGDPIR_INVALID_ADDRESS,

            /// <summary>
            /// The proxy is empty
            /// </summary>
            AGDPIR_EMPTY_PROXY,

            /// <summary>
            /// There is an error in the protocol
            /// </summary>
            AGDPIR_PROTOCOL_ERROR,

            /// <summary>
            /// Failed to initialize the listener
            /// </summary>
            AGDPIR_LISTENER_INIT_ERROR,

            /// <summary>
            /// The provided IPv4 address is invalid
            /// </summary>
            AGDPIR_INVALID_IPV4,

            /// <summary>
            /// The provided IPv6 address is invalid
            /// </summary>
            AGDPIR_INVALID_IPV6,

            /// <summary>
            /// Failed to initialize the upstream
            /// </summary>
            AGDPIR_UPSTREAM_INIT_ERROR,

            /// <summary>
            /// Failed to initialize the fallback filter
            /// </summary>
            AGDPIR_FALLBACK_FILTER_INIT_ERROR,

            /// <summary>
            /// Failed to load the filter
            /// </summary>
            AGDPIR_FILTER_LOAD_ERROR,

            /// <summary>
            /// The memory limit has been reached
            /// </summary>
            AGDPIR_MEM_LIMIT_REACHED,

            /// <summary>
            /// The filter ID is not unique
            /// </summary>
            AGDPIR_NON_UNIQUE_FILTER_ID,

            /// <summary>
            /// DNS proxy initialization was successful
            /// </summary>
            AGDPIR_OK,
		}

		/// <summary>
		/// Holds out-of-band information about a DNS message or how to process it.
		/// </summary>
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
		internal struct ag_dns_message_info
		{
			/// <summary>
			/// If <c>true</c>, the proxy will handle the message transparently: queries are returned to the caller
			/// instead of being forwarded to the upstream by the proxy, responses are processed as if they were received
			/// from an upstream, and the processed response is returned to the caller.The proxy may return a response
			/// when transparently handling a query if the query is blocked.The proxy may still perform an upstream
			/// query when handling a message transparently, for example, to process CNAME-rewrites.
			/// </summary>
			[MarshalAs(UnmanagedType.I1)]
			internal bool transparent;
		}

		/// <summary>
		/// Callback function for asynchronous message processing.
		/// This function is called on an unspecified thread when a result of `handle_message_async` is ready.
		/// </summary>
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		[return: MarshalAs(UnmanagedType.I4)]
		public delegate void
			ag_handle_message_async_cb(IntPtr pEvent);

		[Flags]
        public enum ag_rule_generation_options : uint
        {
            /// <summary>
            /// Add $important modifier.
            /// </summary>
            AGRGO_IMPORTANT = 1 << 0,

            /// <summary>
            /// Add $dnstype modifier.
            /// </summary>
            AGRGO_DNSTYPE = 1 << 1,
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
		internal static extern void ag_dnsproxy_deinit(IntPtr proxy);

		/// <summary>
		/// Process a DNS message and return the response.
		/// </summary>
		/// <param name="pDnsProxyServer">Proxy server </param>
		/// <param name="message">A DNS message in wire format </param>
		/// <param name="info">Additional parameters</param>
		/// <returns>The DNS response in wire format</returns>
		/// <remarks> The caller is responsible for freeing both buffers with `ag_buffer_free()`</remarks>
		[DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
		internal static extern MarshalUtils.ag_buffer ag_dnsproxy_handle_message(IntPtr pDnsProxyServer,
			MarshalUtils.ag_buffer message, IntPtr info);

		/// <summary>
		/// Process a DNS message and call `handler` on an unspecified thread with the response.
		/// </summary>
		/// <param name="pDnsProxyServer">Proxy server </param>
		/// <param name="message">A DNS message in wire format </param>
		/// <param name="info">Additional parameters</param>
		/// <param name="handler">Callback function for asynchronous message processing.</param>
		/// <remarks> The caller is responsible for freeing  message buffer, but you shouldn't free buffer that will be passed to handler</remarks>
		[DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
		internal static extern void ag_dnsproxy_handle_message_async(IntPtr pDnsProxyServer,
			MarshalUtils.ag_buffer message,
			IntPtr info, ag_handle_message_async_cb handler);

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
		/// <param name="timeout_ms">Maximum amount of time allowed for upstream exchange (in milliseconds)</param>
		/// <param name="ipv6Available">Whether IPv6 is available (i.e., bootstrapper is allowed to make AAAA queries)</param>
		/// <param name="onCertificateVerification">Certificate verification callback
		/// as a <see cref="cbd_onCertificateVerification"/> object</param>
		/// <param name="offline">Don't perform online upstream check</param>
		/// <returns>If it is, no error is returned.
		/// Otherwise this method returns an error with an explanation</returns>
		[DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
		internal static extern IntPtr ag_test_upstream(
			IntPtr pUpstreamOptions,
			[MarshalAs(UnmanagedType.U4)] UInt32 timeout_ms,
			[MarshalAs(UnmanagedType.I1)] bool ipv6Available,
			[MarshalAs(UnmanagedType.FunctionPtr)] cbd_onCertificateVerification onCertificateVerification,
			[MarshalAs(UnmanagedType.I1)] bool offline);

		/// <summary>
		/// Check if the specified rule is valid
		/// </summary>
		/// <param name="ruleText">Rule text</param>
		/// <returns>True, is specified rule is valid, otherwise false</returns>
		[DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
		[return: MarshalAs(UnmanagedType.I1)]
		internal static extern bool ag_is_valid_dns_rule(
			[MarshalAs(
				UnmanagedType.CustomMarshaler,
				MarshalTypeRef = typeof(ManualStringToPtrMarshaler))]
			string ruleText);

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
			[MarshalAs(UnmanagedType.FunctionPtr)] cbd_logger_callback_t callback,
			IntPtr pAttachment);

		#endregion

		#region Rule generation

		/// <summary>
		/// Suggest an action based on filtering log event.
		/// </summary>
		/// <param name="pEvent">The pointer to <see cref="ag_dns_request_processed_event"/> instance.</param>
		/// <returns>
		/// NULL on error. Pointer to <see cref="ag_dns_filtering_log_action"/> instance
		/// freed with <see cref="ag_dns_filtering_log_action_free"/> on success.
		/// </returns>
		[DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
		internal static extern IntPtr ag_dns_filtering_log_action_from_event(IntPtr pEvent);

		/// <summary>
		/// Free an action.
		/// </summary>
		/// <param name="pAction">The pointer to <see cref="ag_dns_filtering_log_action"/>instance.</param>
		[DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
		internal static extern void ag_dns_filtering_log_action_free(IntPtr pAction);

		/// <summary>
		/// Generate a rule from a template (obtained from `ag_dns_filtering_log_action`) and a corresponding event.
		/// </summary>
		/// <param name="template">The pointer to template.</param>
		/// <param name="pEvent">The pointer to <see cref="ag_dns_request_processed_event"/> instance.</param>
		/// <param name="options">The <see cref="ag_rule_generation_options"/></param>
		/// <returns>NULL on error. Rule freed with <see cref="ag_str_free"/> on success</returns>
		[DllImport(DnsLibName, CallingConvention = CallingConvention.Cdecl)]
		internal static extern IntPtr ag_dns_generate_rule_with_options(
			[MarshalAs(
				UnmanagedType.CustomMarshaler,
				MarshalTypeRef = typeof(ManualStringToPtrMarshaler))]
			string template,
			IntPtr pEvent,
			ag_rule_generation_options options);

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
        
        /// <summary>
        /// The subset of <see cref="ag_dnsproxy_settings"/>
        /// available for overriding on a specific listener.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ag_proxy_settings_overrides 
        {
            /// <summary>
            /// Overrides <see cref="ag_dnsproxy_settings.BlockEch"/> if not null
            /// </summary>
            internal IntPtr pBlock_ech;
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
            
            /// <summary>
            /// Overridden settings
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            [NativeName("settings_overrides")]
            internal ag_proxy_settings_overrides settings_overrides;
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
             * This option is only for ANDROID
             * see more in https://jira.adguard.com/browse/AG-15207
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
            
            /// <summary>
            /// (Optional) List of upstreams base64 encoded SPKI fingerprints to verify. If at least one of them is matched in the
            /// certificate chain, the verification will be successful
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            internal MarshalUtils.ag_list fingerprints;
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
            /// Maximum amount of time, in milliseconds, allowed for upstream exchange (0 means default)
            /// </summary>
            [MarshalAs(UnmanagedType.U4)]
            [NativeName("upstream_timeout_ms")]
            internal UInt32 UpstreamTimeoutMs;

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
            ///
            /// Mostly intended for iOS.
            /// If enable_retransmission_handling is true,
            /// retransmitted requests
            /// (defined as requests with the same id and sent from the same address
            /// that one of the requests that are currently being handled)
            /// will be handled only using fallback upstreams, and the answer to the original
            /// request will not be sent (to prevent possibly sending SERVFAIL,
            /// b/c iOS may mark the resolver as "bad" in this case and refuse to resolve
            /// anything from that point).
            /// Enabling this feature shouldn't break anything on Android and Windows,
            /// but it should not be enabled if there are otherwise no issues with retransmitted requests.
            /// </summary>
            [MarshalAs(UnmanagedType.I1)]
            [NativeName("enable_retransmission_handling")]
            internal bool EnableRetransmissionHandling;

            /// <summary>
            /// If enabled, strip Encrypted Client Hello parameters from responses.
            /// </summary>
            [MarshalAs(UnmanagedType.I1)]
            [NativeName("block_ech")]
            internal bool BlockEch;

            /// <summary>
            /// If true, all upstreams are queried in parallel, and the first response is returned.
            /// </summary>
            [MarshalAs(UnmanagedType.I1)]
            [NativeName("enable_parallel_upstream_queries")]
            internal bool EnableParallelUpstreamQueries;

            /// <summary>
            /// If true, normal queries will be forwarded to fallback upstreams if all normal upstreams failed.
            /// Otherwise, fallback upstreams will only be used to resolve domains from `fallback_domains`.
            /// </summary>
            [MarshalAs(UnmanagedType.I1)]
            [NativeName("enable_fallback_on_upstreams_failure")]
            internal bool EnableFallbackOnUpstreamsFailure;

            /// <summary>
            /// If true, when all upstreams (including fallback upstreams) fail to provide a response,
            /// the proxy will respond with a SERVFAIL packet. Otherwise, no response is sent on such a failure.
            /// In any case, the proxy will never respond with a SERVFAIL packet due to all upstreams timing out,
            /// nor to a request that has been retransmitted.
            /// </summary>
            [MarshalAs(UnmanagedType.I1)]
            [NativeName("enable_servfail_on_upstreams_failure")]
            internal bool EnableServfailOnUpstreamsFailure;

            /// <summary>
            /// Enable HTTP/3 for DNS-over-HTTPS upstreams if it's able to connect quicker.
            /// </summary>
            [MarshalAs(UnmanagedType.I1)]
            [NativeName("enable_http3")]
            internal bool EnableHttp3;
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
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ag_dns_filtering_log_action
        {
            /// <summary>
            /// A set of rule templates.
            /// </summary>
            [NativeName("templates")]
            [MarshalAs(UnmanagedType.Struct)]
            internal MarshalUtils.ag_list Templates;

            /// <summary>
            /// Options that are allowed to be passed to `generate_rule`.
            /// </summary>
            [NativeName("allowed_options")]
            [MarshalAs(UnmanagedType.U4)]
            internal ag_rule_generation_options AllowedOptions;

            /// <summary>
            /// Options that are required for the generated rule to be correct.
            /// </summary>
            [NativeName("required_options")]
            [MarshalAs(UnmanagedType.U4)]
            internal ag_rule_generation_options RequiredOptions;

            /// <summary>
            /// Whether something will be blocked or un-blocked as a result of this action.
            /// </summary>
            [NativeName("blocking")]
            [MarshalAs(UnmanagedType.I1)]
            internal bool IsBlocking;
        }

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

        /// <summary>
        /// Listener protocols for the networking system.
        /// </summary>
        public enum ag_listener_protocol
        {
            /// <summary>
            /// UDP protocol
            /// </summary>
            AGLP_UDP,

            /// <summary>
            /// TCP protocol
            /// </summary>
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

        /// <summary>
        /// Defines the possible results of certificate verification.
        /// </summary>
        public enum ag_certificate_verification_result
        {
            /// <summary>
            /// OK: Certificate verification was successful
            /// </summary>
            AGCVR_OK,

            /// <summary>
            /// Error: Failed to create a certificate object
            /// </summary>
            AGCVR_ERROR_CREATE_CERT,

            /// <summary>
            /// Error: Failed to access the certificate store
            /// </summary>
            AGCVR_ERROR_ACCESS_TO_STORE,

            /// <summary>
            /// Error: Certificate verification failed
            /// </summary>
            AGCVR_ERROR_CERT_VERIFICATION,

            /// <summary>
            /// Count: The total number of enumeration values
            /// </summary>
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
