# Changelog

* [Feature] Add an ability to route DNS queries directly to a target host in case the configured
            proxy server is determined as unavailable. Mostly intended for Android.
    * [Android] See `OutboundProxySettings`
    * [C API] See `ag_outbound_proxy_settings`

## V1.6
* [Fix] Accept IPv6 availability parameter in upstream testing methods.
    * Note that the API has changed, see `com.adguard.dnslibs.proxy.DnsProxy#testUpstream`, `+[AGDnsUtils testUpstream:ipv6Available:]`, `ag_test_upstream`.
* [Feature] Split the blocking mode setting into separate settings for AdBlock-style and hosts-style rules.
    * Also remove the redundant `CUSTOM_ADDRESS` blocking mode: now if a custom blocking address is specified,
    it will simply be used where an all-zeroes address would have been used otherwise.
    * WARNING: the `DEFAULT` blocking mode has been removed. The default blocking mode for both rule types
    is now obtained with `ag::dnsproxy_settings::get_default()`/`DnsProxySettings.getDefault()`
      /`AGDnsProxyConfig.getDefault()`/`ag_dnsproxy_settings_get_default()`
## V1.5
* [Feature] Fallback-only domains. See `fallbackDomains` or `fallback_domains` in respective adapters.
    * This is a list of domains (limited wildcards allowed) that will be forwarded directly to the fallback upstreams (if they exist).
    * There's also an option to automatically append DNS search domains to this list, see `detectSearchDomains` (Android and Apple only, Windows adapter handles search domains on its own).
  * WARNING: Note to application developers: you MUST get the default value of this field
    from `dnsproxy_settings::get_default()`/`DnsProxySettings.getDefault()`/`AGDnsProxyConfig.getDefault()`
    as it contains important default for Wi-Fi calling, but we can't add them automatically, because the user must see the defaults in UI and be able to edit them.
  
* [Features] Retransmission handling: see `enableRetransmissionHandling` or `enable_retransmission_handling`.
    Mostly intended for iOS.
    If `enable_retransmission_handling` is true, retransmitted requests (defined as requests with the same id and sent from the same address that one of the requests that are currently being handled) will be handled only using fallback upstreams, and the answer to the original request will not be sent (to prevent possibly sending SERVFAIL, b/c iOS may mark the resolver as "bad" in this case and refuse to resolve anything from that point).
    Enabling this feature shouldn't break anything on Android and Windows, but it should not be enabled if there are otherwise no issues with retransmitted requests.
* [Feature] Add an ability to set up outbound proxy
    * [Android] see `OutboundProxySettings`
    * [Apple] see `AGOutboundProxySettings`
    * [C API] see `ag_outbound_proxy_settings`
* [Feature] DNS stamp API has been reworked in adapters: DNS stamps can now be
            dynamically edited and converted to various string representations.
* [Feature] DNSLibs indicate that upstream uses DNSSEC. Turn on `ag::dnsproxy_settings::enable_dnssec_ok`
    and check `ag::dns_request_processed_event::dnssec` in callback.
* [Feature] DNS-over-QUIC default port changed. New port is 8853.
    Now an address like `quic://dns.adguard.com` is transformed into `quic://dns.adguard.com:8853`.
    So to force the use of the old port `784` specify it strictly - `quic://dns.adguard.com:784`.
* [Feature] Allow retrieving the library version
    * see `ag::dnsproxy::version()`
    * see `AGDnsProxy.libraryVersion` (Apple)
    * see `com.adguard.dnsproxy.DnsProxy.version()` (Android)
    * see `ag_dnsproxy_version()` (C API)
* [Feature] Add a "pretty URL" function for DNS stamps
    * see `ag::server_stamp::pretty_url()`
    * see `AGDnsStamp.prettyUrl`, `AGDnsStamp.prettierUrl` (Apple)
    * see `com.adguard.dnsproxy.DnsStamp.getPrettyUrl()`,
          `com.adguard.dnsproxy.DnsStamp.getPrettierUrl()` (Android)
    * see `ag_dns_stamp::pretty_url`, `ag_dns_stamp::prettier_url` (C API)

## V1.4
* [Feature] API change: allow in-memory filters<p>
    see `ag::dnsfilter::filter_params`
* [Feature] Optimistic DNS caching<p>
    see `ag::dnsproxy_settings::optimistic_cache`
