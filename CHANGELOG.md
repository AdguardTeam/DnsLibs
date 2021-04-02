# Changelog

## V1.5
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
