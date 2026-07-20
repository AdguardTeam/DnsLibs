# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

### Changed

- Updated NLC to 8.1.44.
- Changed the default `adblock_rules_blocking_mode` from `REFUSED` to `UNSPECIFIED_ADDRESS` for all platforms.
    - Previously, only Windows used `UNSPECIFIED_ADDRESS` to avoid issues with the system resolver trying other servers and AdGuard VPN blocking those requests.
    - On other platforms, responding with `REFUSED` caused some applications to endlessly retry blocked requests, leading to increased CPU and battery consumption.

### Deprecated

### Removed

### Fixed

### Security

## [2.8.58] - 2026-06-29

### Changed

- Updated NLC to 8.1.38.

## [2.8.57] - 2026-06-25

### Fixed

- Fixed deploy for Windows.

## [2.8.56] - 2026-06-24

- Updated NLC to 8.1.36.

## [2.8.55] - 2026-06-10

### Changed

- Updated ngtcp2 dependency used in DoQ/DoH3.

## [2.8.54] - 2026-06-08

### Fixed

- Fixed build on GCC 15.1.

## [2.8.53] - 2026-06-04

### Added

- Added `autotag.yml` workflow for automatic tagging when a new version is added to CHANGELOG.
- Added `create-release-pr.yml` workflow for manual release PR creation.
- Added public crash helpers to `DnsProxy` for testing fatal error handling.
    - [Android] See `com.adguard.dnslibs.proxy.DnsProxy.crash()`.
    - [Apple] See `+[AGDnsProxy crash]`.
    - [Windows C API] See `ag_dnsproxy_crash()`.
    - [Windows C#] See `DnsProxyServer.Crash()`.

### Changed

- Converted CHANGELOG.md to [Keep a Changelog](https://keepachangelog.com/) format.
- Renamed `increment_version.sh` to `set_version.sh` with explicit version argument.
- Optimized conan upload steps: removed cleanup since container will anyway be destroyed.

### Removed

- Removed `increment-version.yml` workflow that auto-incremented version on every commit.
- Removed `conandata.yml` since conan export is now tag-based, not revision-based.

## [2.8.52] - 2026-05-08

### Changed

- Updated project layout to be agent-friendly (added `AGENTS.md`).

### Fixed

- Fix `Uv`/`UvPtr` to handle RAII of uninitialized C uv handle.

### Security

- Mask upstream password in log messages to avoid leaking credentials in debug logs.

## [2.8.45] - 2026-03-25

### Fixed

- Fix bugs in co_connect in upstream_dot (AG-49394).

## [2.8.37] - 2026-03-06

### Added

- Added an example of a helper program that allows to automatically route DNS traffic to the DNS proxy on Windows. See `platform/windows/capi/README.md` for details.

## [2.8.19] - 2026-02-03

### Changed

- Refactored `reapply_settings` to use `ReapplyOptions` enum.
    - Options: `RO_SETTINGS` (reload DNS settings except listeners and filters), `RO_FILTERS` (reload filters).
    - Can combine flags using bitwise OR to reload multiple components.
    - [C API] See `ag_dnsproxy_reapply_options` (`AGDPRO_NONE`, `AGDPRO_SETTINGS`, `AGDPRO_FILTERS`) and `ag_dnsproxy_reapply_settings`.
    - [Android] See `DnsProxy.ReapplyOption` enum and `DnsProxy#reapplySettings(DnsProxySettings, EnumSet<ReapplyOption>)`.
    - [Apple] See `AGDnsProxyReapplyOptions` (`AGDnsProxyReapplyNone`, `AGDnsProxyReapplySettings`, `AGDnsProxyReapplyFilters`) and `AGDnsProxy.reapplySettings`.
    - [Windows C#] See `ag_dnsproxy_reapply_options` and `DnsProxyServer.ReapplySettings`.

## [2.8.17] - 2026-01-27

### Added

- Added `AGDnsAppProxyFlowManager` for Apple platforms to support DNS proxying via Network Extension App Proxy flows.
    - Needed to handle `NEAppProxyTCPFlow`/`NEAppProxyUDPFlow` modes (redirect/bypass/filter) and integrate them with `AGDnsProxy`.
    - See `documentation/DNS_PROXY_PROVIDER.md`.
- Added TUN listener which properly handles TCP DNS packets.
    - [Android] See `DnsTunListener`
    - [Apple] See `AGDnsTunListener`
- Added new function reapply_settings to update upstreams list without reloading filters.
    - [C API] See `ag_dnsproxy_reapply_settings`.
    - [Android] See `com.adguard.dnslibs.proxy.DnsProxy#reapplySettings`.
    - [Apple] See `AGDnsProxy.reapplySettings`.
- Added `blocking_reason` field to `DnsRequestProcessedEvent` to indicate why a DNS request was blocked.
    - New enum `DnsBlockingReason` with values:
        - `NONE` - request was not blocked
        - `MOZILLA_DOH_DETECTION` - blocked Mozilla DoH detection
        - `DDR` - blocked DDR (Discovery of Designated Resolvers)
        - `IPV6` - blocked IPv6 request (when `block_ipv6` option is enabled)
        - `QUERY_MATCHED_BY_RULE` - domain name in the query matched a filtering rule
        - `CNAME_MATCHED_BY_RULE` - CNAME in the response matched a filtering rule
        - `IP_MATCHED_BY_RULE` - IP address in the response matched a filtering rule
        - `HTTPS_MATCHED_BY_RULE` - HTTPS record matched a filtering rule
    - [C API] See `ag_dns_blocking_reason` and `ag_dns_request_processed_event::blocking_reason`.
    - [Android] See `com.adguard.dnslibs.proxy.DnsBlockingReason` and `com.adguard.dnslibs.proxy.DnsRequestProcessedEvent#getBlockingReason`.
    - [Apple] See `AGDnsBlockingReason` and `AGDnsRequestProcessedEvent.blockingReason`.
    - [Windows] See `ag_dns_blocking_reason` and `DnsRequestProcessedEventArgs.BlockingReason`.

## [2.7] - 2025-11-25

### Added

- Added support for post-quantum cryptography (ML-KEM-768).
    - The hybrid scheme X25519 + ML-KEM-768 is now supported for DNS-over-TLS, DNS-over-HTTPS, and DNS-over-QUIC protocols.
    - Enabled by default on all platforms.
    - [C API] See `ag_dnsproxy_settings::enable_post_quantum_cryptography`.
    - [Android] See `com.adguard.dnslibs.proxy.DnsProxySettings#setEnablePostQuantumCryptography`.
    - [Apple] See `AGDnsProxyConfig.enablePostQuantumCryptography`.
    - [Windows] See `DnsProxySettings.EnablePostQuantumCryptography`.
- Added option to block HTTP/3 by removing "h3" from ALPN parameter in HTTPS records.
    - [C API] See `ag_dnsproxy_settings::block_h3_alpn`.
    - [Android] See `com.adguard.dnslibs.proxy.DnsProxySettings#setBlockH3Alpn`.
    - [Apple] See `AGDnsProxyConfig.blockH3Alpn`.
    - [Windows] See `DnsProxySettings.BlockH3Alpn`.
- Added socket protection callback to prevent routing loops when using system-wide proxy rules.

## [2.6] - 2025-10-07

### Changed

- For non-SDNS urls server properties is now null. It can be set later using `set_server_properties()`.
    - [C API] See `ag_dns_stamp`.
    - [Android] `DnsStamp::getProperties` became nullable. See `com.adguard.dnslibs.proxy.DnsStamp#getProperties`.
    - [Apple] Use new enum with properties. See `AGServerInformalProperties` and `AGDnsStamp`.
- A callback must now be set to enable logging on Android.
    - [Android] See `com.adguard.dnslibs.proxy.DnsProxy#setLoggingCallback`.

## [2.5] - 2025-02-06

### Added

- Added a new blocking mode: `UNSPECIFIED_ADDRESS`. The new mode should be made selectable in the UI.
    - [Android] See `com.adguard.dnslibs.proxy.DnsProxySettings.BlockingMode#UNSPECIFIED_ADDRESS`.
    - [Apple] See `AGBM_UNSPECIFIED_ADDRESS`.
    - [C API] See `AGBM_UNSPECIFIED_ADDRESS`.

### Changed

- Default for option enable_servfail_on_upstreams_failure is changed to off. Please ensure that you use DnsLibs-provided defaults.
- The default blocking mode on Windows changed to `UNSPECIFIED_ADDRESS`. The default should also be updated in the Windows UI.
- Removed `ag::dns::OutboundProxySettings::ignore_if_unavailable`. Also removed the corresponding fields from platform-specific adapters.

## [2.4] - 2024-02-22

### Added

- Added an option to do transparent filtering. See `ag::dns::DnsMessageInfo::transparent` for details.
- Added an async (callback-based) message-handling interface to adapters.
    - [Android] See `com.adguard.dnslibs.proxy.DnsProxy#handleMessageAsync`.
    - [Apple] See `-[AGDnsProxy handleMessage:withInfo:withCompletionHandler:]`.
    - [C API] See `ag_dnsproxy_handle_message_async`.
- Improved DNS Fallback Mechanism. Added logic to retry DNS queries over TCP if initial UDP attempts are unsuccessful or return incomplete data.
- Support for Basic Authentication in DNS-over-HTTPS. Username and password can now be passed directly in the address. Compatible with both HTTPS URLs and DNS Stamps. Example configurations:
    - `https://username:password@dns.google/dns-query`
    - `sdns://username:password@AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5`

## [2.3] - 2023-11-07

### Added

- Added filtering of IP hints in HTTPS RR type DNS records. IP hints in HTTPS RR type DNS records can now be filtered like it is done for A and AAAA records.

### Changed

- DNS-over-HTTPS upstream has been fully rewritten from libcurl to NativeLibsCommon HTTP module.
    - Stability improved in HTTP/3 mode.
    - HTTP/3 mode now supports connecting via outbound proxy.
- Outbound network interface name is now a required property on iOS.
    - [Apple/iOS] See `AGDnsUpstream.outboundInterfaceName`.

### Fixed

- Localhost upstreams can now be used even if outbound proxy is set.

## [2.2] - 2023-09-26

### Added

- Added a workaround for incompatibility between ECH features of CoreLibs and DnsLibs. The correct set-up expects an application creates an additional TCP listener with settings overrides with `blockEch` set to `false`, if "block ECH" feature in DnsLibs and "enable ECH" feature in CoreLibs are enabled simultaneously.
    - [Android] See `ListenerSettings.setSettingsOverrides()`/`getSettingsOverrides()`.
    - [Apple] See `AGListenerSettings.settingsOverrides`.
    - [C API] See `ag_listener_settings.settings_overrides`.
- Upstream exchange timeout is now specified separately from the upstream options. The signature of some functions is changed as a result.
    - [Android] See `com.adguard.dnslibs.proxy.DnsProxySettings#setUpstreamTimeoutMs`/`com.adguard.dnslibs.proxy.DnsProxySettings#getUpstreamTimeoutMs`. See `com.adguard.dnslibs.proxy.DnsProxy#testUpstream`.
    - [Apple] See `AGDnsProxyConfig.upstreamTimeoutMs`. See `[AGDnsUtils testUpstream:]`.
    - [C API] See `ag_dnsproxy_settings::upstream_timeout_ms`. See `ag_test_upstream`.
- Implemented fingerprints verification for two types of fingerprints for encrypted DNS protocols.
    1. SPKI fingerprint, set separately in the upstream options, compared with the sha256 hash of the `SubjectPublicKeyInfo` certificate part. It is possible to transfer several such fingerprints, they will try to get matched with one of the certificates in the chain.
    2. The fingerprint of the certificate in full, which is passed as one of the DNS Stamp fields. Compared with sha256 hashes of the entire certificate.
    - [C API] See `ag_upstream_options.fingerprints`
    - [Apple] See `AGDnsUpstream.fingerprints`
    - [Android] See `UpstreamSettings.fingerprints`
    - How it is used: Computes the Fingerprints (for the public keys/ for full certificate) found in the server's certificate chain. If a computed fingerprint exactly matches one of the configured pins the chain is successfully verified.
- Made the API more XPC-friendly (without breaking changes) and added some boilerplate to help setup the DNS proxy as an XPC endpoint.

### Changed

- Changed the signature of `com.adguard.dnslibs.proxy.DnsProxy` constructor: now throws a `com.adguard.dnslibs.proxy.DnsProxyInitException` on failure, containing the same info as the native error.

## [2.1] - 2023-05-03

### Added

- Added an option to try HTTP/3 for DoH upstream connections. If enabled, HTTP/3 will be used for DoH if it's faster. See `DnsProxySettings::enable_http3`, `AGDnsProxyConfig.enableHttp3`, `com.adguard.dnslibs.proxy.DnsProxySettings#enableHttp3`, `ag_dnsproxy_settings::enable_http3`.
- Added an option to query upstreams in parallel. See `DnsProxySettings::enable_parallel_upstream_queries` and the corresponding options in platform-specific adapters.
- Added an option to change fallback behaviour. See `DnsProxySettings::enable_fallback_on_upstreams_failure` and the corresponding options in platform-specific adapters.
- Added an option to change the behaviour when upstreams fail to yield a response. See `DnsProxySettings::enable_servfail_on_upstreams_failure` and the corresponding options in platform-specific adapters.
- A non-standard `h3://` URL scheme can now be used to force a DoH upstream to use HTTP/3.
- Now DnsProxy.init() returns more informative error code with description.
    - [C API] See `DnsProxy.DnsProxyInitResult`
    - [Apple] See `AGDnsProxyError`
    - [Android] See `ag_dnsproxy_init_result`

## [2.0] - 2023-01-17

### Added

- Added an option to strip Encrypted Client Hello parameters from responses, effectively blocking ECH.
    - [C API] See `ag_dnsproxy_settings::block_ech`
    - [Apple] See `AGDnsProxyConfig.blockEch`
    - [Android] See `DnsProxySettings.setBlockEch()`.
- DnsProxy now accepts a hostname as an address of the outbound proxy. In that case an application should also pass a list of the bootstrapping resolvers.

### Changed

- DnsProxy calls are now asynchronous. On iOS `[handlePacket:completionHandler:]` should be called instead of synchronous one.
- The DoQ upstream now uses the port 853 by default (was 8853), conforms to RFC-9250, and doesn't support ALPNs other than "doq". ACHTUNG: Some changes might be required on the application side due to the default port change.

## [1.7.28] - 2022-04-29

### Added

- Route resolver on Apple platforms can now be enabled via `AGDnsProxySettings.enableRouteResolver`.

## [1.7.0] - 2022-01-21

### Added

- In the settings returned by `dnsproxy::get_settings()`, listener settings now contain the actual port that each listener is listening on.

## [1.6] - 2021-09-22

### Added

- Added an ability to route DNS queries directly to a target host in case the configured proxy server is determined as unavailable. Mostly intended for Android.
    - [Android] See `OutboundProxySettings`
    - [C API] See `ag_outbound_proxy_settings`
- Split the blocking mode setting into separate settings for AdBlock-style and hosts-style rules.
    - Also remove the redundant `CUSTOM_ADDRESS` blocking mode: now if a custom blocking address is specified, it will simply be used where an all-zeroes address would have been used otherwise.
    - WARNING: the `DEFAULT` blocking mode has been removed. The default blocking mode for both rule types is now obtained with `ag::DnsProxySettings::get_default()`/`DnsProxySettings.getDefault()`/`AGDnsProxyConfig.getDefault()`/`ag_dnsproxy_settings_get_default()`.

### Fixed

- Accept IPv6 availability parameter in upstream testing methods. Note that the API has changed, see `com.adguard.dnslibs.proxy.DnsProxy#testUpstream`, `+[AGDnsUtils testUpstream:ipv6Available:]`, `ag_test_upstream`.

## [1.5] - 2021-05-24

### Added

- Fallback-only domains. See `fallbackDomains` or `fallback_domains` in respective adapters.
    - This is a list of domains (limited wildcards allowed) that will be forwarded directly to the fallback upstreams (if they exist).
    - There's also an option to automatically append DNS search domains to this list, see `detectSearchDomains` (Android and Apple only, Windows adapter handles search domains on its own).
    - WARNING: Note to application developers: you MUST get the default value of this field from `DnsProxySettings::get_default()`/`DnsProxySettings.getDefault()`/`AGDnsProxyConfig.getDefault()` as it contains important default for Wi-Fi calling, but we can't add them automatically, because the user must see the defaults in UI and be able to edit them.
- Retransmission handling: see `enableRetransmissionHandling` or `enable_retransmission_handling`. Mostly intended for iOS. If `enable_retransmission_handling` is true, retransmitted requests (defined as requests with the same id and sent from the same address that one of the requests that are currently being handled) will be handled only using fallback upstreams, and the answer to the original request will not be sent (to prevent possibly sending SERVFAIL, b/c iOS may mark the resolver as "bad" in this case and refuse to resolve anything from that point). Enabling this feature shouldn't break anything on Android and Windows, but it should not be enabled if there are otherwise no issues with retransmitted requests.
- Added an ability to set up outbound proxy.
    - [Android] see `OutboundProxySettings`
    - [Apple] see `AGOutboundProxySettings`
    - [C API] see `ag_outbound_proxy_settings`
- DNS stamp API has been reworked in adapters: DNS stamps can now be dynamically edited and converted to various string representations.
- DNSLibs indicate that upstream uses DNSSEC. Turn on `ag::DnsProxySettings::enable_dnssec_ok` and check `ag::DnsRequestProcessedEvent::dnssec` in callback.
- DNS-over-QUIC default port changed. New port is 8853. Now an address like `quic://dns.adguard.com` is transformed into `quic://dns.adguard.com:8853`. So to force the use of the old port `784` specify it strictly - `quic://dns.adguard.com:784`.
- Allow retrieving the library version.
    - see `ag::dnsproxy::version()`
    - see `AGDnsProxy.libraryVersion` (Apple)
    - see `com.adguard.dnsproxy.DnsProxy.version()` (Android)
    - see `ag_dnsproxy_version()` (C API)
- Added a "pretty URL" function for DNS stamps.
    - see `ag::ServerStamp::pretty_url()`
    - see `AGDnsStamp.prettyUrl`, `AGDnsStamp.prettierUrl` (Apple)
    - see `com.adguard.dnsproxy.DnsStamp.getPrettyUrl()`, `com.adguard.dnsproxy.DnsStamp.getPrettierUrl()` (Android)
    - see `ag_dns_stamp::pretty_url`, `ag_dns_stamp::prettier_url` (C API)

## [1.4] - 2020-10-07

### Added

- API change: allow in-memory filters. See `ag::dnsfilter::FilterParams`.
- Optimistic DNS caching. See `ag::DnsProxySettings::optimistic_cache`.

[Unreleased]: https://github.com/AdguardTeam/DnsLibs/compare/v2.8.58...HEAD
[2.8.58]: https://github.com/AdguardTeam/DnsLibs/compare/v2.8.57...v2.8.58
[2.8.57]: https://github.com/AdguardTeam/DnsLibs/compare/v2.8.56...v2.8.57
[2.8.56]: https://github.com/AdguardTeam/DnsLibs/compare/v2.8.55...v2.8.56
[2.8.55]: https://github.com/AdguardTeam/DnsLibs/compare/v2.8.54...v2.8.55
[2.8.54]: https://github.com/AdguardTeam/DnsLibs/compare/v2.8.53...v2.8.54
[2.8.53]: https://github.com/AdguardTeam/DnsLibs/compare/v2.8.52...v2.8.53
[2.8.52]: https://github.com/AdguardTeam/DnsLibs/compare/v2.8.45...v2.8.52
[2.8.45]: https://github.com/AdguardTeam/DnsLibs/compare/v2.8.37...v2.8.45
[2.8.37]: https://github.com/AdguardTeam/DnsLibs/compare/v2.8.19...v2.8.37
[2.8.19]: https://github.com/AdguardTeam/DnsLibs/compare/v2.8.17...v2.8.19
[2.8.17]: https://github.com/AdguardTeam/DnsLibs/compare/v2.7.12...v2.8.17
[2.7]: https://github.com/AdguardTeam/DnsLibs/compare/v2.6.22...v2.7.12
[2.6]: https://github.com/AdguardTeam/DnsLibs/compare/v2.5.63...v2.6.22
[2.5]: https://github.com/AdguardTeam/DnsLibs/compare/v2.4.50...v2.5.63
[2.4]: https://github.com/AdguardTeam/DnsLibs/compare/v2.3.8...v2.4.50
[2.3]: https://github.com/AdguardTeam/DnsLibs/compare/v2.2.36...v2.3.8
[2.2]: https://github.com/AdguardTeam/DnsLibs/compare/v2.1.44...v2.2.36
[2.1]: https://github.com/AdguardTeam/DnsLibs/compare/v2.0.76...v2.1.44
[2.0]: https://github.com/AdguardTeam/DnsLibs/compare/v1.7.43...v2.0.76
[1.7.28]: https://github.com/AdguardTeam/DnsLibs/compare/v1.7.22...v1.7.28
[1.7.0]: https://github.com/AdguardTeam/DnsLibs/compare/v1.6.72...v1.7.0
[1.6]: https://github.com/AdguardTeam/DnsLibs/compare/v1.5.44...v1.6.72
[1.5]: https://github.com/AdguardTeam/DnsLibs/compare/v1.4.33.1...v1.5.44
[1.4]: https://github.com/AdguardTeam/DnsLibs/compare/v1.3.27...v1.4.33.1
