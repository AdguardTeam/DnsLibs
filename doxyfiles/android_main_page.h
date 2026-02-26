/**
@mainpage DNS Libs API Documentation for Android

@section intro Introduction
This document outlines the main functionality and usage of the DNS proxy and filtering library designed for Android devices.
The library provides DNS filtering with ad blocking capabilities, support for modern DNS protocols, and VPN-based DNS tunneling.

@section components Main Components

@subsection dnsproxy DnsProxy
The main DNS proxy class that handles DNS query processing, filtering, and forwarding to upstream servers.

Key features:
- DNS query filtering with AdBlock-style rules
- Multiple upstream protocols (DoH, DoT, DNSCrypt, plain DNS)
- DNS64 support for IPv6-only networks
- DNSSEC validation
- HTTP/3 and Post-Quantum cryptography support
- Optimistic caching for improved performance

See @ref com.adguard.dnslibs.proxy.DnsProxy class for the main API and 
@ref com.adguard.dnslibs.proxy.DnsProxySettings for configuration options.

@subsection dnstun DnsTunListener
TUN interface listener for VPN-based DNS filtering. Handles both UDP and TCP DNS traffic from a TUN device,
enabling system-wide DNS filtering through Android's VPN service.

See @ref com.adguard.dnslibs.proxy.DnsTunListener for implementation details.

@section workflow Overview of Workflows

@subsection workflow_proxy DNS Proxy Mode

This mode allows your application to act as a local DNS proxy, filtering DNS queries before forwarding them to upstream servers.

1. **Create settings**: Initialize @ref com.adguard.dnslibs.proxy.DnsProxySettings with desired configuration
   - Configure upstream DNS servers using @ref com.adguard.dnslibs.proxy.UpstreamSettings
   - Set up listeners using @ref com.adguard.dnslibs.proxy.ListenerSettings
   - Configure filtering rules using @ref com.adguard.dnslibs.proxy.FilterParams
   - Choose blocking mode using @ref com.adguard.dnslibs.proxy.DnsProxySettings.BlockingMode

2. **Initialize proxy**: Create @ref com.adguard.dnslibs.proxy.DnsProxy instance
   ```java
   DnsProxy proxy = new DnsProxy(context, settings, events);
   ```

3. **Handle DNS queries**: Process DNS messages using one of:
   - @ref com.adguard.dnslibs.proxy.DnsProxy.handleMessage() for synchronous processing
   - @ref com.adguard.dnslibs.proxy.DnsProxy.handleMessageAsync() for asynchronous processing

4. **Monitor events**: Implement @ref com.adguard.dnslibs.proxy.DnsProxyEvents to receive:
   - @ref com.adguard.dnslibs.proxy.DnsRequestProcessedEvent for processed requests
   - Certificate verification callbacks

5. **Update settings**: Use @ref com.adguard.dnslibs.proxy.DnsProxy.reapplySettings() to update configuration without reinitialization

6. **Cleanup**: Call @ref com.adguard.dnslibs.proxy.DnsProxy.close() to release resources

@subsection workflow_vpn VPN Tunnel Mode

This mode enables system-wide DNS filtering by intercepting DNS traffic through Android's VPN service.

1. **Set up VPN tunnel**: Use Android's VpnService.Builder to create a TUN interface
   ```java
   VpnService.Builder builder = new VpnService.Builder();
   builder.addAddress("10.0.0.2", 32);
   builder.addRoute("0.0.0.0", 0);
   ParcelFileDescriptor tunFd = builder.establish();
   ```

2. **Initialize DnsProxy**: Create DNS proxy instance for filtering (same as proxy mode)

3. **Create TUN listener**: Initialize @ref com.adguard.dnslibs.proxy.DnsTunListener with TUN file descriptor
   ```java
   DnsTunListener listener = new DnsTunListener(
       tunFd.getFd(),
       1500,  // MTU
       (request, replyHandler) -> {
           // Process DNS request through DnsProxy
           proxy.handleMessageAsync(request, null, replyHandler::onReply);
       }
   );
   ```

4. **Handle requests**: The listener automatically processes DNS traffic from the TUN interface
   - UDP and TCP DNS queries are intercepted
   - Requests are passed to your @ref com.adguard.dnslibs.proxy.DnsTunListener.RequestCallback
   - Responses are sent back through @ref com.adguard.dnslibs.proxy.DnsTunListener.ReplyHandler

5. **Cleanup**: Close both listener and proxy when done
   ```java
   listener.close();
   proxy.close();
   ```

@section configuration Detailed Configuration Options

@subsection upstream_config Upstream DNS Servers

Configure upstream DNS servers using @ref com.adguard.dnslibs.proxy.UpstreamSettings:
- Plain DNS: `8.8.8.8`, `1.1.1.1`
- DNS-over-HTTPS: `https://dns.adguard-dns.com/dns-query`
- DNS-over-TLS: `tls://dns.adguard-dns.com`
- DNSCrypt: `sdns://...`

Bootstrap servers can be specified to resolve DoH/DoT hostnames.

@subsection filtering_config Filtering Configuration

Set up DNS filtering using @ref com.adguard.dnslibs.proxy.FilterParams:
- Load filter lists from files or memory
- Configure filter IDs for tracking
- Enable/disable specific filters

Choose blocking behavior with @ref com.adguard.dnslibs.proxy.DnsProxySettings.BlockingMode:
- `REFUSED`: Return REFUSED response code
- `NXDOMAIN`: Return NXDOMAIN response code
- `ADDRESS`: Return zero address or custom blocking address
- `UNSPECIFIED_ADDRESS`: Always return zero address

@subsection caching_config Caching Options

Configure DNS caching in @ref com.adguard.dnslibs.proxy.DnsProxySettings:
- Set cache size with `setDnsCacheSize()`
- Enable optimistic cache with `setOptimisticCache()`
- Control blocked response TTL with `setBlockedResponseTtlSecs()`

@subsection logging Logging Setup

Control logging verbosity using @ref com.adguard.dnslibs.proxy.DnsProxy.setLogLevel():
- `ERROR`, `WARN`, `INFO`, `DEBUG`, `TRACE`

Set custom logging callback with @ref com.adguard.dnslibs.proxy.DnsProxy.setLoggingCallback()

@section advanced_features Advanced Features

@subsection dns64 DNS64 Support

Enable DNS64 for IPv6-only networks using @ref com.adguard.dnslibs.proxy.Dns64Settings.
DNS64 synthesizes AAAA records from A records when needed.

@subsection dnssec DNSSEC Validation

Enable DNSSEC validation with `setEnableDNSSECOK()` in @ref com.adguard.dnslibs.proxy.DnsProxySettings.

@subsection http3 HTTP/3 Support

Enable HTTP/3 for DoH upstreams with `setEnableHttp3()` for improved performance.

@subsection pq Post-Quantum Cryptography

Enable post-quantum cryptography support with `setEnablePostQuantumCryptography()` for future-proof security.

@subsection rule_generation Dynamic Rule Generation

Generate filtering rules dynamically:
- Use @ref com.adguard.dnslibs.proxy.DnsProxy.filteringLogActionFromEvent() to analyze events
- Generate rules with @ref com.adguard.dnslibs.proxy.DnsProxy.generateRuleWithOptions()
- Validate rules with @ref com.adguard.dnslibs.proxy.DnsProxy.isValidRule()

@subsection upstream_testing Upstream Testing

Test upstream server availability before use:
- @ref com.adguard.dnslibs.proxy.DnsProxy.testUpstream() validates upstream configuration
- Checks connectivity and protocol support
- Configurable timeout and IPv6 availability

@section utilities Utility Functions

@subsection version Version Information
Get library version with @ref com.adguard.dnslibs.proxy.DnsProxy.version()

@subsection network_utils Network Utilities
Use @ref com.adguard.dnslibs.proxy.DnsNetworkUtils for network-related operations:
- Detect DNS search domains
- Query network configuration

@subsection dns_stamps DNS Stamps
Parse and work with DNS stamps using @ref com.adguard.dnslibs.proxy.DnsStamp for DNSCrypt server configuration.

*/
