# NEDnsProxyProvider support

You may want to implement a DNS proxy provider in your app.

This manual provides information on how to do so.

## macOS

On macOS, `NEDNSProxyProvider` is hosted in a **System Extension**.

You need a network extension of type "System Extension" with the following entitlements:

- Network Extensions entitlement with `com.apple.networkextension.dns-proxy` capability enabled.
- System Extension entitlement.

You also need the same capabilities in your app's entitlements to be able to install/update the System Extension
and create DNS proxy configuration.

Typical steps to make it run are:

1. Install or update the System Extension using `OSSystemExtensionRequest`.
2. Create or update the DNS proxy configuration using `NEDNSProxyManager`. The system will start/stop the DNS proxy
   automatically based on whether it is enabled. You can control it by changing the `enabled` field of the
   configuration.

The created DNS proxy configuration can be disabled and deleted by the app and by the user.

A working sample is included in the macOS test app:

- `platform/mac/DnsLibsTestApp/`

The test app includes logic to install/update the system extension before starting the provider (see
`SystemManager.swift`).

## iOS (iOS 15+)

On iOS, `NEDNSProxyProvider` requires installing a DNS proxy configuration profile via **MDM**.

You need a network extension of type "App Extension" with the following entitlements:

- Network Extensions entitlement with `com.apple.networkextension.dns-proxy` capability enabled.

You also need the same capabilities in your app's entitlements to be able to enable/disable the DNS profile.

Typical steps to make it run are:

1. Install the DNS profile using MDM. This will create the DNS proxy configuration and start the DNS proxy.
2. Optionally, update the DNS proxy configuration using `NEDNSProxyManager`. The system will start/stop the DNS proxy
   automatically based on whether it is enabled. You can control it by changing the `enabled` field of the
   configuration.

The created DNS proxy configuration can be enabled/disabled by the app and by the user. It can't be deleted by the app
or by the user.

A sample MDM profile for DNS proxy configuration is included in the test app:

- `platform/mac/DnsLibsTestApp/mdm/DnsLibsTestApp-DnsProxy.mobileconfig`

*IMPORTANT*: Bundle identifiers in the `.mobileconfig` should match the bundle identifiers of the app and the
extension.

## Code sample

A minimal example of implementing `NEDNSProxyProvider` is available in the test app:

- `platform/mac/DnsLibsTestApp/DnsProxy/DNSProxyProvider.swift`

Key points in that implementation:

- `startProxy(options:)` creates and starts an `AGDnsProxy` instance and an instance of `AGDnsAppProxyFlowManager`.
- `handleNewFlow(_:)` and `handleNewUDPFlow(_:initialRemoteEndpoint:)` forward flows to `AGDnsAppProxyFlowManager`.

## Extra notes

If you use other VPNs that can bypass DNS queries, and intercepts this provider's DNS traffic,
it is recommended on macOS to use `flow.metadata.sourceAppSigningIdentifier` to bypass such connections in this provider.
Otherwise, this may lead to a route loop. On iOS, no additional actions are needed.

Example: AdGuard VPN using UTUN, in selective mode. DNSProxyProvider has secure upstream DNS server selected.
1. First, DNS query goes to DNSProxyProvider, DNSProxy wants to bootstrap the selected server, originates another plain query.
2. It goes to VPN, which in selective mode originates the same query but on the main interface.
3. This query is intercepted by DNSProxyProxyProvider again, and goes back to DNSProxy, which did not finished bootstrap yet.

Solution: use `flow.metadata.sourceAppSigningIdentifier` to detect AG VPN and bypass such connections, so on step 3 it
switches to bypassing this connection.

This is typically not a problem when the other VPN is a Packet Tunnel (`NEPacketTunnelProvider`) and not a plain
UTUN-based VPN, because on step 2 it does not go to VPN.

## Integration notes

AGDnsAppProxyFlowManager will route-loop if system:// upstream is the main upstream. If you're selected system upstream, use "filter" mode when handling a flow instead.
