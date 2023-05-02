/**

@mainpage AdGuard DNS Proxy C# Adapter Documentation

@section features_sec Quick start

This code defines a C# class @ref Adguard.Dns.DnsProxyServer.DnsProxyServer "DnsProxyServer" that provides a way to start and stop a DNS proxy server.
Here is a quick start guide on how to use this class:

- Create an instance of @ref Adguard.Dns.Api.DnsProxyServer.Configs.DnsProxySettings "DnsProxySettings" with the desired settings for your DNS proxy server.

- Construct a class that inherits from @ref Adguard.Dns.Api.DnsProxyServer.Callbacks.IDnsProxyServerCallbackConfiguration "IDnsProxyServerCallbackConfiguration" and define a callback method to be triggered when the request is completed.

- Create an instance of @ref Adguard.Dns.DnsProxyServer.DnsProxyServer "DnsProxyServer" with the @ref Adguard.Dns.Api.DnsProxyServer.Configs.DnsProxySettings "DnsProxySettings"
and @ref Adguard.Dns.Api.DnsProxyServer.Callbacks.IDnsProxyServerCallbackConfiguration "IDnsProxyServerCallbackConfiguration" instances as parameters.

- Call the Start() method on the @ref Adguard.Dns.DnsProxyServer.DnsProxyServer "DnsProxyServer" instance to start the server.

- Call the Stop() method on the @ref Adguard.Dns.DnsProxyServer.DnsProxyServer "DnsProxyServer" instance to stop the server.

@section func Useful functions

Check if a string is a valid rule:
Call the @ref Adguard.Dns.Utils.DnsUtils.IsRuleValid(). This function takes a string as
 an argument and returns true if the string is a valid rule, and false otherwise.

Example:
```
bool isValidRule = Adguard.Dns.Utils.DnsUtils.IsRuleValid(ruleText);
```

@section dns_stamp Working with DNS stamps

The @ref Adguard.Dns.Api.DnsProxyServer.Configs.DnsStamp "DnsStamp" class provides an API for creating and manipulating DNS stamp objects. An object represents a DNS resolver
 endpoint that uses DNSCrypt, DNS-over-HTTPS (DoH), or other protocols.
To use this API:

Create a @ref Adguard.Dns.Api.DnsProxyServer.Configs.DnsStamp "DnsStamp" object by calling the @ref Adguard.Dns.Utils.DnsUtils.ParseDnsStamp() method from the DnsUtils with a string in the "sdns://" format.
Example:

```
string dnsStampStr = "sdns://...";
DnsStamp dnsStamp = Adguard.Dns.Utils.DnsUtils.ParseDnsStamp(dnsStampStr);
```

Access the @ref Adguard.Dns.Api.DnsProxyServer.Configs.DnsStamp "DnsStamp" object properties such as protocol type, server IP address, provider name, and others using their respective getter methods or properties.

Use the convenience methods provided by DnsUtils for creating and representing stamps in different formats,
 including @ref Adguard.Dns.Utils.DnsUtils.GetDnsStampPrettyUrl(), @ref Adguard.Dns.Utils.DnsUtils.GetDnsStampPrettierUrl(),
 and @ref Adguard.Dns.Utils.DnsUtils.GetDnsStampString().

Example:

```
string prettyUrl = Adguard.Dns.Utils.DnsUtils.GetDnsStampPrettyUrl(dnsStamp);
string prettierUrl = Adguard.Dns.Utils.DnsUtils.GetDnsStampPrettierUrl(dnsStamp);
string stampString = Adguard.Dns.Utils.DnsUtils.GetDnsStampString(dnsStamp);
```

@section logger How to use logger

For detailed description see @ref Adguard.Dns.Logging.DnsLoggerAdapter

@section version How to get version

Get the DNS proxy library version by calling @ref Adguard.Dns.Utils.DnsUtils.GetDnsProxyVersion.
This function returns a string with the version of the library.

 */
