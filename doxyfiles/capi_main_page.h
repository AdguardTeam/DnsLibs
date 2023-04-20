/**

@mainpage AdGuard DNS Proxy C API Documentation

@section intro Introduction
A set of functions is available for working with the DNS proxy server, grouped in @ref api.
To use this group of functions, you need to include the dnsproxy.h header file.

@section start Get started

To start working with the proxy server, you need to initialize it using the @ref ag_dnsproxy_init() function.

Once initialized, there are two possible ways of handling DNS requests:

1) UDP/TCP Listeners
Listener configurations are specified in the @ref ag_dnsproxy_settings, and the library user should redirect DNS traffic to this @ref ag_listener_settings::port.

2) Processing UDP packets with @ref ag_dnsproxy_handle_message()
@note this function cannot handle TCP packets.

If there is a packet tunnel, you can take a straightforward approach and redirect UDP packets from it using this function.
This function takes packet data and a completion handler block, which will be called after
the packet is processed and a response packet is returned. If no response packet is required, the method will return nil.

After finishing working with the server, you need to call the @ref ag_dnsproxy_deinit() function.

Functions are also available to get the current proxy server settings: @ref ag_dnsproxy_get_settings()
and @ref ag_dnsproxy_settings_get_default().

To free the memory occupied by settings, use the @ref ag_dnsproxy_settings_free() function.

@section stamps Working with DNS stamps

To work with DNS stamps, use the @ref ag_dns_stamp_from_str(), @ref ag_dns_stamp_free(), @ref ag_dns_stamp_to_str(), @ref ag_dns_stamp_pretty_url(),
and @ref ag_dns_stamp_prettier_url() functions.

@section test Useful functions

To check the operability of the upstream server, use the @ref ag_test_upstream() function.

The @ref ag_is_valid_dns_rule() function allows you to check if a string is a valid rule.

The @ref ag_dns_generate_rule_with_options() function is also available for generating DNS request filtering rules.

@section log How to use Logger

To set the logging level, use the @ref ag_set_log_level() function.

To set the logger callback, use the @ref ag_set_log_callback() function.

@section version How to get version

To get information about the library version, use the @ref ag_dnsproxy_version() function, and to get the C API version, use the @ref ag_get_capi_version() function.

@section example Usage example

[C API example](@ref capi_test.c).

*/
