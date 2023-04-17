/**

@mainpage AdGuard DNS Proxy C API Documentation

@section intro Introduction
A set of functions is available for working with the DNS proxy server, grouped in @ref api.
To use this group of functions, you need to include the dnsproxy.h header file.

@section start Get started

To start working with the proxy server, you need to initialize it using the ag_dnsproxy_init() function.
Then you can process DNS requests using the ag_dnsproxy_handle_message() function.
After finishing working with the server, you need to call the ag_dnsproxy_deinit() function.
Functions are also available to get the current proxy server settings: ag_dnsproxy_get_settings()
and ag_dnsproxy_settings_get_default().
To free the memory occupied by settings, use the ag_dnsproxy_settings_free() function.

@section stamps Working with DNS stamps

To work with DNS stamps, use the ag_dns_stamp_from_str(), ag_dns_stamp_free(), ag_dns_stamp_to_str(), ag_dns_stamp_pretty_url(),
and ag_dns_stamp_prettier_url() functions.

@section test Useful functions

To check the operability of the upstream server, use the ag_test_upstream() function.

The ag_is_valid_dns_rule() function allows you to check if a string is a valid rule.

The ag_dns_generate_rule_with_options() function is also available for generating DNS request filtering rules.

@section log How to use Logger

To set the logging level, use the ag_set_log_level() function.

To set the logger callback, use the ag_set_log_callback() function.

@section version How to get version

To get information about the library version, use the ag_dnsproxy_version() function, and to get the C API version, use the ag_get_capi_version() function.

@section example Usage example

[C API example](@ref capi_test.c).

*/
