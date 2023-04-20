/**

@mainpage AdGuard DNS Proxy Obj-C Adapter Documentation

@section intro Introduction

@section start Get started

This Objective-C code represents the public interface of the @ref AGDnsProxy class. To use this API, users should:

- Create an instance of the @ref AGDnsProxy class using the AGDnsProxy::initWithConfig:handler:error: method.
The method takes the proxy configuration, event handler, and a reference to an <span style="color: red;">NSError *</span> object to be populated with an error if one occurs.

- There are two possible ways of handling DNS requests:

    1) UDP/TCP Listeners
    Listener configurations are specified in the @ref AGDnsProxyConfig, and the library user should redirect DNS traffic to this @ref AGListenerSettings::port.

    2) Processing UDP packets with AGDnsProxy::handlePacket:completionHandler:
    @note this function cannot handle TCP packets.

    If there is a packet tunnel, you can take a straightforward approach and redirect UDP packets from it using this function.
    This function takes packet data and a completion handler block, which will be called after
    the packet is processed and a response packet is returned. If no response packet is required, the method will return nil.

- Stop the @ref AGDnsProxy by calling the @ref AGDnsProxy::stop() method. This method should be called before the @ref AGDnsProxy instance is destroyed.

@section test Useful functions

Check if a string is a valid rule by calling the @ref AGDnsProxy::isValidRule: method. The method takes a string as an argument
and returns true if the string is a rule, and false otherwise.

@section stamps Working with DNS stamps

The @ref AGDnsStamp class provides an API for creating and manipulating DNS stamp objects.

An @ref AGDnsStamp object represents a DNS resolver endpoint that uses either DNSCrypt, DNS-over-HTTPS (DoH), or DNS-over-QUIC (DoQ) protocols.
The object includes several properties such as protocol type (@ref AGDnsStamp::proto), server IP address (@ref AGDnsStamp::serverAddr), provider name (@ref AGDnsStamp::providerName),
server public key (@ref AGDnsStamp::serverPublicKey), hashes, path, and several Boolean flags (@ref AGDnsStamp::dnssec, @ref AGDnsStamp::noLog, @ref AGDnsStamp::noFilter) that describe the server's properties.

To use this API, users can create an instance of the AGDnsStamp class by calling the AGDnsStamp::initWithString:error:
or AGDnsStamp::stampWithString:error: method with a string in the <span style="color: red;">"sdns://"</span> format. The string should contain all
the necessary parameters for initializing an @ref AGDnsStamp object.

Users can also access the object's properties, including the server's IP address and provider name, using the provided getter methods.

Finally, @ref AGDnsStamp provides several convenience methods for creating and representing stamps in different formats,
including the @ref AGDnsStamp::prettyUrl, @ref AGDnsStamp::prettierUrl, and @ref AGDnsStamp::stringValue properties.

@section log How to use Logger

To use this class, you can:

- Set the default logging level using the class method @ref AGLogger::setLevel:. This method takes an AGLogLevel value and sets the logging level to be used by default.

- Set the log callback using the class method @ref AGLogger::setCallback:. This method takes a block of type @ref AGLogger::logCallback,
which is called when a log message needs to be output. The block takes three parameters: the log level of the message (@ref AGLogLevel),
the formatted log message <span style="color: red;">(const char *)</span>, and the length of the log message (int).

When using this class, you should set the logging level and callback function as needed for application.
The AGLogger::logCallback function will be called whenever a log message needs to be output, and it is up to application to handle
the message as appropriate (e.g., print to console, write to log file, etc.).

@section version How to get version

Get the DNS proxy library version by calling the static @ref AGDnsProxy::libraryVersion method.
The method returns a string with the version of the library.

@section example Usage example

[C API example](@ref test_AGDnsProxyStandalone.mm).

 */
