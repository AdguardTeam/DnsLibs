# AdGuard DNSLibs developer documentation

## Contents

* [Introduction](#introduction)
* [How to start?](#howtostart)
* [Coding style](#codingstyle)
* [Project structure](#projstructure)
* [Main classes and structures](#main)
* [Own ad filter](#adfilter)
* [Useful notes](#notes)

<a name="introduction"></a>
## Introduction

AdGuard DNSLibs is an open-source proxy server that caches, filters, encrypts and redirects DNS requests.
Supports all existing protocols including DNS-over-HTTPS, DNS-over-TLS, DNS-over-QUIC and DNSCrypt.
In this documentation, you will find base information for the developing and support code of AdGuard DNSLibs project
and filters. Also, you can ask your question [here](https://forum.adguard.com).

<a name="howtostart"></a>
## How to start?

After cloning source files init submodules
```
git submodule init
git submodule update
```
Next, create a directory and build project
```
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j4 listener_standalone
```
By default, listener_standalone runs like proxy-server on UDP-port 1234 and TCP-port 1234 and just redirect all dns-requests
to 8.8.8.8:53 or 8.8.4.4:53. As you see in file `proxy/test/listener_standalone.cpp` you can change settings (e.g. port or timeout).
More details about the settings [below](#proxysettings).

#### Block diagram
![](dnslibs-diag.png)

<a name="codingstyle"></a>
## Coding style

See coding style of [NativeLibsCommon](https://github.com/AdguardTeam/NativeLibsCommon)

<a name="logging"></a>
### Logging
- Log messages should start with a capital letter.
- Use WARN/ERROR level only for internal logic warnings/errors and network errors that make the library unusable.
- Use INFO level for messages of regular proxy operation that regular users will see in their log.
- Use DEBUG level for messages that will be logged only with debug logging on.
    - This includes non-fatal network errors, malformed responses, etc. Why network-related errors are usually "DEBUG" level?
    These errors are part of the regular operation of a network client, so they reported in reply to the client of the library.
- Use TRACE debug level for trace messages.
    
### Code sample
type.h
```c++
namespace ag {

struct type {
    int x;
    type();
    std::string *func(const std::string &param);
}

} // namespace ag
```
type.cc
```c++
static constexpr auto FIVE = 5;

ag::type() : x(0)
{
}

std::string *ag::func(const std::string &param) {
    if (time(nullptr) % 2 == 0) {
        return new std::string(param);
    } else {
        std::string *ret = nullptr;
        for (int i = x; i < 10; i++) {
            switch (i) {
            case FIVE:
                ret = new std::string(std::to_string(FIVE) + ", not " + param);
                break;
            default:
                std::clog << "not " << FIVE << std::endl;
                break;
            }
        }
        return ret;
    }
}
```

<a name="projstructure"></a>
## Project structure

Every subproject consists of the following directories and files:
- `include/` - public headers
- `src/` - source code files and private headers
- `test/` - tests and its data
- `CMakeLists.txt` - cmake build config. Should be self-configurable.

Root project consists of the following directories and files:
- `common/` - Set of useful general-purpose utilities
- `dnscrypt/` - DNSCrypt client implementation
- `dnsfilter/` - DNS filter implementation
- `dnsstamp/` - DNSCrypt server stamps encoder/decoder
- `net/` - Set of entities which encapsulate network communication
- `platform/` - Platform-specific interfaces and adapters
- `proxy/` - DNS proxy implementation
- `third-party/` - third-party libraries (this is not a subproject, so subproject's rules are not enforced)
- `upstream/` - Working with DNS upstreams
- `CMakeLists.txt` - main cmake build config. Should build common things and include
  platform-specific things.

<a name="main"></a>
## Main classes and structures
You can find the implementation of each unit from this list in the folder `proxy/`.

### `ag::dnsproxy`
Main class. It receives settings from the user and initializes `DnsForwarder` and `Dnslistener`s.
Each class can also contain `ag::Logger`. More details about the syntax of the log you can find [above](#logging).

<a name="proxysettings"></a>
#### `ag::DnsProxySettings`
Settings structure, comes from the user. Most interesting fields:
- `std::vector<UpstreamOptions> upstreams and fallbacks` Lists of preferred and reserve DNS servers. If the user's query not
cached or filtered, then these servers will respond. `UpstreamOptions` contains:
    - `std::string address` DNSLibs supports UDP DNS, TCP DNS, DoH, DoT, DNSCrypt protocols. Here are examples of string `address`:
        - `8.8.8.8:53` plain DNS.
        - `tcp://8.8.8.8:53` plain DNS over TCP.
        - `tls://1.1.1.1` DNS-over-TLS.
        - `https://dns.adguard.com/dns-query` DNS-over-HTTPS.
        - `quic://dns.adguard.com:853` DNS-over-QUIC.
        - `sdns://...` DNS stamp (see [DNSCrypt](https://dnscrypt.info/stamps-specifications) specifications).
    - `std::vector<std::string> bootstrap` List of plain DNS servers to be used to resolve the hostname in upstreams' address.
- `dnsfilter::EngineParams FilterParams` Filtering engine parameters. Contains a vector of file paths with filter rules.
- `std::vector<ListenerSettings> listeners` List of addresses/ports/protocols/etc... to listen on. We will talk about
listeners later, but settings may consider now:
    - `std::string address{"::"}` The address to listen on.
    - `uint16_t port{53}` The port to listen on.
    - `listener_protocol protocol{listener_protocol::UDP}` The protocol to listen for.
    - `bool persistent{false}` If true, don't close the TCP connection after sending the first response.
    - `std::chrono::milliseconds idle_timeout{3000}` Close the TCP connection this long after the last request received.

#### `ag::DnsProxyListener`
The input class for user queries. At the moment works with UDP or TCP plain requests.
It is extended by the `ListenerBase` class, which in turn is extended by the `UdpListener` and `TcpListener` classes.
Initialization has two steps:
- `ListenerBase::init()` Here a logger is created, settings are set, etc.
Later in this function, a thread will start to listen to the socket.
- `UdpListener(or TcpListener)::before_run()` Depending on the type of protocol, the structure of `libuv` library is
initialized for working with network sockets.

Then `DnsProxyListener` prepared for work.
After receiving a user's request `DnsProxyListener`, thanks to `libuv`, puts a sync call
`DnsForwarder::handle_message()` with a request to the queue. `work_cb()` do this call. When `DnsForwarder` answers,
the response is sent to the user and memory will be cleared.

#### `ag::DnsForwarder`
A class that processes user DNS requests.
During class initialization, depending on the `UpstreamOptions`, vectors with real upstream are created using the Factory
Method programming pattern.
Next, the filtering module is loaded.
About filters and rules see [below](#filterrules).
`DnsForwarder::handle_message()` is the second important method of the `DnsForwarder` class that takes a user DNS request
from `DnsProxyListener`. Here few variants for return:  
- The first step is to check for the existence of this domain name in the cache. If a cached record is found, the data are
returned to the user application.
- Next, filters are applied. If a filter rule is found, the function will return `DnsProxyBlockingMode`.
- Next, if no cache or filter rule, there is an exchange with upstreams. Moreover, the upstreams are divided into upstreams and fallbacks.
Both vectors are sorted by RTT. This allows us to query the fastest servers first. Then traffic is encrypted depending on the
type of upstream in `upstream::exchange()` and query follow to upstream. Then response goes back to the user's app throw
`DnsProxyListener` witch call `DnsForwarder::handle_message()`.

<a name="filterrules"></a>
## Own ad filter

Filter lists are loaded from files. In the future will be added the ability to load from memory.
The file is processed line by line. The result of processing each line is placed in the log. Here is an example, how you
can add own filters in `listener_standalone`:
```
settings.FilterParams.filters.push_back( { 0, "/Users/user/my_rules.txt" } );
```
Now let's see a few examples of rules:
- hosts-like rule:
    - `127.0.0.1 example.com` blocks `example.com` and `ad.example.com` queries.
- basic rule:
    - `@@` - exception rules marker. Rules starting with `@@` disable filtering of matching addresses.
    - `||example.com` blocks `http://example.org/ad1.gif` and `https://example.org/ad1.gif` queries.
    Here `||` means matching the beginning of an address. With this character, you don't have to specify a particular
    protocol and subdomain in the address mask.
    - `example.*` blocks `example.com` and `example.org` queries. `*` - wildcard character.
    It is used to represent "any set of characters".
- and two modifiers:
    - `$important` modifier applied to a rule increases its priority over any other rule without $important modifier.
    Even over basic exception rules. E.g. `example.org$important`.
    - `$badfilter` modifier disable other basic rules to which they refer. It means that the text of the disabled rule should match
    the text of the `badfilter` rule (without the `badfilter` modifier). E.g `||example.com$badfilter` disables `||example.com`.

<a name="notes"></a>
## Useful notes

- RFCs of DNS [1034](https://tools.ietf.org/html/rfc1034), [1035](https://tools.ietf.org/html/rfc1035);
- RFC of DNS-over-TLS [7858](https://tools.ietf.org/html/rfc7858);
- RFC of DNS-over-HTTPS [8484](https://tools.ietf.org/html/rfc8484);
- RFC(draft) of DNS-over-QUIC [here](https://datatracker.ietf.org/doc/draft-ietf-dprive-dnsoquic);
- [DNSCrypt](https://dnscrypt.info/stamps-specifications/) specifications;
- An Introduction to [libuv](https://nikhilm.github.io/uvbook/An%20Introduction%20to%20libuv.pdf);
- [LDNS](https://www.nlnetlabs.nl/documentation/ldns/) docs;
- [Filtering rules syntax](https://github.com/AdguardTeam/AdguardHome/wiki/Hosts-Blocklists);
