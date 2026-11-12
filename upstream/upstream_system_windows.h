#pragma once

// The internals of the Windows `system://` upstream (`upstream_system_windows.cpp`)
// that turn `DnsQueryRaw()` requests and results into DNS messages, exposed for unit testing.

// clang-format off
#include <winsock2.h>
#include <windows.h>
#include <windns.h>
// clang-format on

// `DnsQueryRaw()` and the types it uses were added in Windows 11 23H2 (SDK 10.0.22621.2428),
// so declare them here when the build uses an older SDK. The functions are resolved at runtime
// (see `upstream_system_windows.cpp`), so the library still builds and runs on older Windows
// versions: the upstream just fails to initialize there.
#ifndef DNS_QUERY_RAW_REQUEST_VERSION1

#define DNS_PROTOCOL_UNSPECIFIED 0
#define DNS_PROTOCOL_UDP 1
#define DNS_PROTOCOL_TCP 2

#define DNS_QUERY_RAW_RESULTS_VERSION1 0x1
#define DNS_QUERY_RAW_REQUEST_VERSION1 0x1

#define DNS_QUERY_RAW_OPTION_BEST_EFFORT_PARSE 0x0000000000000001

typedef struct _DNS_QUERY_RAW_RESULT DNS_QUERY_RAW_RESULT;
typedef struct _DNS_QUERY_RAW_REQUEST DNS_QUERY_RAW_REQUEST;
typedef struct DECLSPEC_ALIGN(8) _DNS_QUERY_RAW_CANCEL {
    CHAR reserved[32];
} DNS_QUERY_RAW_CANCEL;
typedef VOID(CALLBACK *DNS_QUERY_RAW_COMPLETION_ROUTINE)(VOID *queryContext, DNS_QUERY_RAW_RESULT *queryResults);

struct _DNS_QUERY_RAW_RESULT {
    ULONG version;
    DNS_STATUS queryStatus;
    ULONG64 queryOptions;
    ULONG64 queryRawOptions;
    ULONG64 responseFlags;
    ULONG queryRawResponseSize;
    BYTE *queryRawResponse;
    PDNS_RECORD queryRecords;
    ULONG protocol;
    // `SOCKADDR_INET sourceAddr` in the original declaration; the upstream doesn't use it.
    CHAR maxSa[32];
};

struct _DNS_QUERY_RAW_REQUEST {
    ULONG version;
    ULONG resultsVersion;
    ULONG dnsQueryRawSize;
    BYTE *dnsQueryRaw;
    PWSTR dnsQueryName;
    USHORT dnsQueryType;
    ULONG64 queryOptions;
    ULONG interfaceIndex;
    DNS_QUERY_RAW_COMPLETION_ROUTINE queryCompletionCallback;
    VOID *queryContext;
    ULONG64 queryRawOptions;
    ULONG customServersSize;
    // `DNS_CUSTOM_SERVER *customServers` in the original declaration; the upstream doesn't use it.
    PVOID customServers;
    ULONG protocol;
    // `SOCKADDR_INET sourceAddr` in the original declaration; the upstream doesn't use it.
    CHAR maxSa[32];
};

DNS_STATUS WINAPI DnsQueryRaw(DNS_QUERY_RAW_REQUEST *queryRequest, DNS_QUERY_RAW_CANCEL *cancelHandle);
DNS_STATUS WINAPI DnsCancelQueryRaw(DNS_QUERY_RAW_CANCEL *cancelHandle);
VOID WINAPI DnsQueryRawResultFree(DNS_QUERY_RAW_RESULT *queryResults);

#endif // DNS_QUERY_RAW_REQUEST_VERSION1

#include <optional>
#include <string>

#include <ldns/ldns.h>

#include "common/defs.h"
#include "dns/upstream/upstream.h"

namespace ag::dns {

/**
 * Serializes a request into the wire format to pass to `DnsQueryRaw()`. The DNS Client forwards
 * this packet as is, so the request's header flags, question class, and EDNS options are preserved.
 * @param request The request.
 * @param tcp     Whether to prepend the 2-byte message length, as `DnsQueryRaw()` expects for
 *                `DNS_PROTOCOL_TCP`.
 * @return The wire request, or nullopt if the request can't be serialized (e.g. it doesn't fit in
 *         a TCP message).
 */
std::optional<Uint8Vector> system_query_wire(const ldns_pkt *request, bool tcp);

/**
 * Makes the `DnsQueryRaw()` query options for a request. The DO and CD bits are carried by the
 * request packet itself.
 * @param request The request.
 */
ULONG64 system_query_options(const ldns_pkt *request);

/**
 * Builds the reply to a request from the raw reply returned by `DnsQueryRaw()`.
 *
 * If the request doesn't have the DO bit set, the DNSSEC records (RRSIG, NSEC, NSEC3, DS,
 * DNSKEY) are dropped unless they are the answer to the question (RFC 3225).
 *
 * @param request   The request.
 * @param raw_reply The raw reply, as returned by `DnsQueryRaw()`. If `tcp` is true, it is prefixed
 *                  with the 2-byte message length, as `DnsQueryRaw()` returns it for `DNS_PROTOCOL_TCP`.
 * @param tcp       Whether the reply is TCP-framed.
 * @return The reply, or an error if the raw reply can't be parsed.
 */
Upstream::ExchangeResult make_system_reply(const ldns_pkt *request, Uint8View raw_reply, bool tcp);

} // namespace ag::dns
