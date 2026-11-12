#pragma once

// The internals of the Windows `system://` upstream (`upstream_system_windows.cpp`)
// that turn `DnsQueryEx()` requests and results into DNS messages, exposed for unit testing.
//
// The records are handled as `DNS_RECORDW`, not as `DNS_RECORD`: `DnsQueryEx()` is Unicode-only
// (`DNS_QUERY_REQUEST::QueryName` is a `PCWSTR`, and the returned names and strings are `PWSTR`s),
// while `DNS_RECORD`/`PDNS_RECORD` alias `DNS_RECORDA` unless `UNICODE` is defined, which it isn't
// in this project. Defining `UNICODE` globally isn't wanted at this time: it would also switch
// `TCHAR`, `TEXT()` and the `...A`/`...W` aliases of `<windows.h>` for every Windows source file.

// clang-format off
#include <winsock2.h>
#include <windows.h>
#include <windns.h>
// clang-format on

// Not declared by older Windows SDKs
#ifndef DNS_QUERY_DNSSEC_OK
#define DNS_QUERY_DNSSEC_OK 0x01000000
#endif
#ifndef DNS_QUERY_DNSSEC_CHECKING_DISABLED
#define DNS_QUERY_DNSSEC_CHECKING_DISABLED 0x02000000
#endif

#include <optional>
#include <string>

#include <ldns/ldns.h>

#include "common/defs.h"
#include "dns/upstream/upstream.h"

namespace ag::dns {

using ldns_rr_ptr = UniquePtr<ldns_rr, &ldns_rr_free>; // NOLINT(readability-identifier-naming)

/**
 * Converts a record returned by `DnsQueryEx()` into an ldns record.
 * If the record can't be converted (e.g. it's of an unsupported type or its data is invalid),
 * a warning describing the reason is logged and null is returned.
 * The names and the character strings (e.g. of TXT records) are converted from UTF-16 to UTF-8,
 * so the character strings that aren't valid UTF-8 can't be restored exactly.
 * @param record The record.
 * @return The converted record, or null if it can't be converted.
 */
ldns_rr_ptr system_record_to_ldns(const DNS_RECORDW &record);

/**
 * Builds the reply to a request from the result of a `DnsQueryEx()` query.
 * The records of the unsupported types are skipped. If the request doesn't have the DO bit set,
 * the DNSSEC records (RRSIG, NSEC, NSEC3, DS, DNSKEY) are skipped too, unless they are the answer
 * to the question (RFC 3225): the DNS Client returns the cached signed answer of a DO query to
 * the queries without DO.
 * @param request The request.
 * @param status  The query status.
 * @param records The returned records, may be null.
 * @return The reply, or an error if the status doesn't describe a DNS answer (e.g. the query timed out).
 */
Upstream::ExchangeResult make_system_reply(const ldns_pkt *request, DNS_STATUS status, const DNS_RECORDW *records);

/**
 * Converts the question name of a request into the name to pass to `DnsQueryEx()`: the labels are
 * taken as is, i.e. they are expected to be UTF-8 and aren't escaped, and the trailing dot is removed.
 * @param request The request.
 * @return The name, or nullopt if the request has no question or the name can't be represented
 *         (e.g. a label contains a dot, or isn't valid UTF-8).
 */
std::optional<std::wstring> system_query_name(const ldns_pkt *request);

/**
 * Makes the `DnsQueryEx()` query options for a request.
 * NetBIOS and multicast name resolution (LLMNR, mDNS) are disabled: the DNS Client would stall on
 * their timeouts, and a DNS proxy isn't a stub resolver, so the requester handles them on its own.
 * The DNS Client's local answers (its cache, the hosts file, `localhost`) are kept, since they don't
 * delay the query. The queries with the DO bit bypass the cache: it ignores the DO bit, so it may
 * have the answer without the signatures.
 * @param request The request.
 * @param tcp     Whether the query must be sent over TCP.
 */
ULONG64 system_query_options(const ldns_pkt *request, bool tcp);

} // namespace ag::dns
