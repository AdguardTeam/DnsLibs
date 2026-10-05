#pragma once

#include <string>

#include "common/defs.h"
#include "common/error.h"

#include "dns/dnsstamp/dns_stamp.h"
#include "dns/net/application_verifier.h"
#include "upstream.h"

namespace ag {
namespace dns {

enum class UpstreamUtilsError {
    AE_FACTORY_ERROR,
    AE_EXCHANGE_ERROR,
    AE_WRONG_ANSWER_NUMBER,
};

/**
 * Checks if upstream is valid and available
 * @param opts Upstream options
 * @param timeout Upstream exchange timeout
 * @param ipv6_available whether IPv6 is available, i.e. bootstrapper should make AAAA queries
 * @param on_certificate_verification Certificate verification callback
 * @param offline do not send a query to the wire, just validate the passed parameters
 * @return If it is, no error is returned. Otherwise this method returns an error with an explanation.
 */
Error<UpstreamUtilsError> test_upstream(const UpstreamOptions &opts, Millis timeout, bool ipv6_available,
        const OnCertificateVerificationFn &on_certificate_verification, bool offline);

/**
 * Creates a SOA record for the authority section of a negative response, based on the
 * question of `request`.
 * @param request The request packet to take the owner name from.
 * @return A newly allocated SOA record, or nullptr if the request has no question.
 */
ldns_rr *create_negative_soa(const ldns_pkt *request);

} // namespace dns

// clang format off
template <>
struct ErrorCodeToString<dns::UpstreamUtilsError> {
    std::string operator()(dns::UpstreamUtilsError e) {
        switch (e) {
        case decltype(e)::AE_FACTORY_ERROR:
            return "Upstream factory error";
        case decltype(e)::AE_EXCHANGE_ERROR:
            return "Upstream exchange error";
        case decltype(e)::AE_WRONG_ANSWER_NUMBER:
            return "DNS upstream returned reply with wrong number of answers";
        }
    }
};
// clang format on

} // namespace ag