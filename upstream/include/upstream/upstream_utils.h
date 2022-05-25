#pragma once

#include <string>
#include "common/defs.h"
#include "dnsstamp/dns_stamp.h"
#include "net/application_verifier.h"
#include "upstream.h"

namespace ag {

/**
 * Checks if upstream is valid and available
 * @param opts Upstream options
 * @param ipv6_available whether IPv6 is available, i.e. bootstrapper should make AAAA queries
 * @param on_certificate_verification Certificate verification callback
 * @param offline do not send a query to the wire, just validate the passed parameters
 * @return If it is, no error is returned. Otherwise this method returns an error with an explanation.
 */
ErrString test_upstream(const UpstreamOptions &opts, bool ipv6_available,
                        const OnCertificateVerificationFn &on_certificate_verification,
                        bool offline);

} // namespace ag
