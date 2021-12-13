#pragma once

#include <string>
#include "common/defs.h"
#include <dns_stamp.h>
#include <application_verifier.h>
#include <upstream.h>

namespace ag {

/**
 * Checks if upstream is valid and available
 * @param opts Upstream options
 * @param ipv6_available whether IPv6 is available, i.e. bootstrapper should make AAAA queries
 * @param on_certificate_verification Certificate verification callback
 * @param offline do not send a query to the wire, just validate the passed parameters
 * @return If it is, no error is returned. Otherwise this method returns an error with an explanation.
 */
ErrString test_upstream(const upstream_options &opts, bool ipv6_available,
                        const on_certificate_verification_function &on_certificate_verification,
                        bool offline);

} // namespace ag
