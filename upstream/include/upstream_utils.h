#pragma once

#include <string>
#include <ag_defs.h>
#include <dns_stamp.h>
#include <application_verifier.h>
#include <upstream.h>

namespace ag {

/**
 * Checks if upstream is valid and available
 * @param opts Upstream options
 * @param ipv6_available whether IPv6 is available, i.e. bootstrapper should make AAAA queries
 * @param on_certificate_verification Certificate verification callback
 * @return If it is, no error is returned. Otherwise this method returns an error with an explanation.
 */
err_string test_upstream(const upstream_options &opts, bool ipv6_available,
                         const on_certificate_verification_function &on_certificate_verification);

} // namespace ag
