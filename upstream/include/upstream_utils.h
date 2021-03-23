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
 * @param on_certificate_verification Certificate verification callback
 * @return If it is, no error is returned. Otherwise this method returns an error with an explanation.
 */
err_string test_upstream(const upstream_options &opts,
                         const on_certificate_verification_function &on_certificate_verification);

/**
 * Test if a well-known plain DNS server is reachable over IPv6.
 * @return true if IPv6 works,
 *         false otherwise.
 */
bool test_ipv6_connectivity();

} // namespace ag
