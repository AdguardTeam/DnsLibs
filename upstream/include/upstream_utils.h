#pragma once

#include <string>
#include <ag_defs.h>
#include <dns_stamp.h>
#include <application_verifier.h>
#include <upstream.h>

namespace ag {

/**
 * DNS stamp structure
 */
struct dns_stamp {
    stamp_proto_type proto; /** Protocol */
	std::string server_addr; /** Server address */
	std::string provider_name; /** Provider name */
	std::string path; /** Path (for DOH) */
};

struct parse_dns_stamp_result {
    dns_stamp stamp;
    err_string error;
};

/**
 * Parses a DNS stamp string and returns a instance or an error
 * @param stamp_str DNS stamp string
 * @return stamp instance or an error
 */
parse_dns_stamp_result parse_dns_stamp(const std::string &stamp_str);

/**
 * Checks if upstream is valid and available
 * @param opts Upstream options
 * @param on_certificate_verification Certificate verification callback
 * @return If it is, no error is returned. Otherwise this method returns an error with an explanation.
 */
err_string test_upstream(const upstream_options &opts,
                         const on_certificate_verification_function &on_certificate_verification);

} // namespace ag
