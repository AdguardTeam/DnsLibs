#pragma once

#include <chrono>
#include <memory>
#include <dns_stamp.h>
#include <upstream.h>

namespace ag {

class upstream_dnscrypt : public ag::upstream {
public:
    /**
     * Create DNSCrypt upstream
     * @param stamp Stamp
     * @param timeout Timeout in milliseconds resolution
     */
    upstream_dnscrypt(server_stamp &&stamp, std::chrono::milliseconds timeout);
    upstream_dnscrypt(const upstream_dnscrypt &) = delete;
    upstream_dnscrypt &operator=(const upstream_dnscrypt &) = delete;
    ~upstream_dnscrypt() override;

    std::string address() override;
    exchange_result exchange(ldns_pkt *request_pkt) override;

private:
    struct impl;
    using impl_ptr = std::unique_ptr<impl>;

    err_string setup_impl();
    exchange_result apply_exchange(ldns_pkt &request_pkt);

    server_stamp m_stamp;
    std::chrono::milliseconds m_timeout;
    impl_ptr m_impl;
};

} // namespace ag
