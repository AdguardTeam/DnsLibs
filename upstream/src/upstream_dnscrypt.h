#pragma once

#include <chrono>
#include <memory>
#include <dns_stamp.h>
#include <upstream.h>
#include <ag_logger.h>

namespace ag {

class upstream_dnscrypt : public ag::upstream {
public:
    /**
     * Create DNSCrypt upstream
     * @param stamp Stamp
     * @param opts Upstream settings
     */
    upstream_dnscrypt(server_stamp &&stamp, const upstream_options &opts, const upstream_factory_config &config);
    upstream_dnscrypt(const upstream_dnscrypt &) = delete;
    upstream_dnscrypt &operator=(const upstream_dnscrypt &) = delete;
    ~upstream_dnscrypt() override;

private:
    err_string init() override;
    exchange_result exchange(ldns_pkt *request_pkt, const dns_message_info *info) override;

    struct impl;
    using impl_ptr = std::unique_ptr<impl>;

    struct setup_result {
        std::chrono::milliseconds rtt;
        err_string error;
    };

    setup_result setup_impl();
    exchange_result apply_exchange(ldns_pkt &request_pkt, std::chrono::milliseconds timeout);
    [[nodiscard]] socket_factory::socket_parameters make_socket_parameters() const;

    logger m_log = create_logger("DNScrypt upstream");
    server_stamp m_stamp;
    impl_ptr m_impl;
    std::mutex m_guard;
};

} // namespace ag
