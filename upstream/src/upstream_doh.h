#pragma once


#include <string>
#include <string_view>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>

#include <ag_logger.h>
#include <ag_defs.h>
#include <upstream.h>
#include <ag_socket_address.h>
#include "bootstrapper.h"

#include <ldns/packet.h>
#include <curl/curl.h>
#include <curl/multi.h>


namespace ag {

using curl_slist_ptr = std::unique_ptr<curl_slist, ftor<&curl_slist_free_all>>;
using curl_pool_ptr = std::unique_ptr<CURLM, ftor<&curl_multi_cleanup>>;

class dns_over_https : public upstream {
public:
    static constexpr int DEFAULT_PORT = 443;
    static constexpr std::string_view SCHEME = "https://";

    /**
     * @param url a DNS server url
     * @param opts upstream settings
     */
    dns_over_https(std::string_view url, const options &opts);
    ~dns_over_https() override;

    struct query_handle;

private:
    std::pair<ldns_pkt_ptr, err_string> exchange(ldns_pkt *) override;
    std::string address() override;

    std::unique_ptr<query_handle> create_handle(ldns_pkt *request, std::chrono::milliseconds timeout) const;

    static void run(dns_over_https *us);

    bool stop = false;
    logger log = create_logger("DOH upstream");
    const std::chrono::milliseconds timeout;
    const std::string server_url;
    curl_slist_ptr resolved = nullptr;
    curl_pool_ptr handle_pool = nullptr;
    bootstrapper_ptr bootstrapper;
    std::list<query_handle *> pending_queue;
    std::list<query_handle *> running_queue;
    struct {
        std::mutex guard;
        std::condition_variable run_condition;
        std::thread thread;
    } worker;
};

}
