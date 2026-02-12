#pragma once

#include <ldns/ldns.h>
#include <string>

#include "common/cache.h"
#include "common/defs.h"
#include "dns/common/dns_defs.h"
#include "dns/common/net_consts.h"

namespace ag::dns {

/**
 * Response cache
 *
 * This class contains response cache that properly handles TTL and do cacheability checks.
 */
class ResponseCache {
public:
    struct Result {
        ldns_pkt_ptr response;
        std::optional<int32_t> upstream_id;
        bool expired;
    };

    ResponseCache()
            : m_log(__func__)
            , m_cache() {
    }

    explicit ResponseCache(size_t capacity)
            : m_log(__func__)
            , m_cache(capacity) {
    }

    /**
     * @return null result if no cache entry satisfies the given key.
     * Otherwise, a response is synthesized from the cached template.
     * If the cache entry is expired, it becomes least recently used,
     * all response records' TTLs are set to 1 second,
     * and `expired` is set to `true`.
     * @param block_ech Whether ECH blocking is enabled for this request (affects cache key)
     */
    Result get(const ldns_pkt *request) {
        Result r{};
        std::string key = get_cache_key(request);

        if (m_cache.max_size() == 0) { // Caching disabled
            return r;
        }

        if (has_unsupported_extensions(request)) {
            dbglog(m_log, "Request has unsupported extensions");
            return r;
        }

        uint32_t ttl;
        auto cached_response_acc = m_cache.get(key);
        if (!cached_response_acc) {
            dbglog(m_log, "Cache miss for key {}", key);
            return {nullptr};
        }

        r.upstream_id = cached_response_acc->upstream_id;
        auto cached_response_ttl = std::chrono::ceil<Secs>(cached_response_acc->expires_at - ag::SteadyClock::now());
        if (cached_response_ttl.count() <= 0) {
            m_cache.make_lru(cached_response_acc);
            dbglog(m_log, "Expired cache entry for key {}", key);
            ttl = 1;
            r.expired = true;
        } else {
            ttl = cached_response_ttl.count();
        }

        r.response.reset(ldns_pkt_clone(cached_response_acc->response.get()));

        // Patch response id
        ldns_pkt_set_id(r.response.get(), ldns_pkt_id(request));

        // Patch EDNS UDP SIZE
        if (ldns_pkt_edns(r.response.get())) {
            ldns_pkt_set_edns_udp_size(r.response.get(), UDP_RECV_BUF_SIZE);
        }

        // Patch response question section
        assert(!ldns_pkt_question(r.response.get()));
        ldns_pkt_set_qdcount(r.response.get(), ldns_pkt_qdcount(request));
        ldns_pkt_set_question(r.response.get(), ldns_pkt_get_section_clone(request, LDNS_SECTION_QUESTION));

        // Patch response TTLs
        for (int_fast32_t i = 0; i < ldns_pkt_ancount(r.response.get()); ++i) {
            ldns_rr_set_ttl(ldns_rr_list_rr(ldns_pkt_answer(r.response.get()), i), ttl);
        }
        for (int_fast32_t i = 0; i < ldns_pkt_nscount(r.response.get()); ++i) {
            ldns_rr_set_ttl(ldns_rr_list_rr(ldns_pkt_authority(r.response.get()), i), ttl);
        }
        for (int_fast32_t i = 0; i < ldns_pkt_arcount(r.response.get()); ++i) {
            ldns_rr_set_ttl(ldns_rr_list_rr(ldns_pkt_additional(r.response.get()), i), ttl);
        }

        return r;
    }

    /*
     * Check cacheability and put an eligible response to the cache
     * @param block_ech Whether ECH blocking is enabled for this request (affects cache key)
     */
    void put(const ldns_pkt *request, ldns_pkt_ptr response, std::optional<int32_t> upstream_id) {
        if (m_cache.max_size() == 0) {
            // Caching disabled
            return;
        }
        if (ldns_pkt_tc(response.get())                                     // Truncated
                || ldns_pkt_qdcount(response.get()) != 1                    // Invalid
                || ldns_pkt_get_rcode(response.get()) != LDNS_RCODE_NOERROR // Error
                || has_unsupported_extensions(response.get())) {
            // Not cacheable
            return;
        }

        const auto *question = ldns_rr_list_rr(ldns_pkt_question(response.get()), 0);
        const auto type = ldns_rr_get_type(question);
        if (type == LDNS_RR_TYPE_A || type == LDNS_RR_TYPE_AAAA) {
            // Check contains at least one record of requested type
            bool found = false;
            for (int_fast32_t i = 0; i < ldns_pkt_ancount(response.get()); ++i) {
                const ldns_rr *rr = ldns_rr_list_rr(ldns_pkt_answer(response.get()), i);
                if (rr && ldns_rr_get_type(rr) == type) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                // Not cacheable
                return;
            }
        }

        // Will be patched when returning the cached response
        ldns_rr_list_deep_free(ldns_pkt_question(response.get()));
        ldns_pkt_set_question(response.get(), nullptr);
        ldns_pkt_set_qdcount(response.get(), 0);

        // This is NOT an authoritative answer
        ldns_pkt_set_aa(response.get(), false);

        // Compute the TTL of the cached response as the minimum of the response RR's TTLs
        uint32_t min_rr_ttl = compute_min_rr_ttl(response.get());
        if (min_rr_ttl == 0) {
            // Not cacheable
            return;
        }

        Value cached_response{
                .response = std::move(response),
                .expires_at = SteadyClock::now() + Secs(min_rr_ttl),
                .upstream_id = upstream_id,
        };

        m_cache.insert(get_cache_key(request), std::move(cached_response));
    }

    /** Erase cached entry of request if exists */
    void erase(const ldns_pkt *request) {
        m_cache.erase(get_cache_key(request));
    }

    /** Change capacity of LRU cache */
    void set_capacity(size_t capacity) {
        m_cache.set_capacity(capacity);
    }

    void clear() {
        m_cache.clear();
    }

    ResponseCache(const ResponseCache &) = delete;
    void operator=(const ResponseCache &) = delete;
    ResponseCache(ResponseCache &&) = delete;
    void operator=(ResponseCache &&) = delete;

private:
    Logger m_log;
    struct Value {
        ldns_pkt_ptr response;
        SteadyClock::time_point expires_at;
        std::optional<int32_t> upstream_id;
    };
    LruCache<std::string, Value> m_cache;

    static std::string get_cache_key(const ldns_pkt *request) {
        const auto *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
        std::string key = fmt::format("{}|{}|{}{}|", // '|' is to avoid collisions
                (int) ldns_rr_get_type(question), (int) ldns_rr_get_class(question),
                ldns_pkt_edns_do(request) ? "1" : "0",
                ldns_pkt_cd(request) ? "1" : "0"); // 'e' suffix for ECH-blocked cache entries

        // Compute the domain name, in lower case for case-insensitivity
        const auto *owner = ldns_rr_owner(question);
        const size_t size = ldns_rdf_size(owner);
        key.reserve(key.size() + size);
        if (size == 1) {
            key.push_back('.');
        } else {
            auto *data = (uint8_t *) ldns_rdf_data(owner);
            uint8_t len = data[0];
            uint8_t src_pos = 0;
            while ((len > 0) && (src_pos < size)) {
                ++src_pos;
                for (int_fast32_t i = 0; i < len; ++i) {
                    key.push_back(std::tolower(data[src_pos]));
                    ++src_pos;
                }
                if (src_pos < size) {
                    key.push_back('.');
                }
                len = data[src_pos];
            }
        }

        return key;
    }

    static bool has_unsupported_extensions(const ldns_pkt *pkt) {
        return ldns_pkt_edns_data(pkt) || ldns_pkt_edns_extended_rcode(pkt) || ldns_pkt_edns_unassigned(pkt);
    }

    static uint32_t compute_min_rr_ttl(const ldns_pkt *pkt) {
        uint32_t min_rr_ttl = UINT32_MAX;
        for (int_fast32_t i = 0; i < ldns_pkt_ancount(pkt); ++i) {
            min_rr_ttl = std::min(min_rr_ttl, ldns_rr_ttl(ldns_rr_list_rr(ldns_pkt_answer(pkt), i)));
        }
        for (int_fast32_t i = 0; i < ldns_pkt_arcount(pkt); ++i) {
            min_rr_ttl = std::min(min_rr_ttl, ldns_rr_ttl(ldns_rr_list_rr(ldns_pkt_additional(pkt), i)));
        }
        for (int_fast32_t i = 0; i < ldns_pkt_nscount(pkt); ++i) {
            min_rr_ttl = std::min(min_rr_ttl, ldns_rr_ttl(ldns_rr_list_rr(ldns_pkt_authority(pkt), i)));
        }
        if (min_rr_ttl == UINT32_MAX) { // No RRs in pkt (or insanely large TTL)
            min_rr_ttl = 0;
        }
        return min_rr_ttl;
    }
};

} // namespace ag::dns
