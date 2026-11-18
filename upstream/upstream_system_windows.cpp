// clang-format off
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
// clang-format on

#include <cassert>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

#include "common/logger.h"
#include "common/utils.h"
#include "dns/common/dns_utils.h"
#include "dns/common/event_loop.h"

#include "upstream_system.h"
#include "upstream_system_windows.h"

namespace ag::dns {

static ag::Logger g_log{"SystemUpstream"};

static constexpr size_t ERROR_MESSAGE_BUFFER_SIZE = 256;
static constexpr int BYTE_BITS = 8;
static constexpr size_t TCP_FRAME_LENGTH_SIZE = 2;
static constexpr size_t MAX_MESSAGE_LENGTH = 0xFFFF;

static std::string win_error_string(DWORD code) {
    char buf[ERROR_MESSAGE_BUFFER_SIZE]{};
    DWORD len =
            FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                    nullptr, code, 0, buf, sizeof(buf), nullptr);
    std::string_view message = ag::utils::trim(std::string_view{buf, len});
    if (message.empty()) {
        return AG_FMT("error {}", code);
    }
    return AG_FMT("{} ({})", message, code);
}

/**
 * Converts a `DnsQueryRaw()` status into an error.
 * The status of a query that produced a reply is ignored: a negative answer (e.g. NXDOMAIN) comes
 * with an error status, but the raw reply is valid and has to be returned to the client.
 */
static Error<DnsError> query_error(DNS_STATUS status) {
    switch (status) {
    case ERROR_TIMEOUT:
    case WSAETIMEDOUT:
        return make_error(DnsError::AE_TIMED_OUT, win_error_string(status));
    case ERROR_INVALID_PARAMETER:
        // The DNS Client couldn't parse the packet (e.g. an opcode other than QUERY, or a name
        // that isn't valid UTF-8)
        return make_error(
                DnsError::AE_ENCODE_ERROR, AG_FMT("DnsQueryRaw() rejected the request: {}", win_error_string(status)));
    default:
        return make_error(DnsError::AE_INTERNAL_ERROR, AG_FMT("DnsQueryRaw() failed: {}", win_error_string(status)));
    }
}

static bool is_dnssec_type(ldns_rr_type type) {
    switch (type) {
    case LDNS_RR_TYPE_RRSIG:
    case LDNS_RR_TYPE_NSEC:
    case LDNS_RR_TYPE_NSEC3:
    case LDNS_RR_TYPE_DS:
    case LDNS_RR_TYPE_DNSKEY:
        return true;
    default:
        return false;
    }
}

/**
 * Checks whether a record must be left out of the reply to a request without the DO bit: the DNSSEC
 * records are returned only if they are asked for (RFC 3225, section 3). The DNS Client may answer
 * a query without DO from the cache entry it made for a DO query, which has the signatures.
 * @param request The request.
 * @param section The section of the reply the record goes to.
 * @param type    The record type.
 */
static bool is_unrequested_dnssec_record(const ldns_pkt *request, ldns_pkt_section section, ldns_rr_type type) {
    if (!is_dnssec_type(type)) {
        return false;
    }
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    if (section != LDNS_SECTION_ANSWER || question == nullptr) {
        return true;
    }
    ldns_rr_type qtype = ldns_rr_get_type(question);
    return qtype != type && qtype != LDNS_RR_TYPE_ANY;
}

/**
 * Replaces a section of a reply with the records that must be kept.
 */
static void drop_dnssec_records_from_section(
        ldns_pkt *reply, ldns_pkt_section section, ldns_rr_list *records, const ldns_pkt *request) {
    ldns_rr_list *kept = ldns_rr_list_new();
    for (size_t i = 0; i < ldns_rr_list_rr_count(records); ++i) {
        const ldns_rr *rr = ldns_rr_list_rr(records, i);
        if (!is_unrequested_dnssec_record(request, section, ldns_rr_get_type(rr))) {
            ldns_rr_list_push_rr(kept, ldns_rr_clone(rr));
        }
    }

    auto count = uint16_t(ldns_rr_list_rr_count(kept));
    switch (section) {
    case LDNS_SECTION_ANSWER:
        ldns_pkt_set_answer(reply, kept);
        ldns_pkt_set_ancount(reply, count);
        break;
    case LDNS_SECTION_AUTHORITY:
        ldns_pkt_set_authority(reply, kept);
        ldns_pkt_set_nscount(reply, count);
        break;
    case LDNS_SECTION_ADDITIONAL:
        ldns_pkt_set_additional(reply, kept);
        ldns_pkt_set_arcount(reply, count);
        break;
    default:
        assert(false);
        ldns_rr_list_deep_free(kept);
        break;
    }
    ldns_rr_list_deep_free(records);
}

/**
 * Drops the DNSSEC records that the requester didn't ask for (see `is_unrequested_dnssec_record()`).
 */
static void drop_unrequested_dnssec_records(ldns_pkt *reply, const ldns_pkt *request) {
    drop_dnssec_records_from_section(reply, LDNS_SECTION_ANSWER, ldns_pkt_answer(reply), request);
    drop_dnssec_records_from_section(reply, LDNS_SECTION_AUTHORITY, ldns_pkt_authority(reply), request);
    drop_dnssec_records_from_section(reply, LDNS_SECTION_ADDITIONAL, ldns_pkt_additional(reply), request);
}

Upstream::ExchangeResult make_system_reply(const ldns_pkt *request, Uint8View raw_reply, bool tcp) {
    if (tcp) {
        if (raw_reply.size() < TCP_FRAME_LENGTH_SIZE) {
            return make_error(DnsError::AE_DECODE_ERROR, "The TCP-framed reply from DnsQueryRaw() is too short");
        }
        size_t length = (size_t(raw_reply[0]) << BYTE_BITS) | raw_reply[1];
        if (length != raw_reply.size() - TCP_FRAME_LENGTH_SIZE) {
            return make_error(DnsError::AE_DECODE_ERROR,
                    AG_FMT("The TCP-framed reply from DnsQueryRaw() declares {} bytes, but has {}", length,
                            raw_reply.size() - TCP_FRAME_LENGTH_SIZE));
        }
        raw_reply.remove_prefix(TCP_FRAME_LENGTH_SIZE);
    }

    ldns_pkt *raw_pkt = nullptr;
    ldns_status status = ldns_wire2pkt(&raw_pkt, raw_reply.data(), raw_reply.size());
    if (status != LDNS_STATUS_OK) {
        return make_error(DnsError::AE_DECODE_ERROR,
                AG_FMT("Failed to parse the reply from DnsQueryRaw(): {}", ldns_get_errorstr_by_id(status)));
    }
    ldns_pkt_ptr reply{raw_pkt};

    // The DNS Client may answer from its cache with its own query ID
    ldns_pkt_set_id(reply.get(), ldns_pkt_id(request));

    if (!ldns_pkt_edns_do(request)) {
        drop_unrequested_dnssec_records(reply.get(), request);
    }

    return std::move(reply);
}

std::optional<Uint8Vector> system_query_wire(const ldns_pkt *request, bool tcp) {
    uint8_t *data = nullptr;
    size_t size = 0;
    ldns_status status = ldns_pkt2wire(&data, request, &size);
    AllocatedPtr<uint8_t> guard{data};
    if (status != LDNS_STATUS_OK || size == 0) {
        return std::nullopt;
    }
    if (!tcp) {
        return Uint8Vector{data, data + size};
    }
    if (size > MAX_MESSAGE_LENGTH) {
        return std::nullopt;
    }
    Uint8Vector framed;
    framed.reserve(size + TCP_FRAME_LENGTH_SIZE);
    framed.push_back(uint8_t(size >> BYTE_BITS));
    framed.push_back(uint8_t(size));
    framed.insert(framed.end(), data, data + size);
    return framed;
}

ULONG64 system_query_options(const ldns_pkt *request) {
    // Don't try NetBIOS or multicast name resolution (LLMNR, mDNS): the DNS Client would stall on
    // their timeouts, while a DNS proxy isn't a stub resolver, so the requester handles multicast
    // name resolution on its own. The DNS Client's local answers (its hosts file, `localhost`) are
    // kept: unlike multicast, they don't delay the query.
    ULONG64 options = DNS_QUERY_NO_NETBT | DNS_QUERY_NO_MULTICAST;
    if (ldns_pkt_edns_do(request)) {
        // The DNS Client's cache doesn't distinguish the queries by the DO bit, so a DO query may
        // get the answer cached for a query without DO, i.e. without the signatures. Get the answer
        // from the server instead. It replaces the cached one, so the queries without DO may get the
        // signatures from the cache afterwards: `make_system_reply()` leaves them out.
        options |= DNS_QUERY_BYPASS_CACHE;
    }
    return options;
}

/**
 * The `dnsapi.dll` functions used by the upstream, resolved at runtime because `DnsQueryRaw()` is
 * only available on Windows 11 23H2 and Windows Server 2025 and later, while the library supports
 * Windows 8 and later.
 */
class DnsApi {
public:
    using QueryRaw = decltype(&::DnsQueryRaw);
    using CancelQueryRaw = decltype(&::DnsCancelQueryRaw);
    using FreeResult = decltype(&::DnsQueryRawResultFree);

    /**
     * Returns the API, or null if the system doesn't support `DnsQueryRaw()`.
     */
    static const DnsApi *get() {
        static const DnsApi api;
        return (api.query_raw != nullptr) ? &api : nullptr;
    }

    QueryRaw query_raw = nullptr;
    CancelQueryRaw cancel_query_raw = nullptr;
    FreeResult free_result = nullptr;

private:
    DnsApi() {
        // `LOAD_LIBRARY_SEARCH_SYSTEM32` makes sure a `dnsapi.dll` next to the executable isn't
        // picked up instead of the system one.
        HMODULE module = LoadLibraryExW(L"dnsapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (module == nullptr) {
            dbglog(g_log, "Failed to load dnsapi.dll: {}", win_error_string(GetLastError()));
            return;
        }

        query_raw = (QueryRaw) GetProcAddress(module, "DnsQueryRaw");
        cancel_query_raw = (CancelQueryRaw) GetProcAddress(module, "DnsCancelQueryRaw");
        free_result = (FreeResult) GetProcAddress(module, "DnsQueryRawResultFree");
        if (query_raw == nullptr || cancel_query_raw == nullptr || free_result == nullptr) {
            dbglog(g_log, "DnsQueryRaw() is not exported by dnsapi.dll");
            query_raw = nullptr;
            return;
        }

        // The functions may be present but disabled (e.g. by a feature flag), in which case they
        // return ERROR_CALL_NOT_IMPLEMENTED. Probe them once, so that the upstream fails to
        // initialize with a clear error instead of failing every query.
        if (query_raw(nullptr, nullptr) == ERROR_CALL_NOT_IMPLEMENTED) {
            dbglog(g_log, "DnsQueryRaw() is disabled on this system");
            query_raw = nullptr;
        }
    }
};

/**
 * Sends DNS queries via `DnsQueryRaw()` and returns the replies it gets from the DNS Client.
 *
 * The queries are performed by the DNS Client service (Dnscache), which `DnsQueryRaw()` talks to
 * over RPC. The completion callback is therefore called on a dnsapi thread pool thread, and it may
 * be called at any time until it's invoked, including after `DnsCancelQueryRaw()` returns:
 * cancelling doesn't wait for the query to complete.
 *
 * The upstream passes the request packet to `DnsQueryRaw()` as is: the DNS Client forwards it
 * through its usual policy (the configured servers, NRPT rules, local names) and returns the raw
 * wire reply. This preserves the request's header flags, question class, and EDNS options, which
 * the name-and-type form would replace with a query built by the DNS Client, and the reply still
 * contains the records `DnsQueryEx()` couldn't represent (e.g. SVCB and HTTPS).
 */
class SystemUpstream::Impl {
public:
    /**
     * The state shared between the event loop and the `DnsQueryRaw()` completion callback.
     * The callback holds a reference until it's called, so the structures handed to `DnsQueryRaw()`
     * outlive the query even if the request doesn't wait for the result anymore.
     */
    struct Context {
        std::mutex mutex;
        bool detached = false;             ///< The request no longer waits for the result. Guarded by `mutex`.
        bool completed = false;            ///< The query has completed. Guarded by `mutex`.
        DNS_STATUS status = ERROR_SUCCESS; ///< The query status. Guarded by `mutex`.
        Uint8Vector reply;                 ///< The raw reply, empty if the query failed. Guarded by `mutex`.

        Impl *impl = nullptr;              ///< Valid only while not detached.
        uint64_t id = 0;                   ///< The request ID in `Impl::m_requests`.
        const ldns_pkt *request = nullptr; ///< Valid until the awaiting coroutine is resumed.
        Uint8Vector wire;                  ///< The packet to pass to `DnsQueryRaw()`.
        ULONG64 options = 0;
        bool tcp = false;
        DNS_QUERY_RAW_CANCEL cancel_handle{};
    };

    struct Request {
        std::shared_ptr<Context> ctx;
        ldns_pkt_ptr reply;
        Error<DnsError> error;
        UvPtr<uv_timer_t> timer_event;
        std::coroutine_handle<> continuation; ///< The awaiting coroutine, if it's suspended.
        std::optional<Upstream::ExchangeResult> *awaiter_result = nullptr; ///< Where to put the result for it.
    };

    Impl(EventLoop *loop, Millis timeout, ULONG interface_index)
            : m_loop(loop)
            , m_interface_index(interface_index)
            , m_timeout(timeout) {
    }

    ~Impl() {
        // The pending requests are completed by resuming their coroutines below, which may try to
        // send new requests (e.g. if the caller retries on `AE_SHUTTING_DOWN`). Refuse them, so
        // that they can't modify `m_requests` while it's being drained.
        m_destroying = true;
        while (!m_requests.empty()) {
            Request &req = m_requests.begin()->second;
            req.error = make_error(DnsError::AE_SHUTTING_DOWN);
            complete_request(req);
        }
    }

    /**
     * Sends a DNS query and awaits the reply.
     * @param wire    The packet to pass to `DnsQueryRaw()` (see `system_query_wire()`).
     * @param request The request. Must outlive the returned awaitable.
     * @param options The `DnsQueryRaw()` query options (see `system_query_options()`).
     * @param tcp     Whether the packet is framed for TCP.
     */
    auto send(Uint8Vector wire, const ldns_pkt *request, ULONG64 options, bool tcp) {
        struct Awaitable {
            Request *req = nullptr; ///< The request, or null if it was rejected.
            std::optional<Upstream::ExchangeResult> result;

            bool await_ready() {
                if (req == nullptr) {
                    return true;
                }
                Context &ctx = *req->ctx;
                Impl &impl = *ctx.impl;

                DNS_QUERY_RAW_REQUEST request{};
                request.version = DNS_QUERY_RAW_REQUEST_VERSION1;
                request.resultsVersion = DNS_QUERY_RAW_RESULTS_VERSION1;
                request.dnsQueryRaw = ctx.wire.data();
                request.dnsQueryRawSize = (ULONG) ctx.wire.size();
                request.queryOptions = ctx.options;
                request.interfaceIndex = impl.m_interface_index;
                request.queryCompletionCallback = on_query_complete;
                request.queryContext = new std::shared_ptr<Context>(req->ctx);
                // `DNS_QUERY_RAW_OPTION_BEST_EFFORT_PARSE` only helps with a packet the DNS Client
                // can't parse at all, and it may turn the query into a subset of the packet, so it
                // isn't set: the upstream forwards everything the requester sent.
                request.queryRawOptions = 0;
                request.protocol = ctx.tcp ? DNS_PROTOCOL_TCP : DNS_PROTOCOL_UDP;

                const DnsApi *api = DnsApi::get();
                assert(api != nullptr);
                DNS_STATUS status = (api != nullptr) ? api->query_raw(&request, &ctx.cancel_handle)
                                                     : (DNS_STATUS) ERROR_CALL_NOT_IMPLEMENTED;
                if (status != DNS_REQUEST_PENDING) {
                    // The query has completed with an error, and the completion callback won't be
                    // called. Mark it completed so that `remove_request()` doesn't cancel it: the
                    // API hasn't filled `cancel_handle`, and passing a zeroed handle is invalid.
                    {
                        std::scoped_lock l(ctx.mutex);
                        ctx.completed = true;
                    }
                    delete (std::shared_ptr<Context> *) request.queryContext;
                    req->error = query_error(status);
                    result = impl.remove_request(*req);
                    return true;
                }

                req->timer_event = Uv<uv_timer_t>::create_with_parent(req);
                if (0 != uv_timer_init(impl.m_loop->handle(), req->timer_event->raw())) {
                    req->timer_event->mark_uninit();
                    req->error = make_error(DnsError::AE_INTERNAL_ERROR, "Failed to init timer event");
                    result = impl.remove_request(*req);
                    return true;
                }
                if (0 != uv_timer_start(req->timer_event->raw(), on_uv_timer, impl.m_timeout.count(), /*repeat*/ 0)) {
                    req->error = make_error(DnsError::AE_INTERNAL_ERROR, "Failed to start timer event");
                    result = impl.remove_request(*req);
                    return true;
                }

                return false;
            }

            static void on_uv_timer(uv_timer_t *handle) {
                auto *req = (Request *) Uv<uv_timer_t>::parent_from_data(handle->data);
                if (!req) {
                    return;
                }
                req->error = make_error(DnsError::AE_TIMED_OUT);
                req->ctx->impl->complete_request(*req);
            }

            void await_suspend(std::coroutine_handle<> continuation) {
                req->continuation = continuation;
                req->awaiter_result = &result;
            }

            Upstream::ExchangeResult await_resume() {
                return std::move(result.value());
            }
        };

        // The destructor resumes the coroutines awaiting their results, so they may try to send
        // new requests. Refuse them, so that they can't modify `m_requests` while it's being drained.
        if (m_destroying) {
            return Awaitable{.req = nullptr,
                    .result = make_error(DnsError::AE_SHUTTING_DOWN, "The upstream is being destroyed")};
        }

        uint64_t id = m_next_request_id++;
        auto &req = m_requests[id];
        req.ctx = std::make_shared<Context>();
        req.ctx->impl = this;
        req.ctx->id = id;
        req.ctx->request = request;
        req.ctx->wire = std::move(wire);
        req.ctx->options = options;
        req.ctx->tcp = tcp;

        return Awaitable{.req = &req};
    }

    /**
     * The `DnsQueryRaw()` completion callback. Called on an arbitrary thread.
     */
    static VOID WINAPI on_query_complete(PVOID query_context, DNS_QUERY_RAW_RESULT *result) {
        std::unique_ptr<std::shared_ptr<Context>> holder{(std::shared_ptr<Context> *) query_context};
        std::shared_ptr<Context> ctx = std::move(*holder);

        DNS_STATUS status = ERROR_INVALID_DATA;
        Uint8Vector reply;
        if (result != nullptr) {
            status = result->queryStatus;
            // A negative answer (e.g. NXDOMAIN) comes with an error status, but the raw reply is
            // valid, so the status alone doesn't tell whether there is anything to return.
            if (result->queryRawResponse != nullptr && result->queryRawResponseSize > 0) {
                reply.assign(result->queryRawResponse, result->queryRawResponse + result->queryRawResponseSize);
            }
            if (const DnsApi *api = DnsApi::get()) {
                api->free_result(result);
            }
        }

        std::scoped_lock l(ctx->mutex);
        ctx->completed = true;
        if (ctx->detached) {
            return;
        }
        ctx->status = status;
        ctx->reply = std::move(reply);
        // Submit while holding the lock: the request is detached on the event loop under the same lock
        // before the upstream is destroyed, so the loop is guaranteed to still be running at this point.
        ctx->impl->m_loop->submit([ctx] {
            on_query_result(ctx);
        });
    }

    static void on_query_result(const std::shared_ptr<Context> &ctx) {
        DNS_STATUS status = ERROR_SUCCESS;
        Uint8Vector reply;
        bool tcp = false;
        {
            std::scoped_lock l(ctx->mutex);
            if (ctx->detached) {
                return;
            }
            status = ctx->status;
            reply = std::move(ctx->reply);
            tcp = ctx->tcp;
        }
        auto it = ctx->impl->m_requests.find(ctx->id);
        if (it == ctx->impl->m_requests.end()) {
            return;
        }
        dbglog(g_log, "DnsQueryRaw completed with status {}", status);
        Request &req = it->second;
        if (reply.empty()) {
            req.error = query_error(status);
        } else {
            auto result = make_system_reply(req.ctx->request, {reply.data(), reply.size()}, tcp);
            if (result.has_error()) {
                req.error = result.error();
            } else {
                req.reply = std::move(result.value());
            }
        }
        ctx->impl->complete_request(req);
    }

    /**
     * Stops waiting for the query result, cancelling the query if it's still in progress.
     * Must be called on the event loop.
     */
    static void detach(Context &ctx) {
        bool pending = false;
        {
            std::scoped_lock l(ctx.mutex);
            if (ctx.detached) {
                return;
            }
            ctx.detached = true;
            pending = !ctx.completed;
        }
        if (pending) {
            // The completion callback locks this mutex, and may be invoked by `DnsCancelQueryRaw()` or
            // run on another thread already, so the lock must not be held here.
            const DnsApi *api = DnsApi::get();
            DNS_STATUS status = (api != nullptr) ? api->cancel_query_raw(&ctx.cancel_handle)
                                                 : (DNS_STATUS) ERROR_CALL_NOT_IMPLEMENTED;
            if (ERROR_SUCCESS != status) {
                const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(ctx.request), 0);
                AllocatedPtr<char> type{(question != nullptr) ? ldns_rr_type2str(ldns_rr_get_type(question)) : nullptr};
                AllocatedPtr<char> name{(question != nullptr) ? ldns_rdf2str(ldns_rr_owner(question)) : nullptr};
                std::string error = win_error_string(status);
                warnlog(g_log, "DnsCancelQueryRaw failed for request {} (name: {}, type: {}, options: {:#x}): {}",
                        ctx.id, (name != nullptr) ? utils::trim(name.get()) : std::string_view{"(unknown)"},
                        (type != nullptr) ? type.get() : "(unknown)", ctx.options, error);
            }
        }
    }

    /**
     * Removes the request, stopping waiting for the query result.
     * @return The request result.
     */
    Upstream::ExchangeResult remove_request(Request &req) {
        auto node = m_requests.extract(req.ctx->id);
        Request &removed = node.mapped();
        if (removed.timer_event) {
            uv_timer_stop(removed.timer_event->raw());
        }
        detach(*removed.ctx);
        if (removed.error) {
            return removed.error;
        }
        return std::move(removed.reply);
    }

    /**
     * Removes the request and resumes the coroutine awaiting its result.
     * The request is removed before resuming, so the resumed coroutine may destroy the upstream.
     */
    void complete_request(Request &req) {
        std::coroutine_handle<> continuation = std::exchange(req.continuation, nullptr);
        std::optional<Upstream::ExchangeResult> *awaiter_result = req.awaiter_result;
        Upstream::ExchangeResult result = remove_request(req);
        if (continuation) {
            assert(awaiter_result);
            *awaiter_result = std::move(result);
            continuation.resume();
        }
    }

    EventLoop *m_loop = nullptr;
    ULONG m_interface_index = 0;
    bool m_destroying = false; ///< Whether the upstream is being destroyed. No new requests are accepted.
    uint64_t m_next_request_id = 0;
    std::map<uint64_t, Request> m_requests;
    Millis m_timeout;
};

SystemUpstream::SystemUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config)
        : Upstream(opts, config)
        , m_log(AG_FMT("System upstream ({})", opts.address))
        , m_interface(interface_from_address(opts.address)) {
}

SystemUpstream::~SystemUpstream() = default;

Error<Upstream::InitError> SystemUpstream::init() {
    if (DnsApi::get() == nullptr) {
        return make_error(InitError::AE_SYSTEMRESOLVER_INIT_FAILED,
                "The system:// upstream is not supported on this system: it requires DnsQueryRaw(), which is "
                "only available on Windows 11 23H2 and Windows Server 2025 and later");
    }

    ULONG interface_index = 0;

    if (!m_interface.empty()) {
        // An interface index, as shown by e.g. `route print` or `netsh interface ipv4 show interfaces`
        std::optional<NET_IFINDEX> index = utils::to_integer<NET_IFINDEX>(m_interface);
        NET_LUID luid{};
        if (!index.has_value() || NO_ERROR != ConvertInterfaceIndexToLuid(index.value(), &luid)) {
            return make_error(InitError::AE_INVALID_ADDRESS, AG_FMT("Invalid interface index: {}", m_interface));
        }
        interface_index = index.value();
    }

    m_pimpl = std::make_unique<Impl>(&config().loop, config().timeout, interface_index);
    return {};
}

coro::Task<Upstream::ExchangeResult> SystemUpstream::exchange(const ldns_pkt *request_pkt, const DnsMessageInfo *info) {
    bool tcp = info != nullptr && info->proto == utils::TP_TCP;
    std::optional<Uint8Vector> wire = system_query_wire(request_pkt, tcp);
    if (!wire.has_value()) {
        co_return make_error(DnsError::AE_ENCODE_ERROR, "Failed to serialize the request for DnsQueryRaw()");
    }

    // The upstream may be destroyed while the request is in flight: the destructor resumes it with
    // AE_SHUTTING_DOWN after the upstream is gone, so don't access `this` after creating the awaitable.
    co_return co_await m_pimpl->send(std::move(wire.value()), request_pkt, system_query_options(request_pkt), tcp);
}

} // namespace ag::dns
