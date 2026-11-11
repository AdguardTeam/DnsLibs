// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <windns.h>
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
static constexpr size_t MAX_LABEL_LENGTH = 63;
static constexpr size_t MAX_NAME_LENGTH = 255;
static constexpr size_t MAX_CHARACTER_STRING_LENGTH = 255;
static constexpr size_t MAX_RDATA_LENGTH = UINT16_MAX;
static constexpr uint8_t BYTE_MASK = 0xff;
static constexpr int BYTE_BITS = 8;

static void free_records(DNS_RECORDW *records) {
    DnsFree(records, DnsFreeRecordList);
}

using RecordsPtr = UniquePtr<DNS_RECORDW, &free_records>;

static std::string win_error_string(DNS_STATUS code) {
    char buf[ERROR_MESSAGE_BUFFER_SIZE]{};
    DWORD len =
            FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                    nullptr, (DWORD) code, 0, buf, sizeof(buf), nullptr);
    std::string_view message = ag::utils::trim(std::string_view{buf, len});
    if (message.empty()) {
        return AG_FMT("error {}", code);
    }
    return AG_FMT("{} ({})", message, code);
}

/**
 * Serializes a resource record in wire format.
 */
class WireWriter {
public:
    void u8(uint8_t value) {
        m_data.push_back(value);
    }

    void u16(uint16_t value) {
        m_data.push_back(uint8_t(value >> BYTE_BITS));
        m_data.push_back(uint8_t(value & BYTE_MASK));
    }

    void u32(uint32_t value) {
        u16(uint16_t(value >> (2 * BYTE_BITS)));
        u16(uint16_t(value));
    }

    void bytes(const void *data, size_t size) {
        if (size > 0) {
            m_data.insert(m_data.end(), (const uint8_t *) data, (const uint8_t *) data + size);
        }
    }

    /**
     * Writes an uncompressed domain name.
     * @return False if the name is null or isn't a valid domain name.
     */
    bool name(PCWSTR value) {
        if (value == nullptr) {
            return false;
        }
        std::string name = utils::from_wstring(value);
        std::string_view rest = name;
        if (rest.ends_with('.')) {
            rest.remove_suffix(1);
        }
        size_t length = 1;
        while (!rest.empty()) {
            size_t dot = rest.find('.');
            std::string_view label = rest.substr(0, dot);
            if (label.empty() || label.size() > MAX_LABEL_LENGTH) {
                return false;
            }
            length += label.size() + 1;
            if (length > MAX_NAME_LENGTH) {
                return false;
            }
            u8(uint8_t(label.size()));
            bytes(label.data(), label.size());
            rest = (dot == std::string_view::npos) ? std::string_view{} : rest.substr(dot + 1);
            if (dot != std::string_view::npos && rest.empty()) {
                return false; // An empty label in the middle
            }
        }
        u8(0);
        return true;
    }

    /**
     * Writes a character string.
     * @return False if the string is null or too long.
     */
    bool string(PCWSTR value) {
        if (value == nullptr) {
            return false;
        }
        std::string str = utils::from_wstring(value);
        if (str.size() > MAX_CHARACTER_STRING_LENGTH) {
            return false;
        }
        u8(uint8_t(str.size()));
        bytes(str.data(), str.size());
        return true;
    }

    [[nodiscard]] size_t size() const {
        return m_data.size();
    }

    void set_u16(size_t pos, uint16_t value) {
        m_data[pos] = uint8_t(value >> BYTE_BITS);
        m_data[pos + 1] = uint8_t(value & BYTE_MASK);
    }

    [[nodiscard]] const Uint8Vector &data() const {
        return m_data;
    }

private:
    Uint8Vector m_data;
};

/** The result of writing a record's RDATA. */
enum class RdataWriteResult {
    OK,               ///< The RDATA has been written.
    UNSUPPORTED_TYPE, ///< The record type isn't supported.
    INVALID,          ///< A name or a character string in the RDATA is invalid.
};

/**
 * Writes the RDATA of a record returned by `DnsQueryEx()`.
 * @return The result of writing the RDATA.
 */
static RdataWriteResult write_rdata(WireWriter &w, const DNS_RECORDW &record) {
    const auto &data = record.Data;

    switch (record.wType) {
    case LDNS_RR_TYPE_A:
        w.bytes(&data.A.IpAddress, sizeof(data.A.IpAddress));
        return RdataWriteResult::OK;
    case LDNS_RR_TYPE_AAAA:
        w.bytes(&data.AAAA.Ip6Address, sizeof(data.AAAA.Ip6Address));
        return RdataWriteResult::OK;
    case LDNS_RR_TYPE_NS:
    case LDNS_RR_TYPE_MD:
    case LDNS_RR_TYPE_MF:
    case LDNS_RR_TYPE_CNAME:
    case LDNS_RR_TYPE_MB:
    case LDNS_RR_TYPE_MG:
    case LDNS_RR_TYPE_MR:
    case LDNS_RR_TYPE_PTR:
    case LDNS_RR_TYPE_DNAME:
        return w.name(data.PTR.pNameHost) ? RdataWriteResult::OK : RdataWriteResult::INVALID;
    case LDNS_RR_TYPE_SOA:
        if (!w.name(data.SOA.pNamePrimaryServer) || !w.name(data.SOA.pNameAdministrator)) {
            return RdataWriteResult::INVALID;
        }
        w.u32(data.SOA.dwSerialNo);
        w.u32(data.SOA.dwRefresh);
        w.u32(data.SOA.dwRetry);
        w.u32(data.SOA.dwExpire);
        w.u32(data.SOA.dwDefaultTtl);
        return RdataWriteResult::OK;
    case LDNS_RR_TYPE_MINFO:
    case LDNS_RR_TYPE_RP:
        return w.name(data.MINFO.pNameMailbox) && w.name(data.MINFO.pNameErrorsMailbox) ? RdataWriteResult::OK
                                                                                        : RdataWriteResult::INVALID;
    case LDNS_RR_TYPE_MX:
    case LDNS_RR_TYPE_AFSDB:
    case LDNS_RR_TYPE_RT:
        w.u16(data.MX.wPreference);
        return w.name(data.MX.pNameExchange) ? RdataWriteResult::OK : RdataWriteResult::INVALID;
    case LDNS_RR_TYPE_TXT:
    case LDNS_RR_TYPE_HINFO:
    case LDNS_RR_TYPE_ISDN:
    case LDNS_RR_TYPE_X25:
        for (DWORD i = 0; i < data.TXT.dwStringCount; ++i) {
            if (!w.string(data.TXT.pStringArray[i])) {
                return RdataWriteResult::INVALID;
            }
        }
        return RdataWriteResult::OK;
    case LDNS_RR_TYPE_NULL:
        w.bytes(data.Null.Data, data.Null.dwByteCount);
        return RdataWriteResult::OK;
    case LDNS_RR_TYPE_KEY:
    case LDNS_RR_TYPE_DNSKEY:
        w.u16(data.KEY.wFlags);
        w.u8(data.KEY.chProtocol);
        w.u8(data.KEY.chAlgorithm);
        w.bytes(data.KEY.Key, data.KEY.wKeyLength);
        return RdataWriteResult::OK;
    case LDNS_RR_TYPE_SIG:
    case LDNS_RR_TYPE_RRSIG:
        w.u16(data.SIG.wTypeCovered);
        w.u8(data.SIG.chAlgorithm);
        w.u8(data.SIG.chLabelCount);
        w.u32(data.SIG.dwOriginalTtl);
        w.u32(data.SIG.dwExpiration);
        w.u32(data.SIG.dwTimeSigned);
        w.u16(data.SIG.wKeyTag);
        if (!w.name(data.SIG.pNameSigner)) {
            return RdataWriteResult::INVALID;
        }
        w.bytes(data.SIG.Signature, data.SIG.wSignatureLength);
        return RdataWriteResult::OK;
    case LDNS_RR_TYPE_SRV:
        w.u16(data.SRV.wPriority);
        w.u16(data.SRV.wWeight);
        w.u16(data.SRV.wPort);
        return w.name(data.SRV.pNameTarget) ? RdataWriteResult::OK : RdataWriteResult::INVALID;
    case LDNS_RR_TYPE_NAPTR:
        w.u16(data.NAPTR.wOrder);
        w.u16(data.NAPTR.wPreference);
        return w.string(data.NAPTR.pFlags) && w.string(data.NAPTR.pService) && w.string(data.NAPTR.pRegularExpression)
                        && w.name(data.NAPTR.pReplacement)
                ? RdataWriteResult::OK
                : RdataWriteResult::INVALID;
    case LDNS_RR_TYPE_DS:
        w.u16(data.DS.wKeyTag);
        w.u8(data.DS.chAlgorithm);
        w.u8(data.DS.chDigestType);
        w.bytes(data.DS.Digest, data.DS.wDigestLength);
        return RdataWriteResult::OK;
    case LDNS_RR_TYPE_NSEC:
        if (!w.name(data.NSEC.pNextDomainName)) {
            return RdataWriteResult::INVALID;
        }
        w.bytes(data.NSEC.TypeBitMaps, data.NSEC.wTypeBitMapsLength);
        return RdataWriteResult::OK;
    case LDNS_RR_TYPE_NSEC3: {
        // `chData` holds the salt, the next hashed owner name, and the type bit maps
        const BYTE *salt = data.NSEC3.chData;
        const BYTE *hash = salt + data.NSEC3.bSaltLength;
        const BYTE *type_bit_maps = hash + data.NSEC3.bHashLength;
        w.u8(data.NSEC3.chAlgorithm);
        w.u8(data.NSEC3.bFlags);
        w.u16(data.NSEC3.wIterations);
        w.u8(data.NSEC3.bSaltLength);
        w.bytes(salt, data.NSEC3.bSaltLength);
        w.u8(data.NSEC3.bHashLength);
        w.bytes(hash, data.NSEC3.bHashLength);
        w.bytes(type_bit_maps, data.NSEC3.wTypeBitMapsLength);
        return RdataWriteResult::OK;
    }
    case LDNS_RR_TYPE_NSEC3PARAM:
        w.u8(data.NSEC3PARAM.chAlgorithm);
        w.u8(data.NSEC3PARAM.bFlags);
        w.u16(data.NSEC3PARAM.wIterations);
        w.u8(data.NSEC3PARAM.bSaltLength);
        w.bytes(data.NSEC3PARAM.pbSalt, data.NSEC3PARAM.bSaltLength);
        return RdataWriteResult::OK;
    case LDNS_RR_TYPE_TLSA:
        w.u8(data.TLSA.bCertUsage);
        w.u8(data.TLSA.bSelector);
        w.u8(data.TLSA.bMatchingType);
        w.bytes(data.TLSA.bCertificateAssociationData, data.TLSA.bCertificateAssociationDataLength);
        return RdataWriteResult::OK;
    case LDNS_RR_TYPE_DHCID:
        w.bytes(data.DHCID.DHCID, data.DHCID.dwByteCount);
        return RdataWriteResult::OK;
    case LDNS_RR_TYPE_SVCB:
    case LDNS_RR_TYPE_HTTPS:
        // `DnsQueryEx()` fills in `DNS_SVCB_DATA` only when `DNS_QUERY_PARSE_ALL_RECORDS` is set
        // in a `DNS_QUERY_REQUEST3`, which Windows 8 (the minimum supported version) doesn't have.
        // Without that option, these records are returned as the raw RDATA, which is exactly what
        // ldns expects. The RDATA is stored inline at `Data`: `Data.pDataPtr` is a `PBYTE` alias of
        // the buffer, not a pointer to it (its value is the first bytes of the RDATA), and the
        // record is allocated with `offsetof(DNS_RECORDW, Data) + wDataLength` bytes.
        w.bytes(&data, record.wDataLength);
        return RdataWriteResult::OK;
    default:
        // The types we don't marshal, e.g. the ones `DnsQueryEx()` returns as raw RDATA (CAA),
        // or the parsed ones nobody needs anymore (WKS, ATMA, WINS)
        return RdataWriteResult::UNSUPPORTED_TYPE;
    }
}

ldns_rr_ptr system_record_to_ldns(const DNS_RECORDW &record) {
    WireWriter w;
    if (!w.name(record.pName)) {
        warnlog(g_log, "Skipping a record of type {} with an invalid name: {}", record.wType,
                (record.pName != nullptr) ? utils::from_wstring(record.pName) : "(null)");
        return nullptr;
    }
    w.u16(record.wType);
    w.u16(LDNS_RR_CLASS_IN);
    w.u32(record.dwTtl);
    size_t rdlength_pos = w.size();
    w.u16(0);
    switch (write_rdata(w, record)) {
    case RdataWriteResult::OK:
        break;
    case RdataWriteResult::UNSUPPORTED_TYPE:
        warnlog(g_log, "Skipping a record of unsupported type {}", record.wType);
        return nullptr;
    case RdataWriteResult::INVALID:
        warnlog(g_log, "Skipping a record of type {} with invalid RDATA", record.wType);
        return nullptr;
    }
    size_t rdlength = w.size() - rdlength_pos - sizeof(uint16_t);
    if (rdlength > MAX_RDATA_LENGTH) {
        warnlog(g_log, "Skipping a record of type {} with an oversized RDATA ({} bytes)", record.wType, rdlength);
        return nullptr;
    }
    w.set_u16(rdlength_pos, uint16_t(rdlength));

    ldns_rr *rr = nullptr;
    size_t pos = 0;
    ldns_status status = ldns_wire2rr(&rr, w.data().data(), w.size(), &pos, LDNS_SECTION_ANSWER);
    if (status != LDNS_STATUS_OK) {
        warnlog(g_log, "Skipping a record of type {} with malformed RDATA: {}", record.wType,
                ldns_get_errorstr_by_id(status));
        return nullptr;
    }
    ldns_rr_ptr result{rr};
    if (pos != w.size()) {
        warnlog(g_log, "Skipping a record of type {} with trailing bytes after the RDATA", record.wType);
        return nullptr;
    }
    return result;
}

static bool has_soa(const ldns_rr_list *list) {
    for (size_t i = 0; i < ldns_rr_list_rr_count(list); ++i) {
        if (ldns_rr_get_type(ldns_rr_list_rr(list, i)) == LDNS_RR_TYPE_SOA) {
            return true;
        }
    }
    return false;
}

Upstream::ExchangeResult make_system_reply(const ldns_pkt *request, DNS_STATUS status, const DNS_RECORDW *records) {
    ldns_pkt_rcode rcode = LDNS_RCODE_NOERROR;
    switch (status) {
    case ERROR_SUCCESS:
    case DNS_INFO_NO_RECORDS:
        rcode = LDNS_RCODE_NOERROR;
        break;
    case DNS_ERROR_RCODE_NAME_ERROR:
        rcode = LDNS_RCODE_NXDOMAIN;
        break;
    case DNS_ERROR_RCODE_FORMAT_ERROR:
        rcode = LDNS_RCODE_FORMERR;
        break;
    case DNS_ERROR_RCODE_SERVER_FAILURE:
        rcode = LDNS_RCODE_SERVFAIL;
        break;
    case DNS_ERROR_RCODE_NOT_IMPLEMENTED:
        rcode = LDNS_RCODE_NOTIMPL;
        break;
    case DNS_ERROR_RCODE_REFUSED:
        rcode = LDNS_RCODE_REFUSED;
        break;
    case ERROR_TIMEOUT:
    case WSAETIMEDOUT:
        return make_error(DnsError::AE_TIMED_OUT, win_error_string(status));
    default:
        return make_error(DnsError::AE_INTERNAL_ERROR, AG_FMT("DnsQueryEx() failed: {}", win_error_string(status)));
    }

    // `DnsQueryEx()` gives us the records only, not the raw reply, so the reply has to be assembled by hand.
    ldns_pkt_ptr reply{ldns_pkt_clone(request)};
    ldns_pkt_set_qr(reply.get(), true);
    ldns_pkt_set_aa(reply.get(), false);
    ldns_pkt_set_rd(reply.get(), true);
    ldns_pkt_set_ra(reply.get(), true);
    ldns_pkt_set_ad(reply.get(), false);
    ldns_pkt_set_cd(reply.get(), false);
    ldns_pkt_set_rcode(reply.get(), rcode);
    // Don't echo the EDNS options of the request
    ldns_rdf_deep_free(ldns_pkt_edns_data(reply.get()));
    ldns_pkt_set_edns_data(reply.get(), nullptr);

    for (const DNS_RECORDW *record = records; record != nullptr; record = record->pNext) {
        if (record->wType == LDNS_RR_TYPE_OPT) {
            continue;
        }
        ldns_pkt_section section = LDNS_SECTION_ANSWER;
        switch (record->Flags.S.Section) {
        case DnsSectionAuthority:
            section = LDNS_SECTION_AUTHORITY;
            break;
        case DnsSectionAddtional:
            section = LDNS_SECTION_ADDITIONAL;
            break;
        default:
            // Local answers (e.g. for `localhost`) are in the question section
            break;
        }
        ldns_rr_ptr rr = system_record_to_ldns(*record);
        if (rr == nullptr) {
            continue;
        }
        ldns_pkt_push_rr(reply.get(), section, rr.release());
    }

    if (ldns_pkt_ancount(reply.get()) == 0 && (rcode == LDNS_RCODE_NOERROR || rcode == LDNS_RCODE_NXDOMAIN)
            && !has_soa(ldns_pkt_authority(reply.get()))) {
        ldns_pkt_push_rr(reply.get(), LDNS_SECTION_AUTHORITY, create_soa(request));
    }

    return std::move(reply);
}

std::optional<std::wstring> system_query_name(const ldns_pkt *request) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    const ldns_rdf *owner = (question != nullptr) ? ldns_rr_owner(question) : nullptr;
    if (owner == nullptr || ldns_rdf_get_type(owner) != LDNS_RDF_TYPE_DNAME) {
        return std::nullopt;
    }

    std::string name;
    const uint8_t *data = ldns_rdf_data(owner);
    size_t size = ldns_rdf_size(owner);
    for (size_t pos = 0; pos < size;) {
        size_t length = data[pos++];
        if (length == 0) {
            break;
        }
        if (length > MAX_LABEL_LENGTH || length > size - pos) {
            return std::nullopt;
        }
        std::string_view label{(const char *) data + pos, length};
        if (label.find_first_of(std::string_view{".\0", 2}) != std::string_view::npos) {
            return std::nullopt;
        }
        if (!name.empty()) {
            name.push_back('.');
        }
        name.append(label);
        pos += length;
    }
    if (name.empty()) {
        name = ".";
    }

    int wide_size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(), int(name.size()), nullptr, 0);
    if (wide_size <= 0) {
        return std::nullopt;
    }
    std::wstring wide(wide_size, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(), int(name.size()), wide.data(), wide_size);
    return wide;
}

ULONG64 system_query_options(const ldns_pkt *request, bool tcp) {
    // The name is taken from the question as is: no search suffixes, no IDN conversions
    ULONG64 options = DNS_QUERY_TREAT_AS_FQDN | DNS_QUERY_DISABLE_IDN_ENCODING;
    // Don't try NetBIOS or multicast name resolution (LLMNR, mDNS): the DNS Client would stall on
    // their timeouts, while a DNS proxy isn't a stub resolver, so the requester handles multicast
    // name resolution on its own. The DNS Client's local answers (its cache, the hosts file,
    // `localhost`) are kept: unlike multicast, they don't delay the query.
    options |= DNS_QUERY_NO_NETBT | DNS_QUERY_NO_MULTICAST;
    // `DnsQueryEx()` doesn't expose the TC bit of the response (it returns the records only), so a
    // truncated UDP answer would silently look complete. Don't accept truncated responses: the DNS
    // client then retries over TCP and returns the full answer, and `DnsForwarder` truncates it for
    // the client's UDP size and sets TC.
    if (tcp) {
        options |= DNS_QUERY_USE_TCP_ONLY;
    }
    if (ldns_pkt_edns_do(request)) {
        options |= DNS_QUERY_DNSSEC_OK;
    }
    if (ldns_pkt_cd(request)) {
        options |= DNS_QUERY_DNSSEC_CHECKING_DISABLED;
    }
    return options;
}

/**
 * Sends DNS queries via `DnsQueryEx()` and assembles the replies from the returned records.
 *
 * The queries are performed by the DNS Client service (Dnscache), which `DnsQueryEx()` talks to
 * over RPC. The completion callback is therefore called on a dnsapi thread pool thread, and it may
 * be called at any time until it's invoked, including after `DnsCancelQuery()` returns: cancelling
 * doesn't wait for the query to complete. Some queries (e.g. for the local machine name, or IPv4/IPv6
 * address literals) are answered synchronously, without the callback.
 */
class SystemUpstream::Impl {
public:
    /**
     * The state shared between the event loop and the `DnsQueryEx()` completion callback.
     * The callback holds a reference until it's called, so the structures handed to `DnsQueryEx()`
     * outlive the query even if the request doesn't wait for the result anymore.
     */
    struct Context {
        std::mutex mutex;
        bool detached = false;             ///< The request no longer waits for the result. Guarded by `mutex`.
        bool completed = false;            ///< The query has completed. Guarded by `mutex`.
        DNS_STATUS status = ERROR_SUCCESS; ///< The query status. Guarded by `mutex`.
        RecordsPtr records;                ///< The returned records. Guarded by `mutex`.

        Impl *impl = nullptr;                     ///< Valid only while not detached.
        uint64_t id = 0;                          ///< The request ID in `Impl::m_requests`.
        const ldns_pkt *request = nullptr;        ///< Valid only while not detached.
        ldns_rr_type query_type = LDNS_RR_TYPE_A; ///< The type of the question.
        std::wstring name;
        ULONG64 options = 0;
        DNS_QUERY_RESULT result{};
        DNS_QUERY_CANCEL cancel_handle{};
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
     * @param request The request. Must outlive the returned awaitable.
     * @param name    The name to query (see `system_query_name()`).
     * @param tcp     Whether the system resolver should send the query over TCP.
     */
    auto send(const ldns_pkt *request, std::wstring name, bool tcp) {
        struct Awaitable {
            Request *req = nullptr; ///< The request, or null if it was rejected.
            std::optional<Upstream::ExchangeResult> result;

            bool await_ready() {
                if (req == nullptr) {
                    return true;
                }
                Context &ctx = *req->ctx;
                Impl &impl = *ctx.impl;
                DNS_QUERY_REQUEST request{};
                request.Version = DNS_QUERY_REQUEST_VERSION1;
                request.QueryName = ctx.name.c_str();
                request.QueryType = (WORD) ctx.query_type;
                request.QueryOptions = ctx.options;
                request.InterfaceIndex = impl.m_interface_index;
                request.pQueryCompletionCallback = on_query_complete;
                request.pQueryContext = new std::shared_ptr<Context>(req->ctx);
                ctx.result.Version = DNS_QUERY_RESULTS_VERSION1;

                DNS_STATUS status = DnsQueryEx(&request, &ctx.result, &ctx.cancel_handle);
                if (status != DNS_REQUEST_PENDING) {
                    // The query has completed synchronously, and the completion callback won't be called.
                    delete (std::shared_ptr<Context> *) request.pQueryContext;
                    RecordsPtr records{(DNS_RECORDW *) std::exchange(ctx.result.pQueryRecords, nullptr)};
                    ctx.completed = true;
                    tracelog(g_log, "DnsQueryEx completed synchronously with status {}", status);
                    set_result(*req, status, records.get());
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
        req.ctx->query_type = ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_question(request), 0));
        req.ctx->name = std::move(name);
        req.ctx->options = system_query_options(request, tcp);

        return Awaitable{.req = &req};
    }

    /**
     * The `DnsQueryEx()` completion callback. Called on an arbitrary thread.
     */
    static VOID WINAPI on_query_complete(PVOID query_context, PDNS_QUERY_RESULT result) {
        std::unique_ptr<std::shared_ptr<Context>> holder{(std::shared_ptr<Context> *) query_context};
        std::shared_ptr<Context> ctx = std::move(*holder);
        RecordsPtr records{
                (result != nullptr) ? (DNS_RECORDW *) std::exchange(result->pQueryRecords, nullptr) : nullptr};

        std::scoped_lock l(ctx->mutex);
        ctx->completed = true;
        if (ctx->detached) {
            return;
        }
        ctx->status = (result != nullptr) ? result->QueryStatus : ERROR_INVALID_DATA;
        ctx->records = std::move(records);
        // Submit while holding the lock: the request is detached on the event loop under the same lock
        // before the upstream is destroyed, so the loop is guaranteed to still be running at this point.
        ctx->impl->m_loop->submit([ctx] {
            on_query_result(ctx);
        });
    }

    static void on_query_result(const std::shared_ptr<Context> &ctx) {
        DNS_STATUS status = ERROR_SUCCESS;
        RecordsPtr records;
        {
            std::scoped_lock l(ctx->mutex);
            if (ctx->detached) {
                return;
            }
            status = ctx->status;
            records = std::move(ctx->records);
        }
        auto it = ctx->impl->m_requests.find(ctx->id);
        if (it == ctx->impl->m_requests.end()) {
            return;
        }
        tracelog(g_log, "DnsQueryEx completed with status {}", status);
        set_result(it->second, status, records.get());
        ctx->impl->complete_request(it->second);
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
            // The completion callback locks this mutex, and may be invoked by `DnsCancelQuery()` or run
            // on another thread already, so the lock must not be held here.
            if (DNS_STATUS status = DnsCancelQuery(&ctx.cancel_handle); ERROR_SUCCESS != status) {
                AllocatedPtr<char> type{ldns_rr_type2str(ctx.query_type)};
                warnlog(g_log, "DnsCancelQuery failed for request {} (name: {}, type: {}, options: {:#x}): {}", ctx.id,
                        utils::from_wstring(ctx.name), (type != nullptr) ? type.get() : "(unknown)", ctx.options,
                        win_error_string(status));
            }
        }
    }

    static void set_result(Request &req, DNS_STATUS status, const DNS_RECORDW *records) {
        auto result = make_system_reply(req.ctx->request, status, records);
        if (result.has_error()) {
            req.error = result.error();
        } else {
            req.reply = std::move(result.value());
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
    std::optional<std::wstring> name = system_query_name(request_pkt);
    if (!name.has_value()) {
        co_return make_error(DnsError::AE_ENCODE_ERROR, "The question name can't be passed to DnsQueryEx()");
    }

    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request_pkt), 0);
    if (ldns_rr_get_class(question) != LDNS_RR_CLASS_IN) {
        // `DnsQueryEx()` doesn't let one specify the class
        ldns_pkt_ptr reply{ldns_pkt_clone(request_pkt)};
        ldns_pkt_set_qr(reply.get(), true);
        ldns_pkt_set_ra(reply.get(), true);
        ldns_pkt_set_rcode(reply.get(), LDNS_RCODE_NOTIMPL);
        co_return std::move(reply);
    }

    bool tcp = info != nullptr && info->proto == utils::TP_TCP;

    // Nothing below this line may touch `this`: the awaiting request is resumed with
    // AE_SHUTTING_DOWN from the destructor, i.e. after the upstream itself is gone.
    co_return co_await m_pimpl->send(request_pkt, std::move(name.value()), tcp);
}

} // namespace ag::dns
