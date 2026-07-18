// adyg_cli — packet construction & dig-compatible formatting for the pure adyg
// CLI logic.
//
// This translation unit holds the query builder (make_query), the EDNS-layer
// flag applier (apply_dns_flags), the ADDITIONAL-glue extractor (+trace) and the
// dig-style packet/trace/server/when formatters. See adyg_cli.h for the public
// interface and adyg_cli.cpp for argument parsing.

#include "adyg_cli.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <fmt/format.h>
#include <ldns/ldns.h>

#include "adyg_cli_internal.h"
#include "dns/common/net_consts.h"

namespace ag::adyg {
namespace {

// RAII wrapper for ldns malloc'd strings (char pointers returned by
// ldns_rdf2str, ldns_rr_type2str, etc.) — they must be freed with free().
using ag::AllocatedPtr;

// Compute the wire-format size of a packet. ldns caches the size only for
// packets parsed from wire bytes; freshly-built query packets report 0, so we
// force a round-trip through ldns_pkt2wire in that case.
size_t wire_pkt_size(const ldns_pkt *pkt) {
    if (pkt == nullptr) {
        return 0;
    }
    size_t cached = ldns_pkt_size(pkt);
    if (cached != 0) {
        return cached;
    }
    uint8_t *wire = nullptr;
    size_t sz = 0;
    if (ldns_pkt2wire(&wire, pkt, &sz) == LDNS_STATUS_OK) {
        AllocatedPtr<uint8_t> owned(wire);
        (void) owned;
        return sz;
    }
    return 0;
}

// Build the lowercase flag string dig prints in the header, e.g. "qr rd ra".
// The DO bit is shown in the OPT PSEUDOSECTION, not in the header flags.
std::string pkt_flags_str(const ldns_pkt *pkt) {
    std::string s;
    if (ldns_pkt_qr(pkt)) {
        s += " qr";
    }
    if (ldns_pkt_aa(pkt)) {
        s += " aa";
    }
    if (ldns_pkt_tc(pkt)) {
        s += " tc";
    }
    if (ldns_pkt_rd(pkt)) {
        s += " rd";
    }
    if (ldns_pkt_ra(pkt)) {
        s += " ra";
    }
    if (ldns_pkt_ad(pkt)) {
        s += " ad";
    }
    if (ldns_pkt_cd(pkt)) {
        s += " cd";
    }
    return s;
}

// `dig +multiline` wraps long RDATA in parentheses with a four-tab indent;
// owners are tab-padded to column 24 and the TTL/class/type/RDATA fields are
// space-separated. Verified against `dig 9.20 +multiline` (an `example.com.`
// A record prints `example.com.\t\t300 IN A 1.2.3.4`, byte-identical to dig).
// RRSIG-style wrapping reproduces dig's structure (parens + 4-tab continuation)
// but is not guaranteed byte-identical for every token break.
constexpr size_t MULTILINE_OWNER_COL = 24;
constexpr size_t MULTILINE_WIDTH = 79;
constexpr std::string_view MULTILINE_INDENT = "\t\t\t\t";

// The standard tab-stop width dig uses for its column layout (8 chars/tab).
constexpr size_t TAB_WIDTH = 8;

// SOA RDATA field names, matching dig's `soa_6.c` soa_fieldnames table.
constexpr std::string_view SOA_FIELD_NAMES[] = {"serial", "refresh", "retry", "expire", "minimum"};

// Pad `out` from `current_col` to `target_col` using tabs (and trailing
// spaces as needed), mirroring BIND's `indent()` in masterdump.c. The
// guarantee from BIND is: at minimum one column of separation is inserted (a
// bare `target_col == current_col` advances by one space so fields never
// abut). Returns the actual column reached (which is `target_col`, or
// `current_col + 1` when that is larger).
size_t indent_to(std::string &out, size_t current_col, size_t target_col) {
    size_t to = (target_col < current_col + 1) ? current_col + 1 : target_col;
    size_t from = current_col;
    size_t ntabs = to / TAB_WIDTH - from / TAB_WIDTH;
    if (ntabs > 0) {
        out.append(ntabs, '\t');
        from = (to / TAB_WIDTH) * TAB_WIDTH;
    }
    out.append(to - from, ' ');
    return to;
}

// Compute the column layout dig uses for the given display flags, mirroring
// dighost.c's three-branch `dns_master_stylecreate`:
//   - multiline (or both +nottlid and +noclass): (24, 24, 24, 32)
//   - +nottlid xor +noclass (non-multiline):      (24, 24, 32, 40)
//   - default (all on):                            (24, 32, 40, 48)
// The columns are where TTL/class/type/RDATA begin (in BIND's column view,
// which for the QUESTION section excludes the leading `;` prefix).
struct ColumnLayout {
    size_t ttl_col;
    size_t class_col;
    size_t type_col;
    size_t rdata_col;
};
ColumnLayout compute_column_layout(const DisplayFlags &flags) {
    const bool nottl = !flags.ttlid;
    const bool noclass = !flags.cls;
    if (flags.multiline || (nottl && noclass)) {
        return {24, 24, 24, 32};
    }
    if (nottl || noclass) {
        return {24, 24, 32, 40};
    }
    return {24, 32, 40, 48};
}

// Format a single RR in dig-compatible text using the column-based layout
// mirrored from BIND's `rdataset_totext` / `question_totext`. The `column`
// tracker follows BIND's convention: it starts at 0 and excludes the leading
// `;` for QUESTION-section RRs (the `;` is appended by the caller, not counted
// in the column tracking — that is why the QUESTION section's class lands at
// the next tab stop past the owner name length, not past owner+1).
//
// `with_ttl` is false for QUESTION RRs (which never carry a TTL); `with_class`
// is true for QUESTION and honor `+cls` for the data sections (dig's question
// format always shows class — see `question_totext` in masterdump.c which does
// not gate class on DNS_STYLEFLAG_NO_CLASS).
std::string format_rr_dig(const ldns_rr *rr, const DisplayFlags &flags, bool is_question) {
    std::string out;
    if (is_question) {
        out += ';';
    }
    AllocatedPtr<char> owner(ldns_rdf2str(ldns_rr_owner(rr)));
    out += (owner != nullptr) ? owner.get() : "";

    const bool show_class = flags.cls || is_question;
    const bool show_ttl = flags.ttlid && !is_question;
    const ColumnLayout cols = compute_column_layout(flags);

    AllocatedPtr<char> cls(ldns_rr_class2str(ldns_rr_get_class(rr)));
    std::string cls_str = (cls != nullptr) ? cls.get() : "IN";
    AllocatedPtr<char> type(ldns_rr_type2str(ldns_rr_get_type(rr)));
    std::string type_str = (type != nullptr) ? type.get() : "";

    // Column tracking: in BIND's view, the leading `;` (QUESTION prefix) is
    // NOT counted (it's printed by the caller). The cursor starts at 0 and
    // advances by the owner-name length.
    size_t column = out.size() - (is_question ? 1 : 0);

    // SOA multiline gets a dedicated path below.
    const ldns_rr_type rr_type = ldns_rr_get_type(rr);
    if (flags.multiline && !is_question && rr_type == LDNS_RR_TYPE_SOA) {
        // Pad owner to column 24 (multiline owner column) then walk the
        // TTL/class/type via the column layout (which for multiline is
        // (24,24,24,32), so each INDENT_TO past the first adds at least one
        // space — yielding the `300 IN SOA ` / `IN SOA\t` patterns). The
        // SOA RDATA mname/rname follow, then a ` (` opens the per-field
        // continuation block.
        if (show_ttl) {
            column = indent_to(out, column, cols.ttl_col);
            const std::string ttl_str =
                    (flags.ttl_units ? format_dns_ttl_units(ldns_rr_ttl(rr)) : fmt::format("{}", ldns_rr_ttl(rr)));
            out += ttl_str;
            column += ttl_str.size();
        }
        if (show_class) {
            column = indent_to(out, column, cols.class_col);
            out += cls_str;
            column += cls_str.size();
        }
        column = indent_to(out, column, cols.type_col);
        out += type_str;
        column += type_str.size();
        // The two name RDATA fields (mname, rname) follow at the rdata_col,
        // space-separated; then ` (` opens the multi-line block.
        column = indent_to(out, column, cols.rdata_col);
        static constexpr size_t SOA_MNAME = 0;
        static constexpr size_t SOA_RNAME = 1;
        AllocatedPtr<char> mname(ldns_rdf2str(ldns_rr_rdf(rr, SOA_MNAME)));
        AllocatedPtr<char> rname(ldns_rdf2str(ldns_rr_rdf(rr, SOA_RNAME)));
        out += (mname != nullptr) ? mname.get() : "";
        out += ' ';
        out += (rname != nullptr) ? rname.get() : "";
        out += " (\n";
        // Each numeric field on its own line: 4-tab indent + `%-10lu` +
        // ` ; <name>` (+ ` (<verbose-ttl>)` for refresh/retry/expire/minimum).
        // Pads the numeric value to 10 columns left-justified so the `;`
        // lines up across fields (matches BIND's `"%-10lu ; "` format).
        //
        // Stop at the first missing field: ldns's wire parser accepts a SOA
        // whose RDATA is truncated on a field boundary (it parses as many
        // fields as fit, so e.g. mname+rname+serial yields rd_count==3). For
        // such an RR ldns_rr_rdf() returns NULL past the parsed fields, and
        // ldns_rdf2native_int32(NULL) is NOT null-safe (ldns_rdf_size asserts
        // and dereferences NULL). Guard explicitly rather than blindly
        // indexing all five numeric fields.
        for (size_t i = 0; i < 5; ++i) {
            const ldns_rdf *field = ldns_rr_rdf(rr, static_cast<size_t>(2 + i));
            if (field == nullptr) {
                break;
            }
            const uint32_t value = ldns_rdf2native_int32(field);
            out += MULTILINE_INDENT;
            out += fmt::format("{:<10} ; {}", value, SOA_FIELD_NAMES[i]);
            if (i >= 1) {
                out += " (";
                out += format_dns_ttl_verbose(value);
                out += ")";
            }
            out += '\n';
        }
        out += MULTILINE_INDENT;
        out += ")\n";
        return out;
    }

    // Non-SOA path (single-line, or multiline without per-field comments).
    if (show_ttl) {
        column = indent_to(out, column, cols.ttl_col);
        const std::string ttl_str =
                (flags.ttl_units ? format_dns_ttl_units(ldns_rr_ttl(rr)) : fmt::format("{}", ldns_rr_ttl(rr)));
        out += ttl_str;
        column += ttl_str.size();
    }
    if (show_class) {
        column = indent_to(out, column, cols.class_col);
        out += cls_str;
        column += cls_str.size();
    }
    column = indent_to(out, column, cols.type_col);
    out += type_str;
    column += type_str.size();

    if (is_question) {
        out += '\n';
        return out;
    }

    // RDATA: dig delegates to per-type formatters; for the generic case the
    // RDATA fields are joined with single spaces (verified against `dig 9.20`:
    // `SOA ns1. rname. 1 7200 3600 604800 86400`, `TXT "a" "b"`, etc.). For
    // +multiline, short records stay on one line (no parens), and only the
    // SOA path above (and the generic-width wrapping below for RRSIG-like
    // binary RDATA) insert `(` `)` continuation lines.
    column = indent_to(out, column, cols.rdata_col);

    // Collect RDATA fields (strings from ldns_rdf2str) for both the
    // single-line and the multiline-wrap paths below.
    size_t rd_count = ldns_rr_rd_count(rr);
    std::vector<std::string> rdfs;
    rdfs.reserve(rd_count);
    for (size_t i = 0; i < rd_count; ++i) {
        AllocatedPtr<char> rdf_str(ldns_rdf2str(ldns_rr_rdf(rr, i)));
        rdfs.emplace_back((rdf_str != nullptr) ? rdf_str.get() : "");
    }

    // dig's DS / CDS per-type formatters emit the digest (the trailing hex
    // RDATA field) in UPPERCASE. ldns's ldns_rdf2str renders hex as lowercase
    // by default, so uppercase the trailing field here to match dig (verified
    // against `dig example.com DS`). The leading three fields (key tag,
    // algorithm, digest type) are decimal integers, so case does not apply.
    // Other hex-bearing types (SSHFP/TLSA/...) also use uppercase in dig, but
    // adyg's RRSIG base64 wrapping and the multiline `(` placement for DS /
    // RRSIG are not yet byte-exact (see the note below on the generic wrapping
    // path), so this targeted fix addresses only the reported DS discrepancy.
    if (rr_type == LDNS_RR_TYPE_DS || rr_type == LDNS_RR_TYPE_CDS) {
        if (!rdfs.empty()) {
            std::string &digest = rdfs.back();
            std::transform(digest.begin(), digest.end(), digest.begin(), [](unsigned char c) {
                return static_cast<char>(std::toupper(c));
            });
        }
    }

    // +multiline wrapping is dig-specific per RDATA type; only SOA (above) and
    // a small set of base64/hex-bearing types (DS/KEY/RRSIG/SSHFP) actually
    // wrap in BIND's `totext` formatters. TXT (and most other types) never
    // wrap — verified: `dig +multiline` does not parenthesize a 200-char TXT
    // string. To avoid spurious wrapping of TXT (and remain correct for the
    // short A/AAAA/MX/NS-style records that don't need wrapping either), the
    // generic `( ... )` wrapping here applies only to base64/hex-bearing types
    // — TXT and the name/string-bearing types always print single-line.
    static constexpr ldns_rr_type WRAPPABLE_TYPES[] = {
            LDNS_RR_TYPE_DS, LDNS_RR_TYPE_KEY, LDNS_RR_TYPE_RRSIG, LDNS_RR_TYPE_SSHFP};
    auto is_wrappable = [&]() {
        for (ldns_rr_type t : WRAPPABLE_TYPES) {
            if (t == rr_type) {
                return true;
            }
        }
        return false;
    };

    if (!flags.multiline || !is_wrappable() || rdfs.empty()) {
        // Single line: RDATA fields joined with single spaces (matches dig's
        // per-type formatters for the common types adyg handles).
        for (size_t i = 0; i < rdfs.size(); ++i) {
            if (i != 0) {
                out += ' ';
            }
            out += rdfs[i];
        }
        out += '\n';
        return out;
    }

    // `+multiline` for a base64/hex-bearing type whose RDATA exceeds
    // MULTILINE_WIDTH: wrap in `( ... )` with a four-tab continuation indent.
    // This reproduces dig's structure (parens + 4-tab continuation) but the
    // per-token break points are not guaranteed byte-identical to dig's
    // hex/base64 column wrapping for every record.
    size_t width = out.size() + 1;
    for (size_t i = 0; i < rdfs.size(); ++i) {
        width += (i != 0 ? 1 : 0) + rdfs[i].size();
    }
    if (width <= MULTILINE_WIDTH) {
        for (const std::string &s : rdfs) {
            out += ' ';
            out += s;
        }
        out += '\n';
        return out;
    }
    out += " (\n";
    std::string line{MULTILINE_INDENT};
    for (size_t i = 0; i < rdfs.size(); ++i) {
        const std::string &token = rdfs[i];
        size_t sep = (i != 0) ? 1 : 0;
        if (line.size() > MULTILINE_INDENT.size() && line.size() + sep + token.size() > MULTILINE_WIDTH) {
            out += line;
            out += '\n';
            line = std::string{MULTILINE_INDENT};
            sep = 0;
        }
        if (sep != 0) {
            line += ' ';
        }
        line += token;
    }
    out += line;
    out += " )\n";
    return out;
}

} // namespace

ldns_pkt_ptr make_query(const std::string &name, ldns_rr_type type, bool recurse) {
    std::string fqdn = name;
    if (!fqdn.empty() && fqdn.back() != '.') {
        fqdn += '.';
    }
    ldns_rdf *dname = ldns_dname_new_frm_str(fqdn.c_str());
    if (dname == nullptr) {
        return {nullptr};
    }
    ldns_pkt *pkt = ldns_pkt_query_new(dname, type, LDNS_RR_CLASS_IN, recurse ? LDNS_RD : 0);
    if (pkt == nullptr) {
        // ldns_pkt_query_new did not consume `dname` on failure, so it must be
        // freed here to avoid a leak (mirrors the explicit free on this error
        // path in other call sites, e.g. dnscrypt/dns_crypt_ldns.cpp).
        ldns_rdf_deep_free(dname);
        return {nullptr};
    }
    ldns_pkt_set_random_id(pkt);
    return ldns_pkt_ptr(pkt);
}

void apply_dns_flags(ldns_pkt *pkt, const CliOptions &opts) {
    if (pkt == nullptr) {
        return;
    }
    // AD (Authenticated Data) flag: `dig` sets this by default in its queries
    // to request that the upstream set AD in its response when the data is
    // authentic. It is a DNS header flag (not an EDNS extension), so it is
    // applied unconditionally — even under `+noedns`. `+noadflag` clears it.
    if (opts.ad) {
        ldns_pkt_set_ad(pkt, true);
    }
    // `+header-only`: strip the question section (QDCOUNT=0), mirroring `dig
    // +header-only` which sends a spec-compliant header-only query (no
    // question records) to probe the server's capabilities. The question RR
    // was attached by make_query; replace it with an empty list and update the
    // count. Deep-free the original list to avoid leaking the stripped RR.
    if (opts.header_only) {
        ldns_rr_list *question = ldns_pkt_question(pkt);
        ldns_pkt_set_question(pkt, ldns_rr_list_new());
        ldns_pkt_set_qdcount(pkt, 0);
        if (question != nullptr) {
            ldns_rr_list_deep_free(question);
        }
    }
    // Determine whether an OPT RR must be present. `+edns` (the default) and
    // `+dnssec` / `+subnet` / `+nsid` / `+padding` / `+ednsflags` / `+ednsopt`
    // all require one. `+noedns` (opts.edns == false) suppresses the default
    // OPT only when no EDNS-bearing option forces it — mirroring `dig`, where
    // `+dnssec` / `+subnet` / `+nsid` / `+padding` / `+ednsflags` still attach
    // an OPT RR under `+noedns` (they all live inside the OPT record). Each
    // `+ednsopt` entry is likewise an EDNS option, so it forces an OPT RR here
    // for consistency (dig only attaches it when EDNS is otherwise enabled; adyg
    // attaches it unconditionally, matching its +nsid/+subnet/+padding policy).
    const bool want_edns = opts.edns || opts.dnssec || opts.subnet.enabled || opts.nsid || opts.padding != 0
            || opts.edns_flags.has_value() || !opts.ednsopts.empty();
    if (!want_edns) {
        // Only the header-level CD bit (below) and the opcode override may
        // still apply.
        if (opts.cd) {
            ldns_pkt_set_cd(pkt, true);
        }
        if (opts.opcode.has_value()) {
            ldns_pkt_set_opcode(pkt, *opts.opcode);
        }
        return;
    }
    // Advertising a >0 EDNS UDP payload size is what makes ldns synthesize the
    // OPT pseudo-RR on the wire (ldns_pkt_edns() returns true once the UDP
    // size is non-zero). `+bufsize` overrides the default of 4096.
    const uint16_t udp_size =
            (opts.edns_bufsize != 0) ? opts.edns_bufsize : static_cast<uint16_t>(dns::UDP_RECV_BUF_SIZE);
    ldns_pkt_set_edns_udp_size(pkt, udp_size);
    ldns_pkt_set_edns_version(pkt, opts.edns_version);
    // EDNS flags: the DO bit (set by +dnssec) is bit 15 of the Z field. When
    // +ednsflags is given it sets the raw Z bits; combine with DO so both can
    // be used together (mirrors `dig`, where +ednsflags ORs alongside DO).
    if (opts.edns_flags.has_value()) {
        uint16_t z = *opts.edns_flags;
        if (opts.dnssec) {
            z |= 0x8000; // DO
        }
        ldns_pkt_set_edns_z(pkt, z);
    } else if (opts.dnssec) {
        // RFC 3225: set the DO bit so the upstream returns DNSSEC records.
        ldns_pkt_set_edns_do(pkt, true);
    }
    if (opts.cd) {
        // Checking Disabled: ask the upstream to skip DNSSEC validation.
        ldns_pkt_set_cd(pkt, true);
    }
    // Attach EDNS options as a single concatenated OPT RDATA blob (ldns stores
    // one edns_data rdf, written verbatim). Each enabled option contributes its
    // wire TLV via the shared encoder.
    std::vector<uint8_t> edns_data;
    if (opts.cookie) {
        // RFC 7873: DNS COOKIE option (code 10). `dig` sends an 8-byte random
        // client cookie by default (no server cookie on the first query). The
        // cookie is generated here via ldns_get_random (seeded by
        // ldns_init_random in main), mirroring dig's isc_nonce-based client
        // cookie. It is only attached when an OPT RR is present (above), so
        // `+noedns` suppresses it entirely — matching `dig`.
        uint8_t cookie_bytes[8] = {};
        for (size_t i = 0; i < 4; ++i) {
            const uint16_t r = ldns_get_random();
            cookie_bytes[i * 2] = static_cast<uint8_t>(r >> 8);
            cookie_bytes[i * 2 + 1] = static_cast<uint8_t>(r & 0xFF);
        }
        std::vector<uint8_t> tlv = encode_edns_option(0x0A, cookie_bytes, sizeof(cookie_bytes));
        edns_data.insert(edns_data.end(), tlv.begin(), tlv.end());
    }
    if (opts.subnet.enabled) {
        std::vector<uint8_t> tlv = encode_ecs_option(opts.subnet.addr, opts.subnet.src_prefix);
        if (!tlv.empty()) {
            edns_data.insert(edns_data.end(), tlv.begin(), tlv.end());
        }
    }
    if (opts.nsid) {
        // RFC 5001: NSID option (code 3), empty data from the client.
        std::vector<uint8_t> tlv = encode_edns_option(0x03, nullptr, 0);
        edns_data.insert(edns_data.end(), tlv.begin(), tlv.end());
    }
    // `+ednsopt` generic options (RFC 6891), appended after the named options
    // (ECS/NSID) and before Padding — mirroring `dig`'s build order, where the
    // user-supplied option list is added after +nsid/+subnet/+cookie/... and
    // +padding may then pad the assembled message. The order on the wire
    // therefore follows the argv order of `+ednsopt` occurrences.
    for (const EdnsOption &opt : opts.ednsopts) {
        std::vector<uint8_t> tlv = encode_edns_option(opt.code, opt.data.data(), opt.data.size());
        edns_data.insert(edns_data.end(), tlv.begin(), tlv.end());
    }
    if (opts.padding != 0) {
        // RFC 7830: Padding option (code 12), N zero bytes.
        std::vector<uint8_t> zeros(opts.padding, 0);
        std::vector<uint8_t> tlv = encode_edns_option(0x0C, zeros.data(), zeros.size());
        edns_data.insert(edns_data.end(), tlv.begin(), tlv.end());
    }
    if (!edns_data.empty()) {
        ldns_rdf *rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NONE, edns_data.size(), edns_data.data());
        if (rdf != nullptr) {
            // The packet takes ownership of `rdf` (it is freed with the pkt).
            ldns_pkt_set_edns_data(pkt, rdf);
        }
    }
    // The opcode override is applied last so a NOTIFY/UPDATE still carries the
    // requested EDNS options (it touches only the header opcode field).
    if (opts.opcode.has_value()) {
        ldns_pkt_set_opcode(pkt, *opts.opcode);
    }
}

std::string validate_edns_option_sizes(const CliOptions &opts) {
    // Same gate as apply_dns_flags(): when no OPT RR is attached, no option
    // bytes are written either (the cookie is suppressed along with the OPT).
    const bool want_edns = opts.edns || opts.dnssec || opts.subnet.enabled || opts.nsid || opts.padding != 0
            || opts.edns_flags.has_value() || !opts.ednsopts.empty();
    if (!want_edns) {
        return {};
    }
    // The OPT record's RDLEN is a 16-bit field, so the concatenated EDNS option
    // blob may not exceed 65535 bytes; each option's option-length is likewise a
    // 16-bit field, so a single option's data may not exceed 65535 bytes
    // (encode_edns_option would otherwise truncate it to uint16_t, emitting a
    // TLV whose header length disagrees with its body — a malformed packet).
    constexpr size_t MAX = 65535;
    constexpr size_t TLV_HEADER = 4; // option-code(2 BE) + option-length(2 BE)
    size_t total = 0;
    // Returns a non-empty error string when `data_len` exceeds the per-option
    // limit; otherwise accumulates the option's full TLV size (4 + data_len)
    // into `total`. Mirrors encode_edns_option's on-wire size exactly so the
    // accounting stays in lockstep with the bytes apply_dns_flags() writes.
    auto add_option = [&total](size_t data_len) -> std::string {
        if (data_len > MAX) {
            return fmt::format("EDNS option payload exceeds 65535 bytes: {}", data_len);
        }
        total += TLV_HEADER + data_len;
        return {};
    };
    // Mirror apply_dns_flags's assembly order exactly: cookie, ECS, NSID, the
    // +ednsopt list, then padding last.
    if (opts.cookie) {
        // RFC 7873: an 8-byte client cookie (no server cookie on the first query).
        if (std::string e = add_option(8); !e.empty()) {
            return e;
        }
    }
    if (opts.subnet.enabled) {
        // The ECS TLV is produced by encode_ecs_option; its full size is taken
        // verbatim (an empty result means an invalid addr/prefix, rejected at
        // parse time — defended here so the accounting never over-credits a
        // dropped option). option-data = full TLV - the 4-byte header.
        std::vector<uint8_t> ecs = encode_ecs_option(opts.subnet.addr, opts.subnet.src_prefix);
        if (!ecs.empty()) {
            if (std::string e = add_option(ecs.size() - TLV_HEADER); !e.empty()) {
                return e;
            }
        }
    }
    if (opts.nsid) {
        // RFC 5001: NSID option (code 3), empty data from the client.
        if (std::string e = add_option(0); !e.empty()) {
            return e;
        }
    }
    for (const EdnsOption &opt : opts.ednsopts) {
        if (std::string e = add_option(opt.data.size()); !e.empty()) {
            return e;
        }
    }
    if (opts.padding != 0) {
        // RFC 7830: Padding option (code 12), opts.padding zero bytes.
        if (std::string e = add_option(opts.padding); !e.empty()) {
            return e;
        }
    }
    if (total > MAX) {
        return fmt::format("combined EDNS option data exceeds 65535 bytes: {}", total);
    }
    return {};
}

std::map<std::string, GlueAddress> additional_glue(const ldns_pkt *pkt) {
    std::map<std::string, GlueAddress> glue;
    if (pkt == nullptr) {
        return glue;
    }
    const ldns_rr_list *additional = ldns_pkt_additional(pkt);
    if (additional == nullptr) {
        return glue;
    }
    for (size_t i = 0; i < ldns_rr_list_rr_count(additional); ++i) {
        const ldns_rr *rr = ldns_rr_list_rr(additional, i);
        ldns_rr_type type = ldns_rr_get_type(rr);
        if (type != LDNS_RR_TYPE_A && type != LDNS_RR_TYPE_AAAA) {
            continue;
        }
        AllocatedPtr<char> owner(ldns_rdf2str(ldns_rr_owner(rr)));
        AllocatedPtr<char> addr(ldns_rdf2str(ldns_rr_rdf(rr, 0)));
        if (owner == nullptr || addr == nullptr) {
            continue;
        }
        // Prefer A over AAAA: an A record always wins (overwriting any prior
        // AAAA for the same owner), and an AAAA is kept only when no A was seen
        // for that owner. This prevents a later AAAA from displacing an earlier
        // A in the ADDITIONAL section, so +trace neither prefers IPv6 when IPv4
        // glue is present nor makes the chosen address depend on RR ordering.
        if (type == LDNS_RR_TYPE_A) {
            glue.insert_or_assign(owner.get(), GlueAddress{addr.get(), false});
        } else {
            glue.try_emplace(owner.get(), GlueAddress{addr.get(), true});
        }
    }
    return glue;
}

bool glue_address_usable(const GlueAddress &glue, bool ipv4_only) {
    // -4 (ipv4_only) suppresses IPv6 so a literal IPv6 address is never passed
    // to trace_exchange() (ipv6_available only governs AAAA bootstrapping, not
    // dialing a literal IPv6 peer).
    return !(ipv4_only && glue.ipv6);
}

std::string format_dig_server(std::string_view server, std::optional<uint16_t> port, bool tcp) {
    if (server.empty()) {
        return {};
    }
    // adyg's `+tcp` rewrite (apply_force_tcp) prefixes a bare host with `tcp://`
    // — and rewrites `udp://`/`dns://` to `tcp://` — *before* this function is
    // called, so a SERVER string built afterwards still carries the plain-DNS
    // scheme. Strip it (case-insensitively, mirroring the upstream library's
    // `utils::istarts_with` scheme matching) so the formatted
    // `IP#port(host) (proto)` line is produced rather than the raw `tcp://` URL
    // being echoed. The protocol is taken from the scheme when one is present;
    // the `tcp` parameter is the fallback for a bare host. Encrypted schemes
    // (`tls://`, `https://`, `h3://`, `quic://`, `sdns://`, `system://`, …) are
    // left verbatim — dig's SERVER formatting only applies to plain DNS.
    struct PlainScheme {
        std::string_view prefix;
        bool is_tcp;
    };
    static constexpr PlainScheme PLAIN_SCHEMES[] = {
            {"tcp://", true},
            {"udp://", false},
            {"dns://", false},
    };
    bool use_tcp = tcp;
    for (const PlainScheme &s : PLAIN_SCHEMES) {
        if (server.size() > s.prefix.size()
                && std::equal(s.prefix.begin(), s.prefix.end(), server.begin(), [](char a, char b) {
                       return std::tolower(static_cast<unsigned char>(a))
                               == std::tolower(static_cast<unsigned char>(b));
                   })) {
            server.remove_prefix(s.prefix.size());
            use_tcp = s.is_tcp;
            break;
        }
    }
    // Any remaining `://` is an encrypted upstream: leave it verbatim.
    if (server.find("://") != std::string_view::npos) {
        return std::string(server);
    }
    // Split an explicit `host:port` (a single host/port colon; a bare IPv6
    // literal — two or more colons — is left untouched).
    std::string_view host = server;
    uint16_t explicit_port = 53;
    if (auto p = split_plain_host_port(host)) {
        explicit_port = *p;
    }
    const uint16_t use_port = port.value_or(explicit_port);
    // dig renders `IP#port(IP) (proto)` for plain DNS (the IP and the
    // parenthetical name are the same bare host when no reverse-DNS name is
    // involved).
    return fmt::format("{}#{}({}) ({})", host, use_port, host, use_tcp ? "TCP" : "UDP");
}

std::string format_dig_when(std::time_t when) {
    if (when == 0) {
        return {};
    }
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &when);
#else
    localtime_r(&when, &tm);
#endif
    char buf[64];
    // dig's WHEN format is `%a %b %d %H:%M:%S %Z %Y` with the day space-padded
    // for a single digit (strftime's `%d` zero-pads it). Build it in two
    // strftime legs with the day inserted between them so the leading-zero
    // replacement does not assume `%a` and `%b` are each exactly 3 chars — they
    // are not in every locale, and the old fixed `out[8]` swap could then miss
    // (or, worse, edit the wrong byte).
    size_t n1 = std::strftime(buf, sizeof(buf), "%a %b ", &tm);
    std::string out(buf, n1);
    // Right-align the day in two chars: `5` -> ` 5` (mirrors dig's space
    // padding, swapping the zero pad for a space), `16` -> `16`.
    out += fmt::format("{:>2}", tm.tm_mday);
    size_t n2 = std::strftime(buf, sizeof(buf), " %H:%M:%S %Z %Y", &tm);
    out.append(buf, n2);
    return out;
}

std::string format_packet_dig(const ldns_pkt *pkt, const DisplayFlags &flags, bool is_query, Millis query_time,
        std::string_view server, std::time_t when) {
    if (pkt == nullptr) {
        return {};
    }
    std::string out;

    // Header (opcode, status, id, flags, counts).
    if (flags.comments) {
        out += is_query ? ";; Sending:\n" : ";; Got answer:\n";
        AllocatedPtr<char> opcode(ldns_pkt_opcode2str(ldns_pkt_get_opcode(pkt)));
        AllocatedPtr<char> rcode(ldns_pkt_rcode2str(ldns_pkt_get_rcode(pkt)));
        out += fmt::format(";; ->>HEADER<<- opcode: {}, status: {}, id: {}\n", (opcode != nullptr) ? opcode.get() : "",
                (rcode != nullptr) ? rcode.get() : "", ldns_pkt_id(pkt));
        // dig counts the OPT RR in ADDITIONAL; ldns stores it separately.
        size_t arcount = ldns_pkt_arcount(pkt);
        if (ldns_pkt_edns(pkt)) {
            ++arcount;
        }
        std::string fstr = pkt_flags_str(pkt);
        out += fmt::format(";; flags:{}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}\n\n",
                fstr.empty() ? "" : fstr, ldns_pkt_qdcount(pkt), ldns_pkt_ancount(pkt), ldns_pkt_nscount(pkt), arcount);
    }

    // OPT PSEUDOSECTION (shown before QUESTION in dig; gated on +comments
    // alone — `dig +noall +comments` still prints the OPT section, verified
    // against dig 9.20). dig's trace default (comments off) suppresses it.
    if (flags.comments && ldns_pkt_edns(pkt)) {
        out += ";; OPT PSEUDOSECTION:\n";
        std::string edns_flags;
        if (ldns_pkt_edns_do(pkt)) {
            edns_flags = " do";
        }
        out += fmt::format("; EDNS: version: {}, flags:{}; udp: {}\n", ldns_pkt_edns_version(pkt), edns_flags,
                ldns_pkt_edns_udp_size(pkt));
        // Decode the EDNS options dig-style (`; CLIENT-SUBNET:`, `; NSID:`,
        // `; EDE:`), falling back to dig's generic `; \# N <hex>` for unknown
        // options. No trailing blank line here: dig runs the OPT lines straight
        // into the QUESTION/section header.
        ldns_rdf *data = ldns_pkt_edns_data(pkt);
        if (data != nullptr) {
            const uint8_t *bytes = ldns_rdf_data(data);
            size_t sz = ldns_rdf_size(data);
            size_t i = 0;
            while (i + 4 <= sz) {
                uint16_t code = static_cast<uint16_t>((bytes[i] << 8) | bytes[i + 1]);
                uint16_t opt_len = static_cast<uint16_t>((bytes[i + 2] << 8) | bytes[i + 3]);
                if (i + 4 + opt_len > sz) {
                    break; // malformed trailing option: stop decoding
                }
                out += format_edns_option_text(code, bytes + i + 4, opt_len);
                i += 4 + opt_len;
            }
        }
    }

    // `+onesoa`: print only the first SOA seen across the whole response (dig's
    // `+onesoa`, useful for `ANY`). Tracked across sections so a SOA in
    // AUTHORITY suppresses further SOAs in ADDITIONAL too.
    bool soa_emitted = false;

    // QUESTION / ANSWER / AUTHORITY / ADDITIONAL sections.
    auto print_section = [&](const char *title, const ldns_rr_list *list, bool is_question) {
        if (list == nullptr || ldns_rr_list_rr_count(list) == 0) {
            // dig suppresses empty-section output entirely (no header, no
            // following blank line) — including the `* SECTION:` titles even
            // when `+comments` is on.
            return;
        }
        // Section headers (and the trailing blank line that follows) are
        // `comments`. `dig +nocomments` / the trace-mode default emit just the
        // RRs concatenated; section toggles (`+answer` etc.) gate the RRs.
        if (flags.comments) {
            out += fmt::format(";; {} SECTION:\n", title);
        }
        for (size_t i = 0; i < ldns_rr_list_rr_count(list); ++i) {
            const ldns_rr *rr = ldns_rr_list_rr(list, i);
            // OPT is shown in OPT PSEUDOSECTION, not ADDITIONAL.
            if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_OPT) {
                continue;
            }
            // `+onesoa`: skip any SOA after the first.
            if (flags.one_soa && ldns_rr_get_type(rr) == LDNS_RR_TYPE_SOA) {
                if (soa_emitted) {
                    continue;
                }
                soa_emitted = true;
            }
            out += format_rr_dig(rr, flags, is_question);
        }
        if (flags.comments) {
            out += '\n';
        }
    };

    if (flags.question) {
        print_section("QUESTION", ldns_pkt_question(pkt), true);
    }
    if (flags.answer) {
        print_section("ANSWER", ldns_pkt_answer(pkt), false);
    }
    if (flags.authority) {
        print_section("AUTHORITY", ldns_pkt_authority(pkt), false);
    }
    if (flags.additional) {
        print_section("ADDITIONAL", ldns_pkt_additional(pkt), false);
    }

    // Stats trailer (query time, server, message size). dig's order is
    // Query time / SERVER / WHEN / MSG SIZE.
    if (flags.stats) {
        // A zero query_time (e.g. the `+qr` query echo, which has not been sent
        // yet) omits the line, matching the documented contract and `dig +qr`
        // (which prints only `;; MSG SIZE  sent:` for the query packet).
        if (query_time.count() != 0) {
            out += fmt::format(";; Query time: {} msec\n", query_time.count());
        }
        if (!server.empty()) {
            out += fmt::format(";; SERVER: {}\n", server);
        }
        std::string when_str = format_dig_when(when);
        if (!when_str.empty()) {
            out += fmt::format(";; WHEN: {}\n", when_str);
        }
        size_t sz = wire_pkt_size(pkt);
        // dig's +qr query echo prints `;; QUERY SIZE: N`; the response prints
        // `;; MSG SIZE  rcvd: N` (the double space in MSG SIZE  rcvd: is dig's
        // column alignment — `QUERY SIZE` and `MSG SIZE  rcvd: ` both line up
        // at the colon). Verified against `dig 9.20 +qr`.
        if (is_query) {
            out += fmt::format(";; QUERY SIZE: {}\n", sz);
            // dig's `+qr` separates the query echo's stats block from the
            // following `;; Got answer:` response block by a blank line
            // (verified against `dig +qr +noall +stats`). The blank line is
            // emitted here rather than in the caller so the format is
            // unit-testable and stays with the stats block it terminates.
            out += '\n';
        } else {
            out += fmt::format(";; MSG SIZE  rcvd: {}\n", sz);
        }
    }

    return out;
}

void apply_trace_display_defaults(DisplayFlags &flags) {
    // `dig +trace` clears `comments`, `question`, and `stats`. The other
    // section toggles are left at their default (on), so the per-hop body
    // becomes just the answer/authority/additional RRs without section
    // headers. The trace-specific "Received ... bytes from ..." footer is
    // emitted by `format_trace_packet_dig` in place of the standard stats
    // block. See `setup_trace` in dig's dighost.c (the order-sensitive
    // semantics mirror dig exactly: a `+comments` *after* `+trace` still
    // re-enables comments).
    flags.comments = false;
    flags.question = false;
    flags.stats = false;
    // These stay on (dig prints ANSWER/AUTHORITY/ADDITIONAL RRs in trace):
    flags.cmd = true;
    flags.answer = true;
    flags.authority = true;
    flags.additional = true;
    // Multiline / ttlid / cls are untouched (their defaults apply).
}

std::string format_trace_received_line(
        Millis query_time, size_t bytes, std::string_view server_ip, std::string_view server_name) {
    // Mirrors dig's ";; Received <n> bytes from <IP>#53(<NAME>) in <ms> ms".
    // When the peer has no resolvable name dig repeats the IP inside parens.
    std::string name(server_name);
    if (name.empty()) {
        name = std::string(server_ip);
    }
    if (server_ip.empty()) {
        // Degenerate input (no server recorded); fall back to name only to
        // avoid producing a malformed `#53()` fragment.
        return fmt::format(";; Received {} bytes from {}#53 in {} ms\n", bytes, name, query_time.count());
    }
    return fmt::format(";; Received {} bytes from {}#53({}) in {} ms\n", bytes, server_ip, name, query_time.count());
}

std::string format_trace_packet_dig(const ldns_pkt *pkt, const DisplayFlags &flags, Millis query_time,
        std::string_view server_ip, std::string_view server_name, bool tcp) {
    if (pkt == nullptr) {
        return {};
    }
    // Build the per-hop body using `format_packet_dig` with the standard stats
    // block suppressed (we emit either the trace `Received` line or a
    // trace-flavored stats footer ourselves below). An empty `server` keeps
    // `format_packet_dig` from emitting its own `;; SERVER:` line.
    DisplayFlags body_flags = flags;
    body_flags.stats = false;
    std::string out = format_packet_dig(pkt, body_flags, false, Millis{0}, "");

    size_t sz = wire_pkt_size(pkt);
    if (flags.stats) {
        // User asked for stats: emit a dig-style stats footer using the
        // trace-mode `IP#53(name) (proto)` SERVER formatting. The transport
        // reflects the hop's actual transport (UDP by default, TCP under `+tcp`,
        // which rewrites each hop to `tcp://` in run_trace) rather than being
        // hardcoded to UDP.
        std::string name(server_name);
        if (name.empty()) {
            name = std::string(server_ip);
        }
        out += fmt::format(";; Query time: {} msec\n", query_time.count());
        out += fmt::format(";; SERVER: {}#53({}) ({})\n", server_ip, name, tcp ? "TCP" : "UDP");
        out += fmt::format(";; MSG SIZE  rcvd: {}\n", sz);
    } else {
        out += format_trace_received_line(query_time, sz, server_ip, server_name);
    }
    // Blank line separator between hops (dig prints one after each Received).
    out += '\n';
    return out;
}

} // namespace ag::adyg
