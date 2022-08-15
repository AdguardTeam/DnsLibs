#include <cstddef>
#include <cstdint>
#include <ldns/rbtree.h>

#include <ldns/dname.h>
#include <ldns/host2wire.h>
#include <ldns/rr.h>

#include "dns_truncate.h"

namespace ag::dns {

// `pos` is the "virtual" buffer position needed for compression
static size_t dname_size(const ldns_rdf *name, ldns_rbtree_t *compression, size_t pos) {
    size_t old_pos = pos;
    if (!compression) {
        pos += ldns_rdf_size(name);
    } else if (ldns_dname_label_count(name) == 0) {
        pos += 1; // Root label is a single zero
    } else if (ldns_rbtree_search(compression, name)) {
        pos += 2; // Two-byte pointer
    } else {
        // If pos could be valid pointer, write compression entry
        if (pos < 16384) {
            auto *node = LDNS_MALLOC(ldns_rbnode_t);
            node->key = ldns_rdf_clone(name); // Name might be a temporary created by `ldns_dname_left_chop`
            ldns_rbtree_insert(compression, node);
        }

        ldns_rdf *label = ldns_dname_label(name, 0);
        pos += ldns_rdf_size(label) - 1; // ldns_dname_label returns a zero-terminated byte string, don't want the zero
        ldns_rdf_deep_free(label);

        ldns_rdf *rest = ldns_dname_left_chop(name);
        pos += dname_size(rest, compression, pos);
        ldns_rdf_deep_free(rest);
    }
    return pos - old_pos;
}

static size_t rdf_size(const ldns_rdf *rdf, ldns_rbtree_t *compression, size_t pos) {
    if (compression && ldns_rdf_get_type(rdf) == LDNS_RDF_TYPE_DNAME) {
        return dname_size(rdf, compression, pos);
    }
    return ldns_rdf_size(rdf);
}

static size_t rr_size(const ldns_rr *rr, int section, ldns_rbtree_t *compression, size_t pos) {
    if (!rr) {
        return 0;
    }
    size_t old_pos = pos;
    if (ldns_rr_owner(rr)) {
        pos += dname_size(ldns_rr_owner(rr), compression, pos);
    }
    pos += 4; // TYPE+CLASS
    if (section != LDNS_SECTION_QUESTION) {
        pos += 6; // TTL+RDLENGTH
        // Disable compression if RR is not compressible (compression for OWNER is always enabled by design, probably)
        if (LDNS_RR_NO_COMPRESS == ldns_rr_descript(ldns_rr_get_type(rr))->_compress) {
            compression = nullptr;
        }
        for (size_t i = 0; i < ldns_rr_rd_count(rr); ++i) {
            pos += rdf_size(ldns_rr_rdf(rr, i), compression, pos);
        }
    }
    return pos - old_pos;
}

// Return number of RRs after truncation
static size_t truncate_loop(
        const ldns_rr_list *rrs, int section, ldns_rbtree_t *compression, size_t max_size, size_t &cur_size) {
    for (size_t i = 0; i < ldns_rr_list_rr_count(rrs); ++i) {
        const ldns_rr *rr = ldns_rr_list_rr(rrs, i);
        cur_size += rr_size(rr, section, compression, cur_size);
        if (cur_size > max_size) {
            cur_size = max_size; // Prevent any futher RRs being added
            return i; // Number of RRs, excluding the current one which overflowed
        }
        if (cur_size == max_size) {
            return i + 1; // Number of RRs
        }
    }
    return ldns_rr_list_rr_count(rrs);
}

bool ldns_pkt_truncate(ldns_pkt *pkt, uint16_t max_size) {
    if (max_size < 512) {
        max_size = 512;
    }

    size_t cur_size = 12; // Header

    // Reserve space for EDNS and TSIG
    if (ldns_pkt_edns(pkt)) {
        cur_size += 15; // Owner: 1 ("."), TYPE: 2, CLASS: 2, TTL: 4, RDLEN: 2, EDNS data: 4
    }
    if (ldns_rr *tsig = ldns_pkt_tsig(pkt)) {
        cur_size += rr_size(tsig, LDNS_SECTION_ADDITIONAL, nullptr, 0); // Assume TSIG is never compressed
    }

    ldns_rbtree_t *compression = ldns_rbtree_create((int (*)(const void *, const void *)) ldns_dname_compare);

    size_t qdcount = 0;
    if (ldns_rr_list *rrs = ldns_pkt_question(pkt); rrs && cur_size <= max_size) {
        qdcount = truncate_loop(rrs, LDNS_SECTION_QUESTION, compression, max_size, cur_size);
        while (qdcount != ldns_rr_list_rr_count(rrs)) {
            ldns_rr_free(ldns_rr_list_pop_rr(rrs));
        }
    }

    size_t ancount = 0;
    if (ldns_rr_list *rrs = ldns_pkt_answer(pkt); rrs && cur_size <= max_size) {
        ancount = truncate_loop(rrs, LDNS_SECTION_ANSWER, compression, max_size, cur_size);
        while (ancount != ldns_rr_list_rr_count(rrs)) {
            ldns_rr_free(ldns_rr_list_pop_rr(rrs));
        }
    }

    size_t nscount = 0;
    if (ldns_rr_list *rrs = ldns_pkt_authority(pkt); rrs && cur_size <= max_size) {
        nscount = truncate_loop(rrs, LDNS_SECTION_AUTHORITY, compression, max_size, cur_size);
        while (nscount != ldns_rr_list_rr_count(rrs)) {
            ldns_rr_free(ldns_rr_list_pop_rr(rrs));
        }
    }

    size_t arcount = 0;
    if (ldns_rr_list *rrs = ldns_pkt_additional(pkt); rrs && cur_size <= max_size) {
        arcount = truncate_loop(rrs, LDNS_SECTION_ADDITIONAL, compression, max_size, cur_size);
        while (arcount != ldns_rr_list_rr_count(rrs)) {
            ldns_rr_free(ldns_rr_list_pop_rr(rrs));
        }
    }

    // Free tree
    ldns_traverse_postorder(
            compression,
            [](ldns_rbnode_t *node, void *arg) {
                ldns_rdf_deep_free((ldns_rdf *) node->key);
                LDNS_FREE(node);
            },
            nullptr);
    ldns_rbtree_free(compression);

    bool truncated = (qdcount != ldns_pkt_qdcount(pkt)) || (ancount != ldns_pkt_ancount(pkt))
            || (nscount != ldns_pkt_nscount(pkt)) || (arcount != ldns_pkt_arcount(pkt));

    ldns_pkt_set_tc(pkt, ldns_pkt_tc(pkt) || truncated); // Keep existing truncated flag
    ldns_pkt_set_qdcount(pkt, qdcount);
    ldns_pkt_set_ancount(pkt, ancount);
    ldns_pkt_set_nscount(pkt, nscount);
    ldns_pkt_set_arcount(pkt, arcount);

    return truncated;
}

} // namespace ag::dns
