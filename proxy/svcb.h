#pragma once

#include <ldns/ldns.h>

#include "common/defs.h"
#include "dns/common/dns_defs.h"
#include "dns/common/net_consts.h"

namespace ag::dns {

class SvcbHttpsHelpers {
public:
    /**
     * Remove the "ech" parameter from SVCB/HTTPS records in `response`.
     * @return `true` if any "ech" was removed, false otherwise
     */
    static bool remove_ech_svcparam(ldns_pkt *response) {
        RemoveEchAction action;
        process_rr(response, &action);
        return action.wasRemoved();
    }

    /**
     * Retrieve IP hints (IPv4/IPv6) from DNS response.
     * @return Vector of IP hints as strings.
     */
    static std::vector<std::string> get_ip_hints_from_response(ldns_pkt *response) {
        GetIpHintsAction action;
        process_rr(response, &action);
        return action.getHints();
    }

    /**
     * Apply custom IPv4 and IPv6 addresses to SVCB/HTTPS records in `response` according to `settings`.
     * @return Modified response with applied changes.
     */
    static ldns_pkt_ptr modify_response(const ldns_pkt *response, const std::vector<const char *> &ips) {
        ldns_pkt_ptr clone{ldns_pkt_clone(response)};
        GetCustomResponseAction action(ips);
        process_rr(clone.get(), &action);
        return clone;
    }

private:
    struct ProcessingContext {
        ldns_rr *rr;
        ldns_rdf *params;
        uint8_t *param_start;
        ag::Uint8View params_tail;
        uint16_t key;
        uint16_t len;
    };

    /**
     * Represents a interface for processing SVCB/HTTPS records.
     */
    class SvcbHttpsAction {
    public:
        virtual void beforeProcessing(ProcessingContext &context){};
        virtual void duringProcessing(ProcessingContext &context) = 0;
        virtual void afterProcessing(ProcessingContext &context){};
    };

    class RemoveEchAction : public SvcbHttpsAction {
    public:
        void duringProcessing(ProcessingContext &context) override {
            if (context.key == LDNS_SVCPARAM_KEY_ECHCONFIG) {
                removed = true;
                std::memmove(context.param_start, context.params_tail.data(), context.params_tail.size());
                ldns_rdf_set_size(context.params,
                        ldns_rdf_size(context.params) - sizeof(context.key) - sizeof(context.len) - context.len);
            }
        }
        bool wasRemoved() const {
            return removed;
        }

    private:
        bool removed = false;
    };

    class GetIpHintsAction : public SvcbHttpsAction {
    public:
        void duringProcessing(ProcessingContext &context) override {
            if (context.key == LDNS_SVCPARAM_KEY_IPV4HINT || context.key == LDNS_SVCPARAM_KEY_IPV6HINT) {
                parse_ip_addr_from_raw_data(hints, context);
            }
        }
        std::vector<std::string> getHints() const {
            return hints;
        }

    private:
        std::vector<std::string> hints;
    };

    class GetCustomResponseAction : public SvcbHttpsAction {
    public:
        explicit GetCustomResponseAction(const std::vector<const char *> &ips)
                : ips(ips)
                , buffer(nullptr) {
        }
        void beforeProcessing(ProcessingContext &context) override {
            buffer.reset(ldns_buffer_new(ldns_rdf_size(context.params)));
        }
        void duringProcessing(ProcessingContext &context) override {
            if (context.key == LDNS_SVCPARAM_KEY_IPV4HINT) {
                insert_custom_ip_hint_to_buffer(buffer.get(), LDNS_SVCPARAM_KEY_IPV4HINT, ips);
            } else if (context.key == LDNS_SVCPARAM_KEY_IPV6HINT) {
                insert_custom_ip_hint_to_buffer(buffer.get(), LDNS_SVCPARAM_KEY_IPV6HINT, ips);
            } else {
                insert_data_to_buffer(context, buffer.get());
            }
        }
        void afterProcessing(ProcessingContext &context) override {
            ldns_rdf *new_rdf = ldns_rdf_new_frm_data(
                    LDNS_RDF_TYPE_SVCPARAMS, ldns_buffer_position(buffer.get()), ldns_buffer_begin(buffer.get()));
            ldns_rdf_deep_free(ldns_rr_pop_rdf(context.rr));
            ldns_rr_push_rdf(context.rr, new_rdf);
        }

    private:
        const std::vector<const char *> &ips;
        ldns_buffer_ptr buffer;
    };

    /**
     * Perform generic processing of SVCB/HTTPS records in `response` using `SvcbHttpsAction`.
     */
    static void process_rr(ldns_pkt *response, SvcbHttpsAction *action) {
        for (int i = 0; i < ldns_pkt_ancount(response); i++) {
            ldns_rr *rr = ldns_rr_list_rr(ldns_pkt_answer(response), i);

            if (auto type = ldns_rr_get_type(rr);
                    (type != LDNS_RR_TYPE_HTTPS && type != LDNS_RR_TYPE_SVCB) || ldns_rr_rd_count(rr) != 3) {
                continue;
            }

            ldns_rdf *params = ldns_rr_rdf(rr, 2);

            if (ldns_rdf_get_type(params) != LDNS_RDF_TYPE_SVCPARAMS) {
                continue;
            }

            ProcessingContext ctx = {rr, params, nullptr, {ldns_rdf_data(params), ldns_rdf_size(params)}, 0, 0};
            process_rdf(ctx, action);
        }
    }

    static void process_rdf(ProcessingContext &ctx, SvcbHttpsAction *action) {
        action->beforeProcessing(ctx);

        while (ctx.params_tail.size() >= sizeof(ctx.key)) {
            ctx.param_start = (uint8_t *) ctx.params_tail.data();

            std::memcpy(&ctx.key, ctx.params_tail.data(), sizeof(ctx.key));
            ctx.params_tail.remove_prefix(sizeof(ctx.key));

            if (ctx.params_tail.size() < sizeof(ctx.len)) {
                break;
            }

            std::memcpy(&ctx.len, ctx.params_tail.data(), sizeof(ctx.len));
            ctx.params_tail.remove_prefix(sizeof(ctx.len));

            ctx.key = ntohs(ctx.key);
            ctx.len = ntohs(ctx.len);

            if (ctx.params_tail.size() < ctx.len) {
                break;
            }
            ctx.params_tail.remove_prefix(ctx.len);

            action->duringProcessing(ctx);
        }

        action->afterProcessing(ctx);
    }

    static void insert_data_to_buffer(ProcessingContext &context, ldns_buffer *buffer) {
        ldns_buffer_write(buffer, context.param_start, context.len + sizeof(context.key) + sizeof(context.key));
    }

    static void insert_custom_ip_hint_to_buffer(ldns_buffer *buffer, ldns_enum_svcparam_key key, std::vector<const char *> ips) {
        size_t key_pos = ldns_buffer_position(buffer);
        ldns_buffer_write_u16(buffer, key);
        size_t len_pos = ldns_buffer_position(buffer);
        uint16_t len = 0;
        ldns_buffer_write_u16(buffer, len);
        for (auto *ip : ips) {
            auto custom_ip = utils::str_to_socket_address(ip);
            uint16_t addr_size = custom_ip.addr().size();
            if ((key == LDNS_SVCPARAM_KEY_IPV4HINT && addr_size == IPV4_ADDRESS_SIZE)
                    || (key == LDNS_SVCPARAM_KEY_IPV6HINT && addr_size == IPV6_ADDRESS_SIZE)) {
                ldns_buffer_write(buffer, custom_ip.addr().data(), addr_size);
                len += addr_size;
            }
        }
        if (len > 0) {
            ldns_buffer_write_u16_at(buffer, len_pos, len);
        } else {
            ldns_buffer_set_position(buffer, key_pos);
        }
    }

    static void parse_ip_addr_from_raw_data(std::vector<std::string> &result, const ProcessingContext &context) {
        auto addr_size = context.key == LDNS_SVCPARAM_KEY_IPV4HINT ? IPV4_ADDRESS_SIZE : IPV6_ADDRESS_SIZE;
        auto *data_start = context.param_start + sizeof(context.key) + sizeof(context.len);
        for (size_t i = 0; i < context.len; i += addr_size) {
            result.emplace_back(utils::addr_to_str({data_start + i, addr_size}));
        }
    }
};

} // namespace ag::dns
