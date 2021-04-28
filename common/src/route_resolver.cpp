#include <ag_route_resolver.h>

#if defined(__APPLE__) && defined(__MACH__)

#include <array>
#include <vector>
#include <algorithm>

#include <ag_defs.h>
#include <ag_utils.h>
#include <ag_logger.h>
#include <ag_net_utils.h>

#include <sys/sysctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

#include <TargetConditionals.h>

#if TARGET_OS_IPHONE
#define RTF_UP          0x1             /* route usable */
#define RTF_STATIC      0x800           /* manually added */
#define RTF_WASCLONED   0x20000         /* route generated through cloning */
#define RTF_IFSCOPE     0x1000000       /* has valid interface scope */

#define RTAX_DST        0       /* destination sockaddr present */
#define RTAX_NETMASK    2       /* netmask sockaddr present */
#define RTAX_MAX        8       /* size of array to allocate */

struct rt_metrics {
    u_int32_t       rmx_locks;      /* Kernel leaves these values alone */
    u_int32_t       rmx_mtu;        /* MTU for this path */
    u_int32_t       rmx_hopcount;   /* max hops expected */
    int32_t         rmx_expire;     /* lifetime for route, e.g. redirect */
    u_int32_t       rmx_recvpipe;   /* inbound delay-bandwidth product */
    u_int32_t       rmx_sendpipe;   /* outbound delay-bandwidth product */
    u_int32_t       rmx_ssthresh;   /* outbound gateway buffer limit */
    u_int32_t       rmx_rtt;        /* estimated round trip time */
    u_int32_t       rmx_rttvar;     /* estimated rtt variance */
    u_int32_t       rmx_pksent;     /* packets sent using this route */
    u_int32_t       rmx_state;      /* route state */
    u_int32_t       rmx_filler[3];  /* will be used for TCP's peer-MSS cache */
};

struct rt_msghdr2 {
	u_short rtm_msglen;     /* to skip over non-understood messages */
	u_char  rtm_version;    /* future binary compatibility */
	u_char  rtm_type;       /* message type */
	u_short rtm_index;      /* index for associated ifp */
	int     rtm_flags;      /* flags, incl. kern & message, e.g. DONE */
	int     rtm_addrs;      /* bitmask identifying sockaddrs in msg */
	int32_t rtm_refcnt;     /* reference count */
	int     rtm_parentflags; /* flags of the parent route */
	int     rtm_reserved;   /* reserved field set to 0 */
	int     rtm_use;        /* from rtentry */
	u_int32_t rtm_inits;    /* which metrics we are initializing */
	struct rt_metrics rtm_rmx; /* metrics themselves */
};
#else
#include <net/route.h>
#endif

// Routing socket alignment requirements
#define ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

static ag::err_string dump_routing_table(std::vector<uint8_t> &rt) {
    static constexpr int MAX_TRIES = 10;
    int n_try;
    for (n_try = 0; n_try < MAX_TRIES; ++n_try) {
        int name[] = {CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP2, 0};
        size_t out_size;
        if (sysctl(name, 6, nullptr, &out_size, nullptr, 0) < 0) {
            return AG_FMT("sysctl (estimate): {}, {}", errno, strerror(errno));
        }
        assert(out_size < SIZE_MAX / 2);
        out_size *= 2;
        rt.resize(out_size);
        if (sysctl(name, 6, rt.data(), &out_size, nullptr, 0) < 0) {
            if (errno == ENOMEM) {
                continue;
            }
            return AG_FMT("sysctl (dump): {}, {}", errno, strerror(errno));
        }
        rt.resize(out_size);
        return std::nullopt;
    }
    return AG_FMT("failed to allocate enough memory after {} tries", n_try);
}

class apple_route_resolver : public ag::route_resolver {
public:
    apple_route_resolver() {
        std::vector<uint8_t> rt;
        ag::err_string error = dump_routing_table(rt);
        if (error) {
            warnlog(log, "Failed to dump routing table: {}", *error);
            return; // Tables stay empty, so we won't route anything
        }

        for (uint8_t *next = rt.data(); next < (&rt.back() + 1);) {
            auto *rtm = (rt_msghdr2 *) next;
            next += rtm->rtm_msglen;

            // We are interested in usable, static routes that were not cloned
            // (BSD puts various stuff like ARP cache into the routing table)
            // We also skip routes with RTF_IFSCOPE flag set because we are
            // trying to reproduce the default routing behaviour,
            // (e.g. what the user would get if they ran `route get n.n.n.n`)
            // and Apple OSes will NOT use these routes by default:
            // https://superuser.com/questions/441075/what-traffic-uses-an-interface-bound-route-rtf-ifscope-flag
            if (!(rtm->rtm_flags & RTF_UP)
                || !(rtm->rtm_flags & RTF_STATIC)
                || rtm->rtm_flags & RTF_WASCLONED
                || rtm->rtm_flags & RTF_IFSCOPE) {
                continue;
            }

            auto *sa_iter = (sockaddr *) (rtm + 1);
            if (sa_iter->sa_family != AF_INET && sa_iter->sa_family != AF_INET6) {
                continue;
            }

            sockaddr *rta[RTAX_MAX];
            for (int i = 0; i < RTAX_MAX; i++) {
                if (rtm->rtm_addrs & (1 << i)) {
                    rta[i] = sa_iter;
                    sa_iter = (sockaddr *) (ROUNDUP(sa_iter->sa_len) + (char *) sa_iter);
                } else {
                    rta[i] = nullptr;
                }
            }

            sockaddr *dst = rta[RTAX_DST];
            if (!dst) {
                continue;
            }

            ip_route &route = (dst->sa_family == AF_INET ? &ipv4_table : &ipv6_table)->emplace_back();
            route.if_index = rtm->rtm_index;

            // NOTE: netmask is in internal kernel format, not a usual sockaddr
            sockaddr *netmask = rta[RTAX_NETMASK];
            switch (dst->sa_family) {
            case AF_INET: {
                auto *addr = (uint8_t *) &((sockaddr_in *) dst)->sin_addr.s_addr;
                std::memcpy(&route.address[0], addr, 4);
                if (!netmask) { // Host route
                    std::memset(&route.netmask[0], 0xff, 4);
                    break;
                }
                if (netmask->sa_len <= offsetof(sockaddr_in, sin_addr)) { // Default route
                    break;
                }
                auto *mask = (uint8_t *) &((sockaddr_in *) netmask)->sin_addr.s_addr;
                std::memcpy(&route.netmask[0], mask, netmask->sa_len - offsetof(sockaddr_in, sin_addr));
                break;
            }
            case AF_INET6: {
                auto *addr = &((sockaddr_in6 *) dst)->sin6_addr;
                std::memcpy(&route.address[0], addr, 16);
                if (!netmask) { // Host route
                    std::memset(&route.netmask[0], 0xff, 16);
                    break;
                }
                if (netmask->sa_len <= offsetof(sockaddr_in6, sin6_addr)) { // Default route
                    break;
                }
                auto *mask = &((sockaddr_in6 *) netmask)->sin6_addr;
                std::memcpy(&route.netmask[0], mask, netmask->sa_len - offsetof(sockaddr_in6, sin6_addr));
                break;
            }
            default:
                assert(0);
                break;
            }
        }

        std::sort(ipv4_table.begin(), ipv4_table.end());
        std::sort(ipv6_table.begin(), ipv6_table.end());

        if (log->should_log(spdlog::level::debug)) {
            for (auto *table : {&ipv4_table, &ipv6_table}) {
                bool ipv4 = table == &ipv4_table;
                dbglog(log, "{}", ipv4 ? "IPv4 table:" : "IPv6 table:");
                for (auto &route : *table) {
                    auto addr = ag::utils::addr_to_str({route.address.data(), (size_t) (ipv4 ? 4 : 16)});
                    uint32_t prefix_len = 0;
                    for (uint8_t b : route.netmask) {
                        prefix_len += __builtin_popcount(b);
                    }
                    char buf[IF_NAMESIZE];
                    dbglog(log, "{}/{} -> {}", addr, prefix_len, if_indextoname(route.if_index, buf));
                }
            }
        }
    }

    std::optional<uint32_t> resolve(const ag::socket_address &address) const override {
        auto *table = address.is_ipv4() ? &ipv4_table : &ipv6_table;
        for (auto &route : *table) {
            if (route.matches(address.addr_unmapped())) {
                return route.if_index;
            }
        }
        return std::nullopt;
    }

private:
    static constexpr size_t MAX_ADDR_LEN = 16;
    struct ip_route {
        std::array<uint8_t, MAX_ADDR_LEN> address{};
        std::array<uint8_t, MAX_ADDR_LEN> netmask{};
        uint32_t if_index{0};

        bool matches(ag::uint8_view dest) const {
            for (size_t i = 0; i < dest.size() && i < MAX_ADDR_LEN && netmask[i] != 0; ++i) {
                if ((dest[i] & netmask[i]) != address[i]) {
                    return false;
                }
            }
            return true;
        }

        // More specific is less
        bool operator<(const ip_route &o) const {
            // Masks are contiguous, lexicographically larger mask is more specific
            return netmask > o.netmask;
        }
    };

    ag::logger log{ag::create_logger("route_resolver")};

    std::vector<ip_route> ipv4_table;
    std::vector<ip_route> ipv6_table;
};

std::shared_ptr<ag::route_resolver> ag::route_resolver::create() {
    return std::make_shared<apple_route_resolver>();
}

#else // defined(__APPLE__) && defined(__MACH__)

class noop_route_resolver : public ag::route_resolver {
public:
    std::optional<uint32_t> resolve(const ag::socket_address &) const override {
        return std::nullopt;
    }
};

std::shared_ptr<ag::route_resolver> ag::route_resolver::create() {
    return std::make_shared<noop_route_resolver>();
}

#endif // defined(__APPLE__) && defined(__MACH__)
