#pragma once

namespace ag {

// An ldns_buffer grows automatically.
// We set the initial capacity so that most requests will fit without reallocations.
constexpr size_t REQUEST_BUFFER_INITIAL_CAPACITY = 64;

// This is for incoming request packets.
// RFC 6891 6.2.5 recommends clients to assume that packets of up to 4096 bytes are supported.
// If the upstream supports less, it will say so in its response, which we forward to the requestor.
// If the upstream supports more, and the requestor decides to take advantage of that,
// it's out of luck with our proxy.
// We could specify LDNS_MAX_PACKETLEN here, but that would waste a lot of memory since most request
// packets are going to be small anyway
// (remember, this constant only affects incoming packets, we always send back as much as the upstream returned)
static constexpr size_t UDP_RECV_BUF_SIZE = 4096;

}
