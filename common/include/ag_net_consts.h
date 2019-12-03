#pragma once

namespace ag {

// An ldns_buffer grows automatically.
// We set the initial capacity so that most requests will fit without reallocations.
constexpr size_t REQUEST_BUFFER_INITIAL_CAPACITY = 64;

}
