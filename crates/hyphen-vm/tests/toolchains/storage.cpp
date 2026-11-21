#include "hyphen.h"

namespace {
constexpr char key[] = "key";
uint8_t value[HYPHEN_MAX_VALUE_BYTES];

template <unsigned N>
void store_input(const char (&name)[N]) {
    const auto size = h_input_len();
    if (size > sizeof(value) || h_input_copy(value) != static_cast<int32_t>(size) ||
        h_storage_write(name, N - 1, value, size) != 0) {
        __builtin_trap();
    }
}
}

extern "C" HYPHEN_EXPORT(hyphen_execute) void hyphen_execute() {
    store_input(key);
}

extern "C" HYPHEN_EXPORT(hyphen_query) void hyphen_query() {
    const auto size = h_storage_read(key, sizeof(key) - 1, value);
    if (size < 0 || h_set_return(value, static_cast<uint32_t>(size)) != 0) {
        __builtin_trap();
    }
}
