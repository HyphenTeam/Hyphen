#include "hyphen.h"

static uint8_t value[HYPHEN_MAX_VALUE_BYTES];
static const char key[] = "key";

HYPHEN_EXPORT(hyphen_execute) void hyphen_execute(void) {
    uint32_t len = h_input_len();
    if (len > sizeof value || h_input_copy(value) != (int32_t)len ||
        h_storage_write(key, 3, value, len) != 0) {
        __builtin_trap();
    }
}

HYPHEN_EXPORT(hyphen_query) void hyphen_query(void) {
    int32_t len = h_storage_read(key, 3, value);
    if (len < 0 || h_set_return(value, (uint32_t)len) != 0) {
        __builtin_trap();
    }
}
