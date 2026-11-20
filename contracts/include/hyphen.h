#ifndef HYPHEN_WASM_ABI_H
#define HYPHEN_WASM_ABI_H

#include <stdint.h>

#define HYPHEN_IMPORT(name) __attribute__((import_module("env"), import_name(#name)))
#define HYPHEN_EXPORT(name) __attribute__((export_name(#name)))
#define HYPHEN_MAX_VALUE_BYTES 65536u

/* h_storage_read requires space for HYPHEN_MAX_VALUE_BYTES at destination. */
HYPHEN_IMPORT(h_storage_read) int32_t h_storage_read(const void *key, uint32_t key_len, void *destination);
HYPHEN_IMPORT(h_storage_write) int32_t h_storage_write(const void *key, uint32_t key_len, const void *value, uint32_t value_len);
HYPHEN_IMPORT(h_storage_delete) int32_t h_storage_delete(const void *key, uint32_t key_len);
HYPHEN_IMPORT(h_blake3) int32_t h_blake3(const void *input, uint32_t len, uint8_t digest[32]);
HYPHEN_IMPORT(h_log) int32_t h_log(const void *data, uint32_t len);
HYPHEN_IMPORT(h_set_return) int32_t h_set_return(const void *data, uint32_t len);
HYPHEN_IMPORT(h_caller) int32_t h_caller(uint8_t caller[32]);
HYPHEN_IMPORT(h_self_address) int32_t h_self_address(uint8_t address[32]);
HYPHEN_IMPORT(h_gas_remaining) uint64_t h_gas_remaining(void);
HYPHEN_IMPORT(h_input_len) uint32_t h_input_len(void);
HYPHEN_IMPORT(h_input_copy) int32_t h_input_copy(void *destination);

#endif
