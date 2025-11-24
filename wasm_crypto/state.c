// --- in wasm_crypto/state.c: replace old functions with these ----
#include "crypto.h"   // ensure zkp_ret_t and prototypes available
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/*
* Match the prototype in crypto.h:
* zkp_ret_t base64url_encode(const uint8_t *input, size_t in_len, char *output, size_t out_size, int pad);
*/
zkp_ret_t base64url_encode(const uint8_t *input, size_t in_len, char *output, size_t out_size, int pad) {
    // Simple, robust base64url encoder using a local non-allocating approach.
    // This implementation is compact and returns non-zero on error.
    static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t i = 0, o = 0;
    uint32_t acc = 0;
    int bits = 0;

    // worst-case output length for base64 without padding = ceil(in_len*8/6)
    size_t needed = (in_len * 8 + 5) / 6;
    if (out_size < needed + 1) return -1; // insufficient output buffer

    while (i < in_len) {
        acc = (acc << 8) | input[i++];
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            uint8_t idx = (acc >> bits) & 0x3F;
            output[o++] = b64[idx];
        }
    }
    if (bits > 0) {
        // flush remaining bits (pad with zeros on the right)
        uint8_t idx = (acc << (6 - bits)) & 0x3F;
        output[o++] = b64[idx];
    }

    if (pad) {
        // compute standard base64 padding to multiple of 4 characters (if requested)
        while (o % 4 != 0) {
            if (o + 1 >= out_size) return -1;
            output[o++] = '=';
        }
    }

    if (o >= out_size) return -1;
    output[o] = '\0';
    return 0;
}

/*
* Match prototype in crypto.h:
* zkp_ret_t zero_memory(void *buf, size_t len);
*/
zkp_ret_t zero_memory(void *buf, size_t len) {
    if (!buf) return -1;
    volatile unsigned char *p = (volatile unsigned char *)buf;
    while (len--) *p++ = 0;
    return 0;
}
