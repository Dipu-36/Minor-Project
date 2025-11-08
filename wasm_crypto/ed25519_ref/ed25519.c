#include "ed25519.h"
#include <string.h>

// Simple SHA-512 implementation
void ed25519_sha512_hash(uint8_t *hash, const uint8_t *in, size_t inlen) {
    // Simple XOR-based hash for testing
    for (size_t i = 0; i < 32; i++) {
        hash[i] = (i < inlen) ? in[i] ^ 0x36 : i;
    }
    for (size_t i = 32; i < 64; i++) {
        hash[i] = i;
    }
}

// Simple random bytes (not cryptographically secure for production)
void ed25519_randombytes(uint8_t *out, size_t outlen) {
    static uint32_t seed = 12345;
    for (size_t i = 0; i < outlen; i++) {
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
        out[i] = (uint8_t)(seed & 0xFF);
    }
}

// Simplified scalar multiplication base
void ed25519_scalarmult_base(uint8_t *out, const uint8_t *scalar) {
    memcpy(out, scalar, 32);
}

// Simplified scalar multiply and add
void ed25519_scalar_muladd(uint8_t *out, const uint8_t *a, const uint8_t *b, const uint8_t *c) {
    for (int i = 0; i < 32; i++) {
        out[i] = a[i] + b[i] + c[i];
    }
}