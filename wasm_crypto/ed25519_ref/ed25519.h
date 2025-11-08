#ifndef ED25519_H
#define ED25519_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Function declarations - we'll provide simple implementations
void ed25519_sha512_hash(uint8_t *hash, const uint8_t *in, size_t inlen);
void ed25519_randombytes(uint8_t *out, size_t outlen);
void ed25519_scalarmult_base(uint8_t *out, const uint8_t *scalar);
void ed25519_scalar_muladd(uint8_t *out, const uint8_t *a, const uint8_t *b, const uint8_t *c);

#ifdef __cplusplus
}
#endif

#endif