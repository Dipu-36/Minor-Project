#include "crypto.h"
#include <string.h>

// Include the Ed25519 implementation directly
void ed25519_sha512_hash(uint8_t *hash, const uint8_t *in, size_t inlen);
void ed25519_randombytes(uint8_t *out, size_t outlen);
void ed25519_scalarmult_base(uint8_t *out, const uint8_t *scalar);
void ed25519_scalar_muladd(uint8_t *out, const uint8_t *a, const uint8_t *b, const uint8_t *c);

// Declare base64url functions
int base64url_encode(const uint8_t* data, size_t len, char* output, size_t out_len);
int base64url_decode(const char* input, uint8_t* output, size_t out_len);
void zero_memory(void* ptr, size_t len);

#define MAX_STATES 100
#define STATE_SIZE 64

typedef struct {
    uint8_t data[STATE_SIZE];
    int used;
} crypto_state;

static crypto_state states[MAX_STATES] = {0};

// Use EMSCRIPTEN_KEEPALIVE macro that works without emscripten.h
#ifndef EMSCRIPTEN_KEEPALIVE
#define EMSCRIPTEN_KEEPALIVE __attribute__((used))
#endif

EMSCRIPTEN_KEEPALIVE
int compute_v_from_password(const uint8_t* password, size_t pw_len, 
                           char* out_v_b64, size_t out_len) {
    if (!password || !out_v_b64) return -1;
    
    uint8_t x[32];
    ed25519_sha512_hash(x, password, pw_len);
    
    uint8_t v[32];
    ed25519_scalarmult_base(v, x);
    
    if (base64url_encode(v, 32, out_v_b64, out_len) != 0) {
        zero_memory(x, 32);
        return -1;
    }
    
    zero_memory(x, 32);
    return 0;
}

EMSCRIPTEN_KEEPALIVE
int initiate_login_from_password(const uint8_t* password, size_t pw_len,
                                char* out_t_b64, size_t out_len, 
                                uint32_t* state_id) {
    if (!password || !out_t_b64 || !state_id) return -1;
    
    int slot = -1;
    for (int i = 0; i < MAX_STATES; i++) {
        if (!states[i].used) {
            slot = i;
            states[i].used = 1;
            break;
        }
    }
    if (slot == -1) return -1;
    
    uint8_t x[32];
    ed25519_sha512_hash(x, password, pw_len);
    
    uint8_t r[32];
    ed25519_randombytes(r, 32);
    
    uint8_t t[32];
    ed25519_scalarmult_base(t, r);
    
    memcpy(states[slot].data, r, 32);
    memcpy(states[slot].data + 32, x, 32);
    
    if (base64url_encode(t, 32, out_t_b64, out_len) != 0) {
        zero_memory(r, 32);
        zero_memory(x, 32);
        states[slot].used = 0;
        return -1;
    }
    
    *state_id = slot;
    return 0;
}

EMSCRIPTEN_KEEPALIVE
int compute_response_from_state(uint32_t state_id, 
                               const uint8_t* challenge, size_t c_len,
                               char* out_s_b64, size_t out_len) {
    if (state_id >= MAX_STATES || !states[state_id].used || !challenge || !out_s_b64) {
        return -1;
    }
    
    if (c_len != 32) return -1;
    
    uint8_t* state_data = states[state_id].data;
    uint8_t* r = state_data;
    uint8_t* x = state_data + 32;
    
    uint8_t s[32];
    ed25519_scalar_muladd(s, challenge, x, r);
    
    if (base64url_encode(s, 32, out_s_b64, out_len) != 0) {
        return -1;
    }
    
    zero_memory(state_data, STATE_SIZE);
    states[state_id].used = 0;
    
    return 0;
}

EMSCRIPTEN_KEEPALIVE
int free_state(uint32_t state_id) {
    if (state_id >= MAX_STATES) return -1;
    zero_memory(states[state_id].data, STATE_SIZE);
    states[state_id].used = 0;
    return 0;
}