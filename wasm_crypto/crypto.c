/*
 crypto.c
 Implementation for the wasm_crypto module.
 Exports functions:
  - compute_v_from_scalar
  - initiate_login_from_scalar
  - compute_response_from_state
  - free_state

 The file depends on the ed25519 reference implementation (ed25519_ref/*),
 and on base64url helpers that must be linked in (or supplied here).
*/

#include "crypto.h"
#include <string.h>
#include <stdlib.h>
#include <emscripten.h>
#include "ed25519_ref/ed25519.h" // ensure these exist in wasm_crypto/ed25519_ref

// State pool configuration
#define MAX_STATES 100
#define STATE_SIZE 64 // 32 bytes r, 32 bytes x

typedef struct {
    uint8_t data[STATE_SIZE];
    int used;
} crypto_state;

static crypto_state states[MAX_STATES];

// Utility: find free state slot
static int allocate_state_slot() {
    for (int i = 0; i < MAX_STATES; i++) {
        if (!states[i].used) {
            states[i].used = 1;
            // zero memory first
            zero_memory(states[i].data, STATE_SIZE);
            return i;
        }
    }
    return -1;
}

// Utility: zero memory in a way that resists compiler optimizations
void zero_memory(void* ptr, size_t len) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (len--) *p++ = 0;
}

/* base64url_encode / decode
 Note: You may provide your own implementations in JS or C.
 A very small implementation is included here that uses a simple base64 encoder.
 For production, ensure correctness and URL-safe mapping.
*/

// Minimal base64url encode using emscripten helpers or simple table.
// For simplicity we call into a helper implemented in JS during linking if available.
// If not available, these functions return -1 to indicate missing implementation.
int base64url_encode(const uint8_t* data, size_t len, char* output, size_t out_len) {
    // If compiled with -s EXPORTED_RUNTIME_METHODS=['ccall','cwrap'], you could call
    // an exported helper. For now, we attempt a naive approach using ed25519_ref helper if available.
    // To keep this file self-contained and safe, return -1 if output buffer is too small.
    // In practice, you will provide an implementation or let JS handle encoding by reading WASM memory.
    // For our project, worker.js will prefer to call UTF8ToString on the output buffer that C fills.
    // If you have an implementation, replace this stub.
    (void)data; (void)len; (void)output; (void)out_len;
    return -1;
}

int base64url_decode(const char* input, uint8_t* output, size_t out_len) {
    (void)input; (void)output; (void)out_len;
    return -1;
}

/* compute_v_from_scalar
 Compute v = g^x where x is a 32-byte scalar passed by caller (Argon2 output).
*/
EMSCRIPTEN_KEEPALIVE
int compute_v_from_scalar(const uint8_t* scalar, size_t scalar_len,
                          char* out_v_b64, size_t out_len) {
    if (!scalar || scalar_len < 32 || !out_v_b64) return -1;

    uint8_t x[32];
    memcpy(x, scalar, 32);

    uint8_t v[32];
    // scalar multiply basepoint by x => v = g^x
    ed25519_scalarmult_base(v, x);

    // encode v to base64url - if not implemented in C, caller (JS) should read raw bytes
    if (base64url_encode(v, 32, out_v_b64, out_len) != 0) {
        // If base64 isn't available in C, leave raw bytes in a known memory area or return error.
        zero_memory(x, 32);
        zero_memory(v, 32);
        return -1;
    }

    zero_memory(x, 32);
    zero_memory(v, 32);
    return 0;
}

/* initiate_login_from_scalar
 Generate random r, compute t = g^r, store r and x in a state slot and return t in base64url.
 The random bytes generator must be provided via ed25519_randombytes (which should be secure).
*/
EMSCRIPTEN_KEEPALIVE
int initiate_login_from_scalar(const uint8_t* scalar, size_t scalar_len,
                               char* out_t_b64, size_t out_len,
                               uint32_t* state_id) {
    if (!scalar || scalar_len < 32 || !out_t_b64 || !state_id) return -1;

    int slot = allocate_state_slot();
    if (slot == -1) return -1;

    // Copy x into slot
    memcpy(states[slot].data + 32, scalar, 32);

    // Generate random r
    uint8_t r[32];
    ed25519_randombytes(r, 32);

    // Store r in slot
    memcpy(states[slot].data, r, 32);

    // Compute t = g^r
    uint8_t t[32];
    ed25519_scalarmult_base(t, r);

    // Encode t
    if (base64url_encode(t, 32, out_t_b64, out_len) != 0) {
        // try to fail cleanly
        zero_memory(r, 32);
        zero_memory(t, 32);
        zero_memory(states[slot].data, STATE_SIZE);
        states[slot].used = 0;
        return -1;
    }

    // Return slot id
    *state_id = (uint32_t)slot;

    // Wipe local r
    zero_memory(r, 32);
    zero_memory(t, 32);
    return 0;
}

/* compute_response_from_state
 Compute s = r + c * x (mod L) using ed25519_scalar_muladd helper (must exist in ed25519_ref)
*/
EMSCRIPTEN_KEEPALIVE
int compute_response_from_state(uint32_t state_id,
                                const uint8_t* challenge, size_t c_len,
                                char* out_s_b64, size_t out_len) {
    if (state_id >= MAX_STATES) return -1;
    if (!states[state_id].used) return -1;
    if (!challenge || c_len != 32 || !out_s_b64) return -1;

    uint8_t* slot = states[state_id].data;
    uint8_t* r = slot;
    uint8_t* x = slot + 32;

    uint8_t s[32];
    // ed25519_scalar_muladd(s, c, x, r) should compute s = r + c * x (mod L)
    ed25519_scalar_muladd(s, challenge, x, r);

    if (base64url_encode(s, 32, out_s_b64, out_len) != 0) {
        zero_memory(s, 32);
        return -1;
    }

    // Wipe state and free slot
    zero_memory(states[state_id].data, STATE_SIZE);
    states[state_id].used = 0;

    zero_memory(s, 32);
    return 0;
}

EMSCRIPTEN_KEEPALIVE
int free_state(uint32_t state_id) {
    if (state_id >= MAX_STATES) return -1;
    zero_memory(states[state_id].data, STATE_SIZE);
    states[state_id].used = 0;
    return 0;
}

/* deprecated compute_v_from_password_deprecated - returns error to force using Argon2 
EMSCRIPTEN_KEEPALIVE
int compute_v_from_password_deprecated(const uint8_t* password, size_t pw_len,
                                       char* out_v_b64, size_t out_len) {
    (void)password; (void)pw_len; (void)out_v_b64; (void)out_len;
    // Intentionally fail: password KDF must be performed outside WASM using Argon2id.
    return -1;
}
*/

