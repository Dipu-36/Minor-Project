// At top of crypto.c (adjust include paths as needed)
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "ed25519_ref/ge.h"
#include "ed25519_ref/sc.h"
#include "ed25519_ref/fe.h"
#include "ed25519_ref/ed25519.h" // if you have wrapper header
#include "rand_bridge.h" // declares randombytes() / randombytes_impl

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#define EXPORT EMSCRIPTEN_KEEPALIVE
#else
#define EXPORT
#endif

// Small state store for ephemeral login states
#define MAX_STATES 1024
typedef struct {
  unsigned char x[32]; // client scalar (derived from password)
  unsigned char r[32]; // ephemeral random scalar
  int used;
} zkp_state;

static zkp_state *state_table = NULL;

static void ensure_state_table() {
  if (!state_table) {
    state_table = (zkp_state*)calloc(MAX_STATES, sizeof(zkp_state));
  }
}

// Helper: allocate a new state slot, returns index or -1
static int alloc_state() {
  ensure_state_table();
  for (int i = 0; i < MAX_STATES; ++i) {
    if (!state_table[i].used) {
      state_table[i].used = 1;
      memset(state_table[i].x, 0, 32);
      memset(state_table[i].r, 0, 32);
      return i;
    }
  }
  return -1;
}

// Free a state slot
EXPORT
void free_state(int state_id) {
  ensure_state_table();
  if (state_id >= 0 && state_id < MAX_STATES) {
    volatile unsigned char *p = state_table[state_id].x;
    for (int i = 0; i < 32; ++i) p[i] = 0;
    p = state_table[state_id].r;
    for (int i = 0; i < 32; ++i) p[i] = 0;
    state_table[state_id].used = 0;
  }
}

// compute_v_from_scalar: v = g^x (x is 32-byte scalar input)
// signature: int compute_v_from_scalar(uint8_t *scalar_ptr, int scalar_len, uint8_t *out_ptr, int out_len)
EXPORT
int compute_v_from_scalar(uint8_t *scalar_ptr, int scalar_len, uint8_t *out_ptr, int out_len) {
  if (!scalar_ptr || scalar_len < 32 || !out_ptr) return -1;
  unsigned char v[32];
  ge_p3 A;
  // Compute A = g^x
  ge_scalarmult_base(&A, scalar_ptr); // uses ref10
  ge_p3_tobytes(v, &A); // serialize compressed point (32 bytes)
  if (out_len < 32) return -1;
  memcpy(out_ptr, v, 32);
  return 32;
}

// initiate_login_from_scalar: store x, generate r, compute t = g^r, return t (raw bytes) and state id via state_ptr
// signature: int initiate_login_from_scalar(uint8_t *scalar_ptr, int scalar_len, uint8_t *out_ptr, int out_len, uint32_t *state_ptr)
EXPORT
int initiate_login_from_scalar(uint8_t *scalar_ptr, int scalar_len, uint8_t *out_ptr, int out_len, uint32_t *state_ptr) {
  if (!scalar_ptr || scalar_len < 32 || !out_ptr || !state_ptr) return -1;
  ensure_state_table();
  int sid = alloc_state();
  if (sid < 0) return -1;

  // store x
  memcpy(state_table[sid].x, scalar_ptr, 32);

  // generate r with secure random
  randombytes(state_table[sid].r, 32);

  // compute t = g^r
  ge_p3 T;
  ge_scalarmult_base(&T, state_table[sid].r);
  unsigned char t_bytes[32];
  ge_p3_tobytes(t_bytes, &T);

  if (out_len < 32) {
    // cleanup state
    free_state(sid);
    return -1;
  }

  memcpy(out_ptr, t_bytes, 32);

  // write state id (32-bit) into state_ptr (JS expects little-endian)
  *state_ptr = (uint32_t)sid;

  return 32;
}

// compute_response_from_state: compute s = r + c*x  (mod L)
// signature: int compute_response_from_state(int state_id, uint8_t *c_ptr, int c_len, uint8_t *out_ptr, int out_len)
EXPORT
int compute_response_from_state(int state_id, uint8_t *c_ptr, int c_len, uint8_t *out_ptr, int out_len) {
  if (!c_ptr || c_len < 32 || !out_ptr) return -1;
  ensure_state_table();
  if (state_id < 0 || state_id >= MAX_STATES || !state_table[state_id].used) return -1;

  unsigned char s[32];
  // sc_muladd(s, c, x, r) computes s = c*x + r  (sc_muladd API from ref10)
  sc_muladd(s, c_ptr, state_table[state_id].x, state_table[state_id].r);

  if (out_len < 32) return -1;
  memcpy(out_ptr, s, 32);

  // wipe and free state to avoid reuse
  free_state(state_id);

  return 32;
}
