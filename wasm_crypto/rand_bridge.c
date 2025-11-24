// rand_bridge.c
#include "rand_bridge.h"
#include <stdio.h>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>

EM_JS(void, wasm_randombytes_impl, (uint8_t* buf, size_t n), {
  // create secure random bytes in JS and copy to wasm heap
  const arr = new Uint8Array(n);
  self.crypto.getRandomValues(arr);
  const heap = Module.HEAPU8.subarray(buf, buf + n);
  heap.set(arr);
});
#endif

void randombytes(unsigned char *buf, size_t n) {
#ifdef __EMSCRIPTEN__
    wasm_randombytes_impl(buf, n);
#else
    // native fallback: /dev/urandom
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(buf, 1, n, f);
        fclose(f);
    } else {
        // fallback - poor quality
        for (size_t i = 0; i < n; i++) buf[i] = (unsigned char)(rand() & 0xFF);
    }
#endif
}
