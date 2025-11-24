// wasm_crypto/rand_bridge.c
#include "rand_bridge.h"
#include <stdint.h>
#include <stddef.h>

// On the C side we declare wasm_randombytes as an imported function implemented by JS.
// If building with Emscripten you can also use EM_IMPORT or EM_JS but keeping this
// declaration portable for raw WebAssembly instantiation is better.
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif

// Declare the function that will be provided by the host (JS). We define it as weak here
// so linker doesn't fail if you later build natively for tests (you can provide a native impl).
// For Emscripten this will be satisfied via the `env` import object.
#ifdef __cplusplus
extern "C" {
#endif
extern void wasm_randombytes(uint8_t *buf, size_t n);
#ifdef __cplusplus
}
#endif

// Provide the alias expected by many libs (`randombytes`).
void randombytes(unsigned char *buf, size_t n) {
    // delegate to wasm_randombytes
    wasm_randombytes((uint8_t*)buf, (size_t)n);
}
