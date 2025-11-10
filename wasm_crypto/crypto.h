/*
crypto.h file is the header file declaring the API for the Schnnor-style ZERO KNOWLEDGE PROOF (ZKP) authentication 
built on Ed25519 primitives.

This header exposes the functions that perform cryptographic operations required for passwordless Schnnor ZKP authentication.

Algorithms used are :-
1. Ed25519 elliptic curve for scalar and point operations
2. SHA-512 for hashing the password into a scalar (currently placeholder - should be replaced with Argon2id)
3. Base64URL encoding/decoding for safely serializing binary data to send over HTTP/JSON
*/

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

// compute_v_from_password derives a public verifier value (v = g^x) from a password.
// It takes the parametrs:
// - password: the user's password as bytes
// - pw_len: the length of the password
// - out_v_b64: buffer to hold the base64url-encoded public key
// - out_len: size of the output buffer
// Returns: 0 on success, -1 on failure
int compute_v_from_scalar(const uint8_t* password, size_t pw_len, 
                           char* out_v_b64, size_t out_len);

// initiate_login_from_password begins a Schnnor login round, generates random r, and computes t = g^r.
// It takes the parameters:
// - password: the user's raw passwrd
// - pw_len: the length of the password
// - out_t_b64: output buffer for base64url encoded t (t = g^r)
// - out_len: size of the output buffer
// - state_id: pointer to an integer index into internal state pool for trackig session data
// Returns: 0 on success, -1 on error
int initiate_login_from_scalar(const uint8_t* password, size_t pw_len,
                                char* out_t_b64, size_t out_len, 
                                uint32_t* state_id);

// compute_response_from_state provides the complete Schnnor proof. 
// It takes the stored r and x (state_id) and the verifier's challenge c, and computes s = r + c*x mod L.
// Parameters:
// - state_id: index from initiate_login_from_password that identifies which (r, x) to use
// - challenge: 32-byte challenge sent from verifier
// - c_len: length of the challenge (should be 32 bytes}
// - out_s_b64: output buffer to hold base64url encoded result
// - out_len: size of output buffer
// Returns: 0 on success, -1 on failure
int compute_response_from_state(uint32_t state_id, 
                               const uint8_t* challenge, size_t c_len,
                               char* out_s_b64, size_t out_len);

// free_state function manually clears and frees the memory allocated for a state slot.
// It is used when a login process is aborted, or sensitive information needs to be removed from memory.
// Parameters:
// - state_id: index of the state to free
// Returns: 0 on success, -1 if the provided state_id is invalid.
int free_state(uint32_t state_id);

/*
Utility Functions
These functions are used internally by the main authentication flow.
*/

// zero_memory is used to securely wipe sensitive data from memory to prevent leaks.
// It takes:
// - ptr: pointer to the memory location to be wiped
// - len: number of bytes to overwrite
// This function overwrites memory in a way that avoids compiler optimizations that skip memset.
void zero_memory(void* ptr, size_t len);

// base64url_encode encodes binary data into Base64URL format, which is URL-safe (no '+' or '/').
// It takes:
// - data: binary data to encode
// - len: size of data
// - output: buffer to store encoded string
// - out_len: size of output buffer
// Returns: 0 on success, -1 on failure (e.g., output buffer too small)
int base64url_encode(const uint8_t* data, size_t len, char* output, size_t out_len);

// base64url_decode decodes a Base64URL string back into binary data.
// It takes:
// - input: Base64URL-encoded string
// - output: buffer to store decoded bytes
// - out_len: size of output buffer
// Returns: 0 on success, -1 on failure (e.g., invalid Base64URL string or insufficient buffer size)
int base64url_decode(const char* input, uint8_t* output, size_t out_len);

#endif // CRYPTO_H
