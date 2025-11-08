#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

// Core crypto functions
int compute_v_from_password(const uint8_t* password, size_t pw_len, 
                           char* out_v_b64, size_t out_len);

int initiate_login_from_password(const uint8_t* password, size_t pw_len,
                                char* out_t_b64, size_t out_len, 
                                uint32_t* state_id);

int compute_response_from_state(uint32_t state_id, 
                               const uint8_t* challenge, size_t c_len,
                               char* out_s_b64, size_t out_len);

int free_state(uint32_t state_id);

// Utility functions
void zero_memory(void* ptr, size_t len);
int base64url_encode(const uint8_t* data, size_t len, char* output, size_t out_len);
int base64url_decode(const char* input, uint8_t* output, size_t out_len);

#endif