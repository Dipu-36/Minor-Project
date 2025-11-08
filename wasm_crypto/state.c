#include "crypto.h"
#include <string.h>

// Base64url encoding table
static const char base64url_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int base64url_encode(const uint8_t* data, size_t len, char* output, size_t out_len) {
    if (out_len < (len * 4 / 3 + 4)) {
        return -1; // Output buffer too small
    }
    
    size_t out_index = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t triple = (data[i] << 16);
        if (i + 1 < len) triple |= (data[i + 1] << 8);
        if (i + 2 < len) triple |= data[i + 2];

        output[out_index++] = base64url_table[(triple >> 18) & 0x3F];
        output[out_index++] = base64url_table[(triple >> 12) & 0x3F];
        
        if (i + 1 < len) {
            output[out_index++] = base64url_table[(triple >> 6) & 0x3F];
        } else {
            output[out_index++] = '=';
        }
        
        if (i + 2 < len) {
            output[out_index++] = base64url_table[triple & 0x3F];
        } else {
            output[out_index++] = '=';
        }
    }
    output[out_index] = '\0';
    return 0;
}

int base64url_decode(const char* input, uint8_t* output, size_t out_len) {
    size_t len = strlen(input);
    if (out_len < len * 3 / 4) {
        return -1; // Output buffer too small
    }
    
    size_t out_index = 0;
    for (size_t i = 0; i < len; i += 4) {
        uint32_t quadruple = 0;
        int pad_count = 0;
        
        for (int j = 0; j < 4; j++) {
            if (i + j >= len) {
                pad_count++;
                continue;
            }
            
            char c = input[i + j];
            if (c == '=') {
                pad_count++;
                continue;
            }
            
            const char* pos = strchr(base64url_table, c);
            if (!pos) return -1; // Invalid character
            
            quadruple |= (uint32_t)(pos - base64url_table) << (18 - j * 6);
        }
        
        output[out_index++] = (quadruple >> 16) & 0xFF;
        if (pad_count < 2) {
            output[out_index++] = (quadruple >> 8) & 0xFF;
        }
        if (pad_count < 1) {
            output[out_index++] = quadruple & 0xFF;
        }
    }
    return 0;
}

void zero_memory(void* ptr, size_t len) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (len--) {
        *p++ = 0;
    }
}