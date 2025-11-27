#ifndef ZKP_CRYPTO_H
#define ZKP_CRYPTO_H

/*
* - We are using fixed width integer types for byte level data (unint8_t)
*
* - size_t has been used for sizes / buffer lengths ( standard and portable )
*
* - functions are returning small integer status codes for success 0 
*
* - ownership => caller allocates buffers, functions document specific sizes
*/

#include<stdint.h> // stdint is for the uint8_t, unint32_t, unint64_t
#include<stddef.h> // size_t 

// Return codes, keep positive success (0) negative errors
typedef int32_t zkp_ret_t;
#define ZKP_OK             0 //success
#define ZKP_ERR_GENERIC   -1 // unspecified failure
#define ZKP_ERR_OVERFLOW  -2 // ouput buffer too small 
#define ZKP_ERR_BADARG    -3 // invalid arguement (NULL, wrong size, etc)
#define ZKP_ERR_DECODE    -4 // decode failure (eg base64 decode)

/*
* LOW LEVEL helpers
*/

/* - zero_memory this function is for wiping out the secrets befor freeing the memory
* - Prevents compiler from optimizing it away
* - It accpets void *buf which accepts buffer of any datatype, and accepts len of datatype size_t 
*/
zkp_ret_t zero_memory(void *buf, size_t len);

/* Base64url (RFC 4648) helpers
* - We use RFC4648 "base64url" alphabet ( '-' and '_') optionally without '=' padding.
* - The API support both padded and unpadded inputs
* All encoding and decoding works raw bytes (uint8_t) and NULL terminated output for tesxtual functons where appropiate
*/
zkp_ret_t base64url_encode(const uint8_t *input, size_t in_len, char *output, size_t out_size, int pad);
#endif 
