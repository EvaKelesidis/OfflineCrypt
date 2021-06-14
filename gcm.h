#ifndef GCM_H
#define GCM_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#ifndef osMemcpy
    #include <string.h>
    #define osMemcpy(dest, src, length) (void) memcpy(dest, src, length)
 #endif

#define STORE32BE(a, p) \
    ((uint8_t *)(p))[0] = ((uint32_t)(a) >> 24) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint32_t)(a) >> 16) & 0xFFU, \
    ((uint8_t *)(p))[2] = ((uint32_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[3] = ((uint32_t)(a) >> 0) & 0xFFU

#ifndef osMemset
   #include <string.h>
   #define osMemset(p, value, length) (void) memset(p, value, length)
#endif

#ifndef MIN
   #define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif


#define STORE64BE(a, p) \
   ((uint8_t *)(p))[0] = ((uint64_t)(a) >> 56) & 0xFFU, \
   ((uint8_t *)(p))[1] = ((uint64_t)(a) >> 48) & 0xFFU, \
   ((uint8_t *)(p))[2] = ((uint64_t)(a) >> 40) & 0xFFU, \
   ((uint8_t *)(p))[3] = ((uint64_t)(a) >> 32) & 0xFFU, \
   ((uint8_t *)(p))[4] = ((uint64_t)(a) >> 24) & 0xFFU, \
   ((uint8_t *)(p))[5] = ((uint64_t)(a) >> 16) & 0xFFU, \
   ((uint8_t *)(p))[6] = ((uint64_t)(a) >> 8) & 0xFFU, \
   ((uint8_t *)(p))[7] = ((uint64_t)(a) >> 0) & 0xFFU

#define SWAPINT32(x) ( \
   (((uint32_t)(x) & 0x000000FFUL) << 24) | \
   (((uint32_t)(x) & 0x0000FF00UL) << 8) | \
   (((uint32_t)(x) & 0x00FF0000UL) >> 8) | \
   (((uint32_t)(x) & 0xFF000000UL) >> 24))

 typedef struct
 {
    uint32_t m[16][4];
 } GcmContext;

 int gcmInit(GcmContext *context, uint8_t key[]);
 int gcmEncrypt(GcmContext *context, const uint8_t *iv, size_t ivLen, const uint8_t *a, size_t aLen, const uint8_t *p, uint8_t *c, size_t length, uint8_t *t, size_t tLen, uint8_t key[]);
 int gcmDecrypt(GcmContext *context, const uint8_t *iv, size_t ivLen, const uint8_t *a, size_t aLen, const uint8_t *c, uint8_t *p, size_t length, const uint8_t *t, size_t tLen, uint8_t key[]);

 void gcmMul(GcmContext *context, uint8_t *x);
 void gcmXorBlock(uint8_t *x, const uint8_t *a, const uint8_t *b, size_t n);
 void gcmIncCounter(uint8_t *x);
 uint8_t reverseInt4(uint8_t value);
 int aes_gcm_encrypt(const unsigned char* input, int input_length, const unsigned char* key, const unsigned char * iv, const size_t iv_len, unsigned char* output);
 int aes_gcm_decrypt(const unsigned char* input, int input_length, const unsigned char* key, const unsigned char * iv, const size_t iv_len, unsigned char* output);

 int gcm_test();


#ifdef __cplusplus
}
#endif
#endif // GCM_H
