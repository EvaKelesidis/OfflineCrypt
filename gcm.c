#include "gcm.h"
#include "aes.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

uint8_t reverseInt4(uint8_t value){
   value = ((value & 0x0C) >> 2) | ((value & 0x03) << 2);
   value = ((value & 0x0A) >> 1) | ((value & 0x05) << 1);

   return value;
}

 static const uint32_t red[16] =
 {
    0x00000000,
    0x1C200000,
    0x38400000,
    0x24600000,
    0x70800000,
    0x6CA00000,
    0x48C00000,
    0x54E00000,
    0xE1000000,
    0xFD200000,
    0xD9400000,
    0xC5600000,
    0x91800000,
    0x8DA00000,
    0xA9C00000,
    0xB5E00000
 };

int gcmInit(GcmContext *context, uint8_t key[]){
    unsigned int i;
    unsigned int j;
    uint32_t c;
    uint32_t h[4];

    h[0] = 0;
    h[1] = 0;
    h[2] = 0;
    h[3] = 0;

    unsigned char aes_input[16];
    for(int i = 0; i < 16; i++)
        aes_input[i] = 0;
    aesencrypt(key, aes_input, aes_input);

    for(int i = 0; i < 4; i++)
        h[i] = (aes_input[i * 4 + 3] << 24) | (aes_input[i * 4 + 2] << 16) | (aes_input[i * 4 + 1] << 8) | aes_input[i * 4];

    j = reverseInt4(0);
    context->m[j][0] = 0;
    context->m[j][1] = 0;
    context->m[j][2] = 0;
    context->m[j][3] = 0;

    j = reverseInt4(1);
    context->m[j][0] = SWAPINT32(h[3]);
    context->m[j][1] = SWAPINT32(h[2]);
    context->m[j][2] = SWAPINT32(h[1]);
    context->m[j][3] = SWAPINT32(h[0]);

    for(i = 2; i < 16; i++)
    {
       if(i & 1)
       {
          j = reverseInt4(i - 1);
          h[0] = context->m[j][0];
          h[1] = context->m[j][1];
          h[2] = context->m[j][2];
          h[3] = context->m[j][3];

          j = reverseInt4(1);
          h[0] ^= context->m[j][0];
          h[1] ^= context->m[j][1];
          h[2] ^= context->m[j][2];
          h[3] ^= context->m[j][3];
       }
       else
       {
          j = reverseInt4(i / 2);
          h[0] = context->m[j][0];
          h[1] = context->m[j][1];
          h[2] = context->m[j][2];
          h[3] = context->m[j][3];

          c = h[0] & 0x01;
          h[0] = (h[0] >> 1) | (h[1] << 31);
          h[1] = (h[1] >> 1) | (h[2] << 31);
          h[2] = (h[2] >> 1) | (h[3] << 31);
          h[3] >>= 1;


          h[3] ^= red[reverseInt4(1)] & ~(c - 1);
       }

       j = reverseInt4(i);
       context->m[j][0] = h[0];
       context->m[j][1] = h[1];
       context->m[j][2] = h[2];
       context->m[j][3] = h[3];
    }

  /*  for(int i = 0; i < 16; i++){
        for(int j = 0; j < 4; j++)
            printf("%08x ", context->m[i][j]);
        printf("\n");
    }*/

    return 0;
 }


 int gcmEncrypt(GcmContext *context, const uint8_t *iv, size_t ivLen, const uint8_t *a, size_t aLen, const uint8_t *p, uint8_t *c, size_t length, uint8_t *t, size_t tLen, uint8_t key[]){

    size_t k;
    size_t n;
    uint8_t b[16];
    uint8_t j[16];
    uint8_t s[16];

    //if(context == NULL || ivLen < 1 || tLen < 4 || tLen > 16)
      // return -1;
    if(context == NULL || ivLen < 1 || tLen > 16)
        return -1;
    if(ivLen == 12)
    {
       osMemcpy(j, iv, 12);
       STORE32BE(1, j + 12);
    }
    else
    {
       osMemset(j, 0, 16);
       n = ivLen;
       while(n > 0)
       {
          k = MIN(n, 16);
          gcmXorBlock(j, j, iv, k);
          gcmMul(context, j);
          iv += k;
          n -= k;
       }
       osMemset(b, 0, 8);
       STORE64BE(ivLen * 8, b + 8);
       gcmXorBlock(j, j, b, 16);
       gcmMul(context, j);
    }

    aesencrypt(key, j, b);
    osMemcpy(t, b, tLen);
    osMemset(s, 0, 16);
    n = aLen;

    while(n > 0)
    {
       k = MIN(n, 16);
       gcmXorBlock(s, s, a, k);
       gcmMul(context, s);
       a += k;
       n -= k;
    }

    n = length;

    while(n > 0)
    {
       k = MIN(n, 16);
       gcmIncCounter(j);
       aesencrypt(key, j, b);
       gcmXorBlock(c, p, b, k);
       gcmXorBlock(s, s, c, k);
       gcmMul(context, s);
       p += k;
       c += k;
       n -= k;
    }

    STORE64BE(aLen * 8, b);
    STORE64BE(length * 8, b + 8);
    gcmXorBlock(s, s, b, 16);
    gcmMul(context, s);
    gcmXorBlock(t, t, s, tLen);

    return 0;
 }

int gcmDecrypt(GcmContext *context, const uint8_t *iv, size_t ivLen, const uint8_t *a, size_t aLen, const uint8_t *c,
    uint8_t *p, size_t length, const uint8_t *t, size_t tLen, uint8_t key[]){
    uint8_t mask;
    size_t k;
    size_t n;
    uint8_t b[16];
    uint8_t j[16];
    uint8_t r[16];
    uint8_t s[16];

    if(context == NULL || ivLen < 1 || tLen > 16 )
       return -1;

    if(ivLen == 12)
    {
       osMemcpy(j, iv, 12);
       STORE32BE(1, j + 12);
    }
    else
    {
       osMemset(j, 0, 16);
       n = ivLen;
       while(n > 0)
       {
          k = MIN(n, 16);
          gcmXorBlock(j, j, iv, k);
          gcmMul(context, j);
          iv += k;
          n -= k;
       }
       osMemset(b, 0, 8);
       STORE64BE(ivLen * 8, b + 8);
       gcmXorBlock(j, j, b, 16);
       gcmMul(context, j);
    }

    aesencrypt(key, j, b);
    osMemcpy(r, b, tLen);
    osMemset(s, 0, 16);
    n = aLen;

    while(n > 0)
    {
       k = MIN(n, 16);
       gcmXorBlock(s, s, a, k);
       gcmMul(context, s);
       a += k;
       n -= k;
    }
    n = length;

    while(n > 0)
    {
       k = MIN(n, 16);
       gcmXorBlock(s, s, c, k);
       gcmMul(context, s);
       gcmIncCounter(j);
       aesencrypt(key, j, b);
       gcmXorBlock(p, c, b, k);
       c += k;
       p += k;
       n -= k;
    }
    STORE64BE(aLen * 8, b);
    STORE64BE(length * 8, b + 8);

    gcmXorBlock(s, s, b, 16);
    gcmMul(context, s);
    gcmXorBlock(r, r, s, tLen);

    /*for(int i = 0; i < tLen; i++)
        printf("%02x", r[i]);
    printf("\n");*/

    for(mask = 0, n = 0; n < tLen; n++)
       mask |= r[n] ^ t[n];

    return (mask == 0) ? 0 : -1;
 }

 void gcmMul(GcmContext *context, uint8_t *x){
    int i;
    uint8_t b;
    uint8_t c;
    uint32_t z[4];

    z[0] = 0;
    z[1] = 0;
    z[2] = 0;
    z[3] = 0;

    for(i = 15; i >= 0; i--)
    {
       b = x[i] & 0x0F;
       c = z[0] & 0x0F;
       z[0] = (z[0] >> 4) | (z[1] << 28);
       z[1] = (z[1] >> 4) | (z[2] << 28);
       z[2] = (z[2] >> 4) | (z[3] << 28);
       z[3] >>= 4;

       z[0] ^= context->m[b][0];
       z[1] ^= context->m[b][1];
       z[2] ^= context->m[b][2];
       z[3] ^= context->m[b][3];

       z[3] ^= red[c];
       b = (x[i] >> 4) & 0x0F;

       c = z[0] & 0x0F;
       z[0] = (z[0] >> 4) | (z[1] << 28);
       z[1] = (z[1] >> 4) | (z[2] << 28);
       z[2] = (z[2] >> 4) | (z[3] << 28);
       z[3] >>= 4;

       z[0] ^= context->m[b][0];
       z[1] ^= context->m[b][1];
       z[2] ^= context->m[b][2];
       z[3] ^= context->m[b][3];

       z[3] ^= red[c];
    }
    STORE32BE(z[3], x);
    STORE32BE(z[2], x + 4);
    STORE32BE(z[1], x + 8);
    STORE32BE(z[0], x + 12);
 }

 void gcmXorBlock(uint8_t *x, const uint8_t *a, const uint8_t *b, size_t n){
    size_t i;
    for(i = 0; i < n; i++)
       x[i] = a[i] ^ b[i];

 }


 void gcmIncCounter(uint8_t *x){
    size_t i;
    for(i = 0; i < 4; i++)
       if(++(x[15 - i]) != 0)
          break;
 }

 int gcm_test(){

     unsigned char* input = (unsigned char*)calloc(128, sizeof(unsigned char));
     unsigned char* output = (unsigned char*)calloc(128, sizeof(unsigned char));

     unsigned char Key[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
     unsigned char* iv = (unsigned char*)calloc(16, sizeof(unsigned char));
     unsigned char* tag = (unsigned char*)calloc(32, sizeof(unsigned char));

     unsigned char tag_13[16] = {0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b};

     GcmContext ctx;
     gcmInit(&ctx, Key);
     int ret = gcmEncrypt(&ctx, iv, 12, NULL, 0, input, output, 0, tag, 16, Key);
     if(ret != 0)
         return -1;
     for(int i = 0; i < 16; i++)
         if(tag[i] != tag_13[i])
             return -1;

     unsigned char tag_14[16] = {0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19};
     unsigned char ciphertext_14[16] = {0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18};

     gcmInit(&ctx, Key);
     ret = gcmEncrypt(&ctx, iv, 12, NULL, 0, input, output, 16, tag, 16, Key);
     if(ret != 0)
         return -1;
     for(int i = 0; i < 16; i++)
         if(tag[i] != tag_14[i])
             return -1;
     for(int i = 0; i < 16; i++)
         if(output[i] != ciphertext_14[i])
             return -1;

     unsigned char input_15[64] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09,
                                   0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34,
                                   0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c,
                                   0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24,
                                   0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6,
                                   0x57, 0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55};
     unsigned char iv_15[12] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
     unsigned char Key_15[32] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
                                 0x67, 0x30, 0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                                 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};

     memcpy(input, input_15, 64);
     memcpy(iv, iv_15, 12);

     unsigned char tag_15[16] = {0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34, 0x71, 0xbd, 0xec, 0x1a, 0x50, 0x22, 0x70, 0xe3, 0xcc, 0x6c};
     unsigned char ciphertext_15[64] = {0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3,
                                        0x2a, 0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
                                        0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48,
                                        0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
                                        0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad};

     gcmInit(&ctx, Key_15);
     ret = gcmEncrypt(&ctx, iv_15, 12, NULL, 0, input_15, output, 64, tag, 16, Key_15);
     if(ret != 0)
         return -1;
     for(int i = 0; i < 16; i++)
         if(tag[i] != tag_15[i])
             return -1;
     for(int i = 0; i < 64; i++)
         if(output[i] != ciphertext_15[i])
             return -1;

     unsigned char auth_data_16[20] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
                                       0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
                                       0xab, 0xad, 0xda, 0xd2};
     unsigned char tag_16[16] = {0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b};

     gcmInit(&ctx, Key_15);
     ret = gcmEncrypt(&ctx, iv_15, 12, auth_data_16, 20, input_15, output, 60, tag, 16, Key_15);
     if(ret != 0)
         return -1;
     for(int i = 0; i < 16; i++)
         if(tag[i] != tag_16[i])
             return -1;
     for(int i = 0; i < 60; i++)
         if(output[i] != ciphertext_15[i])
             return -1;

     unsigned char ciphertext_17[60] = {0xc3, 0x76, 0x2d, 0xf1, 0xca, 0x78, 0x7d, 0x32, 0xae, 0x47,
                                        0xc1, 0x3b, 0xf1, 0x98, 0x44, 0xcb, 0xaf, 0x1a, 0xe1, 0x4d,
                                        0x0b, 0x97, 0x6a, 0xfa, 0xc5, 0x2f, 0xf7, 0xd7, 0x9b, 0xba,
                                        0x9d, 0xe0, 0xfe, 0xb5, 0x82, 0xd3, 0x39, 0x34, 0xa4, 0xf0,
                                        0x95, 0x4c, 0xc2, 0x36, 0x3b, 0xc7, 0x3f, 0x78, 0x62, 0xac,
                                        0x43, 0x0e, 0x64, 0xab, 0xe4, 0x99, 0xf4, 0x7c, 0x9b, 0x1f};
     unsigned char tag_17[16] = {0x3a, 0x33, 0x7d, 0xbf, 0x46, 0xa7, 0x92, 0xc4, 0x5e, 0x45, 0x49, 0x13, 0xfe, 0x2e, 0xa8, 0xf2};

     gcmInit(&ctx, Key_15);
     ret = gcmEncrypt(&ctx, iv_15, 8, auth_data_16, 20, input_15, output, 60, tag, 16, Key_15);
     if(ret != 0)
         return -1;
     for(int i = 0; i < 16; i++)
         if(tag[i] != tag_17[i])
             return -1;
     for(int i = 0; i < 60; i++)
         if(output[i] != ciphertext_17[i])
             return -1;

     unsigned char iv_18[60] = {0x93, 0x13, 0x22, 0x5d, 0xf8, 0x84, 0x06, 0xe5,
                                0x55, 0x90, 0x9c, 0x5a, 0xff, 0x52, 0x69, 0xaa,
                                0x6a, 0x7a, 0x95, 0x38, 0x53, 0x4f, 0x7d, 0xa1,
                                0xe4, 0xc3, 0x03, 0xd2, 0xa3, 0x18, 0xa7, 0x28,
                                0xc3, 0xc0, 0xc9, 0x51, 0x56, 0x80, 0x95, 0x39,
                                0xfc, 0xf0, 0xe2, 0x42, 0x9a, 0x6b, 0x52, 0x54,
                                0x16, 0xae, 0xdb, 0xf5, 0xa0, 0xde, 0x6a, 0x57,
                                0xa6, 0x37, 0xb3, 0x9b};

     unsigned char ciphertext_18[60] = {0x5a, 0x8d, 0xef, 0x2f, 0x0c, 0x9e, 0x53, 0xf1, 0xf7, 0x5d,
                                        0x78, 0x53, 0x65, 0x9e, 0x2a, 0x20, 0xee, 0xb2, 0xb2, 0x2a,
                                        0xaf, 0xde, 0x64, 0x19, 0xa0, 0x58, 0xab, 0x4f, 0x6f, 0x74,
                                        0x6b, 0xf4, 0x0f, 0xc0, 0xc3, 0xb7, 0x80, 0xf2, 0x44, 0x45,
                                        0x2d, 0xa3, 0xeb, 0xf1, 0xc5, 0xd8, 0x2c, 0xde, 0xa2, 0x41,
                                        0x89, 0x97, 0x20, 0x0e, 0xf8, 0x2e, 0x44, 0xae, 0x7e, 0x3f};

     unsigned char tag_18[16] = {0xa4, 0x4a, 0x82, 0x66, 0xee, 0x1c, 0x8e, 0xb0, 0xc8, 0xb5, 0xd4, 0xcf, 0x5a, 0xe9, 0xf1, 0x9a};

     gcmInit(&ctx, Key_15);
     ret = gcmEncrypt(&ctx, iv_18, 60, auth_data_16, 20, input_15, output, 60, tag, 16, Key_15);
     if(ret != 0)
         return -1;
     for(int i = 0; i < 16; i++)
         if(tag[i] != tag_18[i])
             return -1;
     for(int i = 0; i < 60; i++)
         if(output[i] != ciphertext_18[i])
             return -1;

     free(input);
     free(output);
     free(iv);
     free(tag);
     return 0;

 }
