#ifndef HMAC_H
#define HMAC_H
#ifdef __cplusplus
extern "C" {
#endif
int hmac(unsigned char* K, int Klen,unsigned char* Data, int Dlen,unsigned char* output);
int check();
#ifdef __cplusplus
}
#endif
#endif
