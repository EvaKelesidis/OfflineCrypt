#ifndef KEYS_H
#define KEYS_H
#include "gmp.h"

#ifdef __cplusplus
extern "C"{
#endif
int compute_common_key( unsigned char* key, int keylength, unsigned char* pubkey, int publength,  unsigned char* output);
int getq(mpz_t* q);
extern "C" void generate_keys(unsigned char* a, size_t &a_length);
#ifdef __cplusplus
}
#endif
#endif // KEYS_H
