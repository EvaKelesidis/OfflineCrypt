#ifndef DHAES_H
#define DHAES_H

#include "keys.h"
#include "gmp.h"
#include "gmpxx.h"

int finalencrypt(unsigned char* input, int length, unsigned char Keycbc[], unsigned char Keymac[], unsigned char* output, unsigned char iv[]);
int finaldecrypt(unsigned char* output,int outlength,unsigned char Keycbc[],
                 unsigned char Keymac[],unsigned char *input);
int encrypt_with_keys(unsigned char* input, int lenght, unsigned char* key, int keylength, unsigned char* pubkey, int publength,  unsigned char* output);
int decrypt_with_keys(unsigned char* input, int lenght, unsigned char* key, int keylength, unsigned char* pubkey, int publength,  unsigned char* output);

#endif // DHAES_H
