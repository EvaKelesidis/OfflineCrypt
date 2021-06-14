#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dhaes.h"
#include "keys.h"
#include "cbc.h"
#include "hmac.h"
#include "gmp.h"
#include "gmpxx.h"
#include "generators.h"

#define keymaclength 32


int finalencrypt(unsigned char* input, int length, unsigned char Keycbc[], unsigned char Keymac[], unsigned char* output, unsigned char iv[])
{

    if(input == NULL || length <= 0 || length % 16 != 0 || output == NULL)
    {
        printf("final encrypt length error!\n");
        return -1;
    }

    if(cbcencrypt(Keycbc, input, length, iv, output+80) == -1)
        return -1;

    if(hmac(Keymac, 32, output+80, length, output) == -1)
        return -1;

    memcpy(output+64, iv, 16);

    return length;
}


int finaldecrypt(unsigned char* output, int outlength, unsigned char Keycbc[], unsigned char Keymac[], unsigned char *input)
{

    unsigned char tag[64];
    unsigned char iv[16];
    int i;


    if((outlength < 96) || ((outlength - 80) % 16 != 0) || output == NULL || input == NULL)
        return -1;

    if(hmac(Keymac, 32, output+80, outlength - 80, tag) == -1)
        return -1;

    for(i = 0; i < 64; i++)
        if(tag[i]!=output[i])
        {
            printf("tag error \n");
            return -1;
        }

    memcpy(iv, output+64, 16);

    if(cbcdecrypt(Keycbc, output+80, outlength - 80, iv, input) == -1)
        return -1;

    return (outlength - 80) / 16;
}

int encrypt_with_keys(unsigned char* input, int lenght, unsigned char* key, int keylength, unsigned char* pubkey, int publength,  unsigned char* output)
{
    if(lenght % 16 != 0 || lenght <= 0|| input == NULL || output == NULL)
    {
        printf("\nlength problems\n");
        return -1;
    }
    unsigned char* key_sha = (unsigned char*)calloc(64, sizeof(unsigned char));
    if(key_sha == NULL)
    {
        free(key_sha);
        return -1;
    }

    if(compute_common_key(key, keylength, pubkey, publength, key_sha) == -1)
    {
        free(key_sha);
        return -1;
    }

    unsigned char AmacKey[32];
    unsigned char AencKey[32];

    memcpy(AmacKey, key_sha, 32);
    memcpy(AencKey, key_sha + 32, 32);

    free(key_sha);

    unsigned char* iv = (unsigned char*)calloc(16, sizeof(unsigned char));
    if(iv == NULL)
    {
        free(iv);
        return -1;
    }

    generate_IV(iv);

    int final;
    if((final = finalencrypt(input, lenght, AencKey, AmacKey, output, iv)) == -1)
        return -1;


    free(iv);
    return final;
}


int decrypt_with_keys(unsigned char* input, int lenght, unsigned char* key, int keylength, unsigned char* pubkey, int publength,  unsigned char* output)
{

    if(lenght < 96 ||(lenght - 80) % 16 != 0 || input == NULL || output == NULL)
        return -1;

    unsigned char* key_sha = (unsigned char*)calloc(64, sizeof(unsigned char));
    if(key_sha == NULL)
    {
        free(key_sha);
        return -1;
    }

    if(compute_common_key(key, keylength, pubkey, publength, key_sha) == -1)
    {
        free(key_sha);
        return -1;
    }

    unsigned char BmacKey[32];
    unsigned char BencKey[32];

    memcpy(BmacKey, key_sha, 32);
    memcpy(BencKey, key_sha + 32, 32);

    free(key_sha);

    if(finaldecrypt(input, lenght, BencKey, BmacKey, output) == -1)
        return -1;


    return 0;

}


