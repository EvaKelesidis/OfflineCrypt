#ifndef AES_H
#define AES_H

#ifdef __cplusplus
extern "C"{
#endif
void aesencrypt(unsigned char key[],unsigned char input[],unsigned char out[] );
void aesdecrypt(unsigned char key[],unsigned char cipher[],unsigned char out[]);
#ifdef __cplusplus
}

#endif
#endif // AES_H
