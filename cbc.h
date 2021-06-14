#ifndef CBC_H
#define CBC_H
#ifdef __cplusplus
extern "C"{
#endif
int cbcencrypt(unsigned char Key[], unsigned char* input,int length,unsigned char iv[],unsigned char* output);
int cbcdecrypt(unsigned char Key[],unsigned char* input, int length,unsigned char iv[],unsigned char* output);

int cbcencryptcheck();
int cbcdecryptcheck();
#ifdef __cplusplus
}

#endif
#endif
