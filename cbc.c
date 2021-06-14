#include<stdio.h>
#include<stdlib.h>
#include <string.h>
#include "aes.h"
#include "cbc.h"

int cbcencrypt(unsigned char Key[], unsigned char* input, int length, unsigned char iv[], unsigned char* output){
    if(length <= 0 || length %16 != 0 || input == NULL || output == NULL)
    {
        printf("\ncbc length error!\n");
        return -1;
    }

    int i,j;
    unsigned char in[16], out[16];

    for(i=0; i<16; i++)
        out[i]=iv[i];

    for(i=0; i<length; i=i+16)
    {
        for(j=0;j<16;j++)
            in[j]=input[i+j]^out[j];

        aesencrypt(Key,in,out);

        for(j=0;j<16;j++)
            output[i+j]=out[j];
    }
    return 1;
}

int cbcdecrypt(unsigned char Key[],unsigned char* input, int length,unsigned char iv[],unsigned char* output)
{  int i,j;
   unsigned char in[16],out[16],out1[16];

   if(length == 0)
   {
       printf("\n Lungimea nu poate fi nula\n");
       return -1;
   }

     for(i=0;i<16;i++)
        out1[i]=iv[i];

     for(i=0;i<length;i=i+16){

        for(j=0;j<16;j++) in[j]=input[i+j];

        aesdecrypt(Key,in,out);

        for(j=0;j<16;j++) {out[j]^=out1[j];
                           out1[j]=in[j];}

        for(j=0;j<16;j++) output[i+j]=out[j];
                            }

     return 1;

};
int cbcencryptcheck(){
    int i;

    unsigned char cipher[16]=  {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};
    unsigned char cipher1[16]= {0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6};
    unsigned char cipher2[16]= {0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d};
    unsigned char cipher3[16]= {0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61};
    unsigned char cipher4[16]= {0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b};
    unsigned char Key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    unsigned char Input[16]= {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    unsigned char Key1[32] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                              0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    unsigned char Input1[16]={0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
    unsigned char Key2[32] ={0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
    unsigned char Input2[16]={0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
    unsigned char Key3[32]={0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
    unsigned char Input3[16]={0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef};
    unsigned char Key4[32]={0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
    unsigned char Input4[16]={0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
    unsigned char iv1[16]={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
    unsigned char iv2[16]={0xF5,0x8C,0x4C,0x04,0xD6,0xE5,0xF1,0xBA,0x77,0x9E,0xAB,0xFB,0x5F,0x7B,0xFB,0xD6};
    unsigned char iv3[16]={0x9C,0xFC,0x4E,0x96,0x7E,0xDB,0x80,0x8D,0x67,0x9F,0x77,0x7B,0xC6,0x70,0x2C,0x7D};
    unsigned char iv4[16]={0x39,0xF2,0x33,0x69,0xA9,0xD9,0xBA,0xCF,0xA5,0x30,0xE2,0x63,0x04,0x23,0x14,0x61};


    unsigned char output[16];


    cbcencrypt(Key1,Input1,16,iv1,output);
    for(i=0;i<16;i++)
        if(output[i]!=cipher1[i]) {
            printf("Test 1 failed\n");
            return -1;
        }
    printf("Test 1 passed\n");



    cbcencrypt(Key2,Input2,16,iv2,output);
    for(i=0;i<16;i++)
        if(output[i]!=cipher2[i]) {
            printf("Test 2 failed\n");
            return -1;
        }
    printf("Test 2 passed\n");


    cbcencrypt(Key3,Input3,16,iv3,output);
    for(i=0;i<16;i++)
        if(output[i]!=cipher3[i]) {
            printf("Test 3 failed\n");
            return -1;
        }
    printf("Test 3 passed\n");



    cbcencrypt(Key4,Input4,16,iv4,output);
    for(i=0;i<16;i++)
        if(output[i]!=cipher4[i]) {
            printf("Test 0 failed\n");
            return -1;
        }
    printf("Test 4 passed\n");
    return 1;

}


int cbcdecryptcheck(){
    int i;


    unsigned char cipher1[16]= {0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6};
    unsigned char cipher2[16]= {0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d};
    unsigned char cipher3[16]= {0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61};
    unsigned char cipher4[16]= {0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b};
    unsigned char Key1[32] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                              0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    unsigned char Input1[16]={0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
    unsigned char Key2[32] ={0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
    unsigned char Input2[16]={0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
    unsigned char Key3[32]={0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
    unsigned char Input3[16]={0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef};
    unsigned char Key4[32]={0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
    unsigned char Input4[16]={0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
    unsigned char iv1[16]={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
    unsigned char iv2[16]={0xF5,0x8C,0x4C,0x04,0xD6,0xE5,0xF1,0xBA,0x77,0x9E,0xAB,0xFB,0x5F,0x7B,0xFB,0xD6};
    unsigned char iv3[16]={0x9C,0xFC,0x4E,0x96,0x7E,0xDB,0x80,0x8D,0x67,0x9F,0x77,0x7B,0xC6,0x70,0x2C,0x7D};
    unsigned char iv4[16]={0x39,0xF2,0x33,0x69,0xA9,0xD9,0xBA,0xCF,0xA5,0x30,0xE2,0x63,0x04,0x23,0x14,0x61};


    unsigned char output[16];


    cbcdecrypt(Key1,cipher1,16,iv1,output);
    for(i=0;i<16;i++) if(output[i]!=Input1[i]) {printf("Test 1 failed\n");
                                                return -1;
                                                 }
    printf("Test 1 passed\n");



    cbcdecrypt(Key2,cipher2,16,iv2,output);
    for(i=0;i<16;i++) if(output[i]!=Input2[i]) {printf("Test 2 failed\n");
                                                return -1;
                                                 }
    printf("Test 2 passed\n");


    cbcdecrypt(Key3,cipher3,16,iv3,output);
    for(i=0;i<16;i++) if(output[i]!=Input3[i]) {printf("Test 3 failed\n");
                                                return -1;
                                                 }
    printf("Test 3 passed\n");



    cbcdecrypt(Key4,cipher4,16,iv4,output);
    for(i=0;i<16;i++) if(output[i]!=Input4[i]) {printf("Test 0 failed\n");
                                                return -1;
                                                 }
    printf("Test 4 passed\n");
    return 1;

}