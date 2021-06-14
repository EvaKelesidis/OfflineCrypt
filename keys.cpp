#include "keys.h"
#include "gmp.h"
#include "gmpxx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <iostream>
#include <QDir>

#include "sha512.h"
#include "hmac.h"
#include "cbc.h"
#include "keys.h"
#include "gmp.h"
#include "gmpxx.h"
#include "gcm.h"
#include "generators.h"

#include <QApplication>
#include <QDataStream>
#include <QFile>

using namespace std;

extern "C" void generate_keys(unsigned char* a_char_arr, size_t &a_length)
{
    gmp_randstate_t randstate;

    mpz_t a;
    mpz_t q;
    mpz_t g;
    mpz_t ka;
    mpz_t zero;

    mpz_init(a);
    mpz_init(q);
    mpz_init(g);
    mpz_init(ka);
    mpz_init(zero);

    mpz_set_ui(zero, 0);

    if(getq(&q)==-1)
        exit(-1);

    if((mpz_probab_prime_p(q,25))==0)
    {
        mpz_clear(a);
        mpz_clear(q);
        mpz_clear(g);
        mpz_clear(ka);
        mpz_clear(zero);
        exit(-1);
    }

    mpz_set_ui(g, 2);
    mpz_mod(g, g, q);
    if(mpz_cmp(g, zero)== 0)
    {
        mpz_clear(a);
        mpz_clear(q);
        mpz_clear(g);
        mpz_clear(ka);
        mpz_clear(zero);
        exit(-1);
    }

    gmp_randinit_mt(randstate);
    gmp_randseed_ui(randstate, time(NULL));

    mpz_urandomm(a, randstate, q);

    if(mpz_cmp(a, zero)== 0)
    {
        mpz_clear(a);
        mpz_clear(q);
        mpz_clear(g);
        mpz_clear(ka);
        mpz_clear(zero);
        exit(-1);
    }

    mpz_class a_private_key = mpz_class(a);
    string a_string = a_private_key.get_str(16);

    if(a_string.length() <= 0)
    {
        mpz_clear(a);
        mpz_clear(q);
        mpz_clear(g);
        mpz_clear(ka);
        mpz_clear(zero);
        exit(-1);
    }

    size_t length ;
    if(a_string.length() % 2 == 0)
        length = a_string.length() / 2;
    else
        length = a_string.length() / 2 + 1;

    mpz_export(a_char_arr, &length, 1, sizeof(a_char_arr[0]), 0, 0, a);
    a_length = length;


    mpz_powm (ka, g, a, q);

    mpz_class a_public_key = mpz_class(ka);
    string ka_string = a_public_key.get_str(16);

    if(ka_string.length() <= 0)
    {
        mpz_clear(a);
        mpz_clear(q);
        mpz_clear(g);
        mpz_clear(ka);
        mpz_clear(zero);
        exit(-1);
    }

    unsigned char* ka_char_arr = (unsigned char*)calloc(ka_string.length(), sizeof(unsigned char));
    if(ka_char_arr == NULL)
    {
        free(ka_char_arr);
        mpz_clear(a);
        mpz_clear(q);
        mpz_clear(g);
        mpz_clear(ka);
        mpz_clear(zero);
        exit(-1);
    }

    if(ka_string.length() % 2 == 0)
        length = ka_string.length() / 2;
    else
        length = ka_string.length() / 2 + 1;
    mpz_export(ka_char_arr, &length, 1, sizeof(ka_char_arr[0]), 0, 0, ka);

    QString path(QDir::homePath() + "/Public_Keys/");
    QDir dir;
    if (!dir.exists(path))
        dir.mkpath(path);
    QFile afdecrypt(path + "public_key");


    if(afdecrypt.open(QIODevice::WriteOnly) == false)
    {
        free(ka_char_arr);
        mpz_clear(a);
        mpz_clear(q);
        mpz_clear(g);
        mpz_clear(ka);
        mpz_clear(zero);
        exit(-1);
    }
    QDataStream out_afdecrypt(&afdecrypt);
    if(out_afdecrypt.writeRawData((const char*)ka_char_arr, length) == -1)
    {
         afdecrypt.close();
         free(ka_char_arr);
         mpz_clear(a);
         mpz_clear(q);
         mpz_clear(g);
         mpz_clear(ka);
         mpz_clear(zero);
         exit(-1);
    }
    afdecrypt.close();
    free(ka_char_arr);
    mpz_clear(a);
    mpz_clear(q);
    mpz_clear(g);
    mpz_clear(ka);
    mpz_clear(zero);
}


int compute_common_key( unsigned char* key, int keylength, unsigned char* pubkey, int publength,  unsigned char* output)
{

    if(keylength <= 0 || keylength > 256 || publength <= 0 || publength > 256 || pubkey == NULL || key == NULL || output == NULL)
        return -1;

    mpz_t private_key;
    mpz_t public_key;
    mpz_t shared_key;
    mpz_t q;

    mpz_init(private_key);
    mpz_init(public_key);
    mpz_init(shared_key);
    mpz_init(q);

    if(getq(&q) == -1)
       return -1;

    if((mpz_probab_prime_p(q,25))==0)
    {
        mpz_clear(q);
        mpz_clear(private_key);
        mpz_clear(public_key);
        mpz_clear(shared_key);
        exit(-1);
    }


    mpz_import(private_key, keylength, 1, sizeof(key[0]), 0, 0 , key);
    mpz_import(public_key, publength, 1, sizeof(pubkey[0]), 0, 0 , pubkey);

    mpz_powm(shared_key, public_key, private_key, q);

    mpz_class shared_key_mpz = mpz_class(shared_key);
    string shared_key_string = shared_key_mpz.get_str(16);

    size_t length;

    if(shared_key_string.length() % 2 == 0)
        length = shared_key_string.length() / 2;
    else
        length = shared_key_string.length() / 2 + 1;

    unsigned char* key_sha = (unsigned char*)calloc(length, sizeof(unsigned char));

    mpz_export(key_sha, &length, 1, sizeof(key_sha[0]), 0, 0, shared_key);

    if(mbedtls_sha512_ret(key_sha, length, output, 0) != 0) {
        free(key_sha);
        return -1;
    }

    free(key_sha);
    return 0;
}

extern "C" int getq(mpz_t* q){
unsigned char longnumber[583]="FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
      "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
      "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
      "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
      "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
      "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
      "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
      "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
      "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
      "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
      "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF";

if (mpz_set_str(*q,(const char*)longnumber,16)==-1) return -1;
return 0;

}
