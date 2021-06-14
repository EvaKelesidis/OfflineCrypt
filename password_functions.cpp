#include <QFile>
#include <QMessageBox>
#include <QDir>

#include "argon2.h"
#include "password_functions.h"
#include "gcm.h"
#include "generators.h"

int check_password(unsigned char* password, size_t length, unsigned char* key, int get_iv)
{

    QFile encrypted_token_file(QDir::homePath() + "/.OfflineCrypt/encrypted_token");
    if(!encrypted_token_file.open(QIODevice::ReadOnly))
        return -1;
    if(encrypted_token_file.size() != 160){
        encrypted_token_file.close();
        return -1;
    }
    QDataStream encrypted_token_stream(&encrypted_token_file);
    unsigned char* encrypted_token = (unsigned char*)calloc(160, sizeof(unsigned char));
    if(encrypted_token == NULL){
        free(encrypted_token);
        encrypted_token_file.close();
        return -1;
    }
    if(encrypted_token_stream.readRawData((char*)encrypted_token, 160) == -1){
        free(encrypted_token);
        encrypted_token_file.close();
        return -1;
    }
    encrypted_token_file.close();

  /*  printf("salt found\n");
    for(int i = 0; i < 64; i++)
        printf("%02x", encrypted_token[i + 64]);
    printf("\n");

    printf("password found\n");
    for(int i = 0; i < length; i++)
        printf("%02x", password[i]);
    printf("\n");

    printf("length of password found: %d\n", length);
*/

    int version = ARGON2_VERSION_10;
    int ret = argon2_hash_without_encoding(2, 1 << 16, 1, password, length, encrypted_token + 64, 64, key, 32, version);
    if(ret != ARGON2_OK){
        free(encrypted_token);
        return -1;
    }
/*    printf("key found\n");
    for(int i = 0; i < 32; i++)
        printf("%02x", key[i]);
    printf("\n");*/

    QFile cleartext_token_file(QDir::homePath() + "/.OfflineCrypt/cleartext_token");
    if(!cleartext_token_file.open(QIODevice::ReadOnly))
        return -1;
    if(cleartext_token_file.size() != 64){
        cleartext_token_file.close();
        return -1;
    }
    QDataStream cleartext_token_stream(&cleartext_token_file);
    unsigned char* cleartext_token = (unsigned char*)calloc(64, sizeof(unsigned char));
    if(cleartext_token == NULL){
        free(cleartext_token);
        cleartext_token_file.close();
        return -1;
    }
    if(cleartext_token_stream.readRawData((char*)cleartext_token, 64) == -1){
        free(cleartext_token);
        cleartext_token_file.close();
        return -1;
    }
    cleartext_token_file.close();

    unsigned char iv[16];
    memcpy(iv, encrypted_token + 128, 16);
    unsigned char check_token[64];
    unsigned char tag_computed[16];


    GcmContext ctx;
    gcmInit(&ctx, key);
    ret = gcmEncrypt(&ctx, iv, 16, NULL, 0, cleartext_token, check_token, 64, tag_computed, 16, key);

    int ok_tag = 1;
    int ok_encryption = 1;
    for(int i = 0; i < 16; i++)
        if(tag_computed[i] != encrypted_token[i + 144])
             ok_tag = 0;

    for(int i = 0; i < 64; i++)
        if(check_token[i] != encrypted_token[i])
            ok_encryption = 0;

    free(encrypted_token);
    free(cleartext_token);

    if(ok_tag== 0 || ok_encryption == 0)
        return -1;
    else
    {
        if(get_iv == 1)
            memcpy(key + 32, iv, 16);
        return 0;
    }
}

int encrypt_token(unsigned char key[], unsigned char iv[], unsigned char salt[]){

    QFile cleartext_token_file(QDir::homePath() + "/.OfflineCrypt/cleartext_token");
    if(!cleartext_token_file.open(QIODevice::ReadOnly))
        return -1;
    if(cleartext_token_file.size() != 64){
        cleartext_token_file.close();
        return -1;
    }
    QDataStream cleartext_token_stream(&cleartext_token_file);
    unsigned char* cleartext_token = (unsigned char*)calloc(64, sizeof(unsigned char));
    if(cleartext_token == NULL){
        free(cleartext_token);
        cleartext_token_file.close();
        return -1;
    }
    if(cleartext_token_stream.readRawData((char*)cleartext_token, 64) == -1){
        free(cleartext_token);
        cleartext_token_file.close();
        return -1;
    }
    cleartext_token_file.close();
\

    int version = ARGON2_VERSION_10;
    unsigned char* token_encrypted = (unsigned char*)calloc(160, sizeof(unsigned char));
    unsigned char tag[16];
    GcmContext ctx;
    gcmInit(&ctx, key);
    int ret = gcmEncrypt(&ctx, iv, 16, NULL, 0, cleartext_token, token_encrypted, 64, tag, 16, key);
    if(ret == -1)
    {
        free(cleartext_token);
        free(token_encrypted);
        return -1;
    }
    memcpy(token_encrypted + 64, salt, 64);
    memcpy(token_encrypted + 128, iv, 16);
    memcpy(token_encrypted + 144, tag, 16);

    free(cleartext_token);

    QString path(QDir::homePath() + "/.OfflineCrypt/");
    QDir dir;
    if (!dir.exists(path))
        dir.mkpath(path);
    QFile new_ciph_token(path + "encrypted_token");
    if(new_ciph_token.open(QIODevice::WriteOnly) == false)
    {
        free(token_encrypted);
        return -1;
    }
    QDataStream out_new_ciph_token(&new_ciph_token);
    if(out_new_ciph_token.writeRawData((char*)token_encrypted, 160) == -1){
        free(token_encrypted);
        new_ciph_token.close();
        return -1;
    }
    free(token_encrypted);
    new_ciph_token.close();

    return 0;

}


int encrypt_key(unsigned char key[], unsigned char iv[], unsigned char salt[], unsigned char* privatekey, size_t length){

    int version = ARGON2_VERSION_10;
    unsigned char* key_encrypted = (unsigned char*)calloc(length + 16, sizeof(unsigned char));
    unsigned char tag[16];
    GcmContext ctx;
    gcmInit(&ctx, key);
    int ret = gcmEncrypt(&ctx, iv, 16, NULL, 0, privatekey, key_encrypted, length, tag, 16, key);
    if(ret == -1)
        return -1;
    memcpy(key_encrypted + length, tag, 16);

    QString path(QDir::homePath() + "/.OfflineCrypt/");
    QDir dir;
    if (!dir.exists(path))
        dir.mkpath(path);
    QFile afencrypt(path + "private_key");

    if(afencrypt.open(QIODevice::WriteOnly) == false)
        exit(-1);
    QDataStream out_afencrypt(&afencrypt);
    if(out_afencrypt.writeRawData((char*)key_encrypted, length + 16) == -1)
    {
        afencrypt.close();
        exit(-1);
    }

    afencrypt.close();

    return 0;

}




int update_password(unsigned char* password, size_t length)
{
    int version = ARGON2_VERSION_10;

    unsigned char new_salt[64];
    unsigned char new_key[32];
    unsigned char new_iv[16];
    unsigned char tag_computed[16];

    generate_salt((unsigned char*)new_salt);
    generate_IV((unsigned char*)new_iv);

    int ret = argon2_hash_without_encoding(2, 1 << 16, 1, password, length, new_salt, 64, new_key, 32, version);
    if(ret != ARGON2_OK)
        return -1;
    ret = encrypt_token(new_key, new_iv, new_salt);

    return ret;
}

