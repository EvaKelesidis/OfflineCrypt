#include "offlineencrypt.h"
#include "sha512.h"
#include "hmac.h"
#include "aes.h"
#include "cbc.h"
#include "gcm.h"
#include "generators.h"
#include "argon2.h"
#include "password_functions.h"
#include "keys.h"
#include <QApplication>
#include <QDir>


int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    OfflineEncrypt w;

    printf("%d\n",mbedtls_sha512_self_test(1));
    printf("%d\n", check());
    printf("%d\n", cbcencryptcheck());
    printf("%d\n", cbcdecryptcheck());
    printf("%d\n", gcm_test());
    printf("%d\n", argon2_test());


    unsigned char* user_token = (unsigned char*)calloc(64, sizeof(unsigned char));
    generate_salt(user_token);

    QString path(QDir::homePath() + "/.OfflineCrypt/");
    QDir dir;
    if (!dir.exists(path))
        dir.mkpath(path);
    QFile clear_token(path + "cleartext_token");
    if(clear_token.open(QIODevice::WriteOnly) == false)
        exit(-1);
    QDataStream out_clear_token(&clear_token);
    if(out_clear_token.writeRawData((char*)user_token, 64) == -1){
        clear_token.close();
        exit(-1);
    }
    clear_token.close();


    unsigned char password[] = "Password2021!!!";
    unsigned char salt[64];
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char* password_bytes = (unsigned char*)calloc(15, sizeof(unsigned char));
    memcpy(password_bytes, password, 15);

    generate_salt((unsigned char*)salt);
    generate_IV((unsigned char*)iv);
    int version = ARGON2_VERSION_10;
    int ret = argon2_hash_without_encoding(2, 1 << 16, 1, password_bytes, 15, salt, 64, key, 32, version);
    encrypt_token(key, iv, salt);
    free(password_bytes);

    unsigned char* privatekey = (unsigned char*)calloc(256, sizeof(unsigned char));

    size_t a_length, ka_length;
    generate_keys(privatekey, a_length);
    encrypt_key(key, iv, salt, privatekey, a_length);
   /* printf("\n");
    for(int i = 0; i < 32; i++)
        printf("%02x", key[i]);
    printf("\n");
    for(int i = 0; i < 16; i++)
        printf("%02x", iv[i]);
    printf("\n");*/

    w.show();
    return a.exec();
}



