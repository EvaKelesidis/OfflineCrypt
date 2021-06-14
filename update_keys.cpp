#include "update_keys.h"
#include "ui_update_keys.h"
#include "gmp.h"
#include "gmpxx.h"
#include "keys.h"
#include "password_functions.h"
#include "gcm.h"
#include "generators.h"
#include "argon2.h"


#include <stdio.h>
#include <stdint.h>
#include <QFile>
#include <QDir>
#include <QMessageBox>

using namespace std;

update_keys::update_keys(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::update_keys)
{
    ui->setupUi(this);
}

update_keys::~update_keys()
{
    delete ui;
}
/*
void update_keys::on_pushButton_clicked()
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

    unsigned char* a_char_arr = (unsigned char*)calloc(a_string.length(), sizeof(unsigned char));
    if(a_char_arr == NULL)
    {
        free(a_char_arr);
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

    QString password = ui->lineEdit->text();
    if(password.length() == 0)
        QMessageBox::warning(this, "title", "password field is empty");
    std::string password_std = password.toUtf8().constData();
    unsigned char* password_bytes = (unsigned char*)calloc(password_std.length(), sizeof(unsigned char));
    for(int i = 0; i < password_std.length(); i++)
        password_bytes[i] = password_std[i];

    unsigned char* key = (unsigned char*)calloc(48, sizeof(unsigned char));
    int ret = check_password(password_bytes, password_std.length(), key, 1);

    unsigned char* encr_a = (unsigned char*)calloc(length + 16, sizeof(unsigned char));

    if(ret != 0)
        QMessageBox::warning(this, "title", "Incorrect password!");
    else
    {
        unsigned char new_salt[64];
        unsigned char new_key[32];
        unsigned char new_iv[16];

        generate_salt((unsigned char*)new_salt);
        generate_IV((unsigned char*)new_iv);

        int version = ARGON2_VERSION_10;
        int ret = argon2_hash_without_encoding(2, 1 << 16, 1, password_bytes, password_std.length(), new_salt, 64, new_key, 32, version);
        if(ret != ARGON2_OK)
            exit(-1);
        ret = encrypt_token(new_key, new_iv, new_salt);
        if(ret == -1)
             exit(-1);

        GcmContext ctx;
        gcmInit(&ctx, new_key);
        ret = gcmEncrypt(&ctx, new_iv, 16, NULL, 0, a_char_arr, encr_a, length, encr_a + length, 16, new_key);
        if(ret == -1)
            exit(-1);


        QString path(QDir::homePath() + "/.OfflineCrypt/");
        QDir dir;
        if (!dir.exists(path))
            dir.mkpath(path);

        QFile afencrypt(path + "private_key_2");

        if(afencrypt.open(QIODevice::WriteOnly) == false)
        {
            free(a_char_arr);
            mpz_clear(a);
            mpz_clear(q);
            mpz_clear(g);
            mpz_clear(ka);
            mpz_clear(zero);
            exit(-1);

        }

        QDataStream out_afencrypt(&afencrypt);
        if(out_afencrypt.writeRawData((char*)encr_a, length + 16) == -1)
        {
            free(a_char_arr);
            afencrypt.close();
            mpz_clear(a);
            mpz_clear(q);
            mpz_clear(g);
            mpz_clear(ka);
            mpz_clear(zero);
            exit(-1);
        }

        afencrypt.close();

        encrypt_token(new_key, new_iv, new_salt);

        free(a_char_arr);

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

        QFile afdecrypt("/home/eva/Bachelors/Public Keys/public_key_2");
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

        QMessageBox::warning(this, "title", "Keys updated succesfully!");
        this->close();

    }

}
*/

void update_keys::on_pushButton_clicked()
{

    QString password = ui->lineEdit->text();
    if(password.length() == 0)
        QMessageBox::warning(this, "title", "password field is empty");
    std::string password_std = password.toUtf8().constData();
    unsigned char* password_bytes = (unsigned char*)calloc(password_std.length(), sizeof(unsigned char));
    for(int i = 0; i < password_std.length(); i++)
        password_bytes[i] = password_std[i];

    unsigned char* key = (unsigned char*)calloc(48, sizeof(unsigned char));
    int ret = check_password(password_bytes, password_std.length(), key, 1);
    if(ret != 0)
        QMessageBox::warning(this, "title", "Incorrect password!");
    else
    {

        unsigned char* privatekey = (unsigned char*)calloc(256, sizeof(unsigned char));

        size_t privatekey_lenght;
        generate_keys(privatekey, privatekey_lenght);

        unsigned char new_salt[64];
        unsigned char new_key[32];
        unsigned char new_iv[16];

        generate_salt((unsigned char*)new_salt);
        generate_IV((unsigned char*)new_iv);

        int version = ARGON2_VERSION_10;
        int ret = argon2_hash_without_encoding(2, 1 << 16, 1, password_bytes, password_std.length(), new_salt, 64, new_key, 32, version);
        if(ret != ARGON2_OK)
            exit(-1);
        ret = encrypt_token(new_key, new_iv, new_salt);
        if(ret == -1)
             exit(-1);

        ret = encrypt_key(new_key, new_iv, new_salt, privatekey, privatekey_lenght);
        if(ret == -1)
             exit(-1);

        free(privatekey);
        QMessageBox::warning(this, "title", "Keys updated succesfully!");
        this->close();
    }
}


