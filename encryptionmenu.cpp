#include "encryptionmenu.h"
#include "ui_encryptionmenu.h"
#include "password_functions.h"
#include "gcm.h"
#include "dhaes.h"

#include <QMessageBox>
#include <QFile>
#include <QDir>
#include <QFileDialog>

EncryptionMenu::EncryptionMenu(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::EncryptionMenu)
{
    ui->setupUi(this);
}

EncryptionMenu::~EncryptionMenu()
{
    delete ui;
}

void EncryptionMenu::on_radioButton_clicked()
{
    mode = 1;
}


void EncryptionMenu::on_radioButton_2_clicked()
{
    mode = 0;
}

void EncryptionMenu::on_browseplain_clicked()
{
    QString file_name = QFileDialog::getOpenFileName(this, "Open a file", QDir::homePath());
    //QMessageBox::information(this, "..", file_name);

    QFile file(file_name);
    if(!file.open(QIODevice::ReadOnly))
        QMessageBox::warning(this, "title", "file not open");
    else
    {
        input_file = file_name;
        ui->label_3->setText(file_name);
        file.close();
    }
}

void EncryptionMenu::on_browsekey_clicked()
{
    QString file_name = QFileDialog::getOpenFileName(this, "Open a file", QDir::homePath());
    //QMessageBox::information(this, "..", file_name);

    QFile file(file_name);
    if(!file.open(QIODevice::ReadOnly))
        QMessageBox::warning(this, "title", "file not open");
    else
    {
         key_file = file_name;
         ui->label_5->setText(file_name);
         file.close();
    }
}

void EncryptionMenu::on_browsefolder_clicked()
{
    QString dir = QFileDialog::getExistingDirectory(this, tr("Open Directory"), "/home", QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    QDir directory(dir);
    if(!directory.exists())
        QMessageBox::warning(this, "title", "Directory cannot be opened!");
    else
    {
        output_directory = dir;
        ui->label_7->setText(dir);
    }
}


void EncryptionMenu::on_pushButton_4_clicked()
{
    if(input_file.length() == 0)
        QMessageBox::warning(this, "title", "Please select a file to process!");
    if(key_file.length() == 0)
        QMessageBox::warning(this, "title", "Please select a key!");
    if(output_directory.length() == 0)
        QMessageBox::warning(this, "title", "Please select a destination folder!");

    QString password = ui->lineEdit->text();
    if(password.length() == 0)
        QMessageBox::warning(this, "title", "password field is empty!");
    std::string password_std = password.toUtf8().constData();
    unsigned char* password_bytes = (unsigned char*)calloc(password_std.length(), sizeof(unsigned char));
    for(int i = 0; i < password_std.length(); i++)
        password_bytes[i] = password_std[i];
    unsigned char* aes_key = (unsigned char*)calloc(48, sizeof(unsigned char));
    int ret = check_password(password_bytes, password_std.length(), aes_key, 1);
    printf("cheia aes\n");
    for(int i = 0; i < 48; i++)
        printf("%02x", aes_key[i]);
    printf("\n");

    if(ret == -1)
        QMessageBox::warning(this, "title", "Incorrect password!");
    else
    {
        QMessageBox::warning(this, "title", "Correct password!");
        QFile file(input_file);
        if(!file.open(QIODevice::ReadOnly))
            QMessageBox::warning(this, "title", "file not open");

        QDataStream in_file(&file);
        unsigned char* input = (unsigned char*)calloc(file.size() + 1, sizeof(unsigned char));
        if(input == NULL)
        {
            free(input);
            exit(-1);
        }

        if(in_file.readRawData((char*)input, file.size()) == -1)
        {
            free(input);
            exit(-1);
        }

        int input_length = file.size();
        file.close();

        QFile kfile(key_file);

        if(!kfile.open(QIODevice::ReadOnly))
            QMessageBox::warning(this, "title", "file not open");

        QDataStream k_file(&kfile);

        unsigned char* key = (unsigned char*)calloc(kfile.size() + 1, sizeof(unsigned char));
        if(key == NULL)
        {
            free(input);
            free(key);
            exit(-1);
        }
        if(k_file.readRawData((char*)key, kfile.size()) == -1)
        {
            free(input);
            free(key);
            exit(-1);
        }
        int key_length = kfile.size();
        kfile.close();

        QFile privatefile(QDir::homePath() + "/.OfflineCrypt/private_key");
        if(!privatefile.open(QIODevice::ReadOnly))
            QMessageBox::warning(this, "title", "Private key doesn't exist!");
        QDataStream private_file(&privatefile);

        unsigned char* encrypted_key = (unsigned char*)calloc(privatefile.size(), sizeof(unsigned char));
        if(encrypted_key == NULL)
        {
            free(input);
            free(key);
            free(encrypted_key);
            exit(-1);
        }

        if(private_file.readRawData((char*)encrypted_key, privatefile.size()) == -1)
        {
            free(input);
            free(key);
            free(encrypted_key);
            exit(-1);
        }

        int private_length = privatefile.size();
        privatefile.close();

        input_file = "";
        key_file = "";

        unsigned char* private_key = (unsigned char*)calloc(private_length - 16, sizeof(unsigned char));

        GcmContext ctx;
        gcmInit(&ctx, aes_key);
        printf("\n");
        for(int i = 0; i < 48; i++)
            printf("%02x", aes_key[i]);
        printf("\n");
        int ret = gcmDecrypt(&ctx, aes_key + 32, 16, NULL, 0, encrypted_key, private_key, private_length - 16, encrypted_key + private_length - 16, 16, aes_key);

        if(ret == -1)
        {
            QMessageBox::warning(this, "title", "An error appeared with the key!");
            exit(-1);
        }

        if(mode == 1)
        {
            printf("input length %d", input_length);
            if(input_length % 16 != 0)
            {
                    int remaining = 16 - input_length % 16;
                    int next_divisor = remaining + input_length;
                    unsigned char* padded_input = (unsigned char*)calloc(next_divisor, sizeof(unsigned char));
                    if(padded_input == NULL)
                    {
                        free(input);
                        free(padded_input);
                        free(key);
                        free(private_key);
                        output_directory = "";
                        exit(-1);
                    }
                    memcpy(padded_input, input, input_length);
                    unsigned char* extended_output = (unsigned char*)calloc(next_divisor + 80, sizeof(unsigned char));
                    if(extended_output == NULL)
                    {
                        free(input);
                        free(padded_input);
                        free(extended_output);
                        free(key);
                        free(private_key);
                        output_directory = "";
                        exit(-1);
                    }
                    int r = encrypt_with_keys(padded_input, next_divisor, private_key, private_length - 16, key, key_length, extended_output);
                    printf("\n%d\n", r);
                    if(r == -1)
                        exit(-1);

                    free(input);
                    free(padded_input);
                    free(private_key);
                    free(key);

                    const QString possibleCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
                    const int randomStringLength = 12; // assuming you want random strings of 12 characters

                    QString randomString;
                    for(int i=0; i<randomStringLength; ++i)
                    {
                        int index = qrand() % possibleCharacters.length();
                        QChar nextChar = possibleCharacters.at(index);
                        randomString.append(nextChar);
                    }
                    QString out_file(output_directory);
                    out_file.append('/');
                    out_file.append(randomString);

                    QFile encrypt(out_file);
                    QDataStream out_encrypt(&encrypt);
                    if(encrypt.open(QIODevice::WriteOnly) == false)
                    {
                        free(extended_output);
                        exit(-1);
                    }
                    if(out_encrypt.writeRawData((char*)extended_output, next_divisor + 80) == -1)
                    {
                        free(extended_output);
                        encrypt.close();
                        exit(-1);
                    }
                    encrypt.close();
                    free(extended_output);
                    output_directory = "";
                    ui->label_3->setText("");
                    ui->label_5->setText("");
                    ui->label_7->setText("");
                    ui->lineEdit->setText("");
                    ui->radioButton->setChecked(false);
                    ui->radioButton_2->setChecked(false);
                    QMessageBox::warning(this, "title", "File encrypted succesfully! Check your destination folder!");
            }
            else{

                unsigned char* output = (unsigned char*)calloc(sizeof(unsigned char), input_length + 80);
                if(output == NULL)
                {
                    free(input);
                    free(private_key);
                    free(key);
                    free(output);
                    output_directory = "";
                    exit(-1);
                }

                int r = encrypt_with_keys(input, input_length, private_key, private_length - 16, key, key_length, output);

                if(r == -1)
                    exit(-1);

                free(input);
                free(private_key);
                free(key);

                QString out_file(output_directory);
                const QString possibleCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
                const int randomStringLength = 12; // assuming you want random strings of 12 characters

                QString randomString;
                for(int i=0; i<randomStringLength; ++i)
                {
                    int index = qrand() % possibleCharacters.length();
                    QChar nextChar = possibleCharacters.at(index);
                    randomString.append(nextChar);
                }
                out_file.append('/');
                out_file.append(randomString);
                QFile encrypt(out_file);
                if(encrypt.open(QIODevice::WriteOnly) == false)
                {
                    free(output);
                    exit(-1);
                }

                QDataStream out_encrypt(&encrypt);
                if(out_encrypt.writeRawData((char*)output, input_length + 80) == -1)
                {
                    free(output);
                    encrypt.close();
                    exit(-1);
                }
                encrypt.close();
                free(output);
                output_directory = "";
                ui->label_3->setText("");
                ui->label_5->setText("");
                ui->label_7->setText("");
                ui->lineEdit->setText("");
                ui->radioButton->setChecked(false);
                ui->radioButton_2->setChecked(false);
                QMessageBox::warning(this, "title", "File encrypted succesfully! Check your destination folder!");

            }

        }
        if(mode == 0)
        {
            unsigned char* output = (unsigned char*)calloc(sizeof(unsigned char), input_length - 80);
            if(output == NULL)
            {
                free(input);
                free(output);
                free(private_key);
                free(key);
                output_directory = "";
                exit(-1);
            }
            int r = decrypt_with_keys(input, input_length, private_key, private_length - 16, key, key_length, output);

            if(r == -1)
            {
                free(input);
                free(private_key);
                free(output);
                free(key);
                output_directory = "";
                exit(-1);
            }

            QString randomString;
            const QString possibleCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
            const int randomStringLength = 12; // assuming you want random strings of 12 characters
            for(int i=0; i<randomStringLength; ++i)
            {
                int index = qrand() % possibleCharacters.length();
                QChar nextChar = possibleCharacters.at(index);
                randomString.append(nextChar);
            }
            QString out_file(output_directory);
            out_file.append('/');
            out_file.append(randomString);

            QFile decrypt(out_file);
            if(decrypt.open(QIODevice::WriteOnly) == false)
            {
                free(output);
                output_directory = "";
                exit(-1);
            }

            QDataStream out_decrypt(&decrypt);

            if(out_decrypt.writeRawData((char*)output, input_length - 80) == -1)
            {
                free(output);
                output_directory = "";
                decrypt.close();
                exit(-1);
            }

            decrypt.close();
            free(output);
            output_directory = "";


        }


    }

}
