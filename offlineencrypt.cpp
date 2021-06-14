#include "offlineencrypt.h"
#include "ui_offlineencrypt.h"
#include "change_password.h"
#include "update_keys.h"
#include "encryptionmenu.h"

#include <QPixmap>

OfflineEncrypt::OfflineEncrypt(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::OfflineEncrypt)
{
    ui->setupUi(this);
    QPixmap pix(":/img/img/key.png");
    ui->label_pic->setPixmap(pix.scaled(100, 100, Qt::KeepAspectRatio));
}

OfflineEncrypt::~OfflineEncrypt()
{
    delete ui;
}



void OfflineEncrypt::on_change_password_button_clicked()
{
    change_password = new Change_Password();
    change_password->show();
}

void OfflineEncrypt::on_update_keys_button_clicked()
{
    up_keys = new update_keys();
    up_keys->show();
}


void OfflineEncrypt::on_encrypt_button_clicked()
{
    menu = new EncryptionMenu();
    menu->show();
}
