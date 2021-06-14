#ifndef OFFLINEENCRYPT_H
#define OFFLINEENCRYPT_H

#include <QMainWindow>

#include "change_password.h"
#include "update_keys.h"
#include "encryptionmenu.h"

namespace Ui {
class OfflineEncrypt;
}

class OfflineEncrypt : public QMainWindow
{
    Q_OBJECT

public:
    explicit OfflineEncrypt(QWidget *parent = 0);
    ~OfflineEncrypt();


private slots:
    void on_change_password_button_clicked();

    void on_update_keys_button_clicked();

    void on_encrypt_button_clicked();

private:
    Ui::OfflineEncrypt *ui;
    Change_Password *change_password;
    update_keys *up_keys;
    EncryptionMenu *menu;
};

#endif // OFFLINEENCRYPT_H
