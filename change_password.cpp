#include <QMessageBox>

#include "change_password.h"
#include "ui_change_password.h"
#include "password_functions.h"

Change_Password::Change_Password(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::Change_Password)
{
    ui->setupUi(this);
}

Change_Password::~Change_Password()
{
    delete ui;
}

void Change_Password::on_Ok_button_clicked()
{
    QString old_password = ui->old_line->text();
    QString new_password = ui->new_line->text();
    QString confirm_password = ui->conf_line->text();

    if(old_password.length() == 0)
        QMessageBox::warning(this, "title", "old password field is empty");
    if(new_password.length() == 0)
        QMessageBox::warning(this, "title", "new password field is empty");
    if(confirm_password.length() == 0)
        QMessageBox::warning(this, "title", "please confirm your password");

    std::string old_password_std = old_password.toUtf8().constData();
    std::string new_password_std = new_password.toUtf8().constData();
    std::string confirm_password_std = confirm_password.toUtf8().constData();

    unsigned char* bytes_old_password = (unsigned char*)calloc(old_password_std.length(), sizeof(unsigned char));
    if(bytes_old_password == NULL){
        free(bytes_old_password);
        exit(-1);
    }
    for(int i = 0; i < old_password.length(); i++)
        bytes_old_password[i] = old_password_std[i];

    unsigned char *key = (unsigned char*)calloc(32, sizeof(unsigned char));
    int ret = check_password(bytes_old_password, old_password_std.length(), key, 0);

    if(ret == 0)
        QMessageBox::warning(this, "title", "password is good!");
    else
        QMessageBox::warning(this, "title", "wrong password!");

    if(ret == 0)
    {
        if(new_password_std.length() != confirm_password.length())
            QMessageBox::warning(this, "title", "passwords do not match!");
        else
        {
            int upper = 0;
            int lower = 0;
            int digit = 0;
            int symbol = 0;
            if(new_password_std.length() < 12)
                QMessageBox::warning(this, "title", "password must have at least 12 characters!");
            else
            {
                for(const auto& character : new_password){
                    if(character.isUpper()){
                        upper++;
                    }
                    else if (character.isLower()){
                        lower++;
                    }
                    else if (character.isDigit()){
                        digit++;
                    }
                    else{
                        symbol++;
                    }

                }
                if(upper < 1 || lower < 1 || digit < 1 || symbol < 1)
                    QMessageBox::warning(this, "title", "password must have at a lowercase letter, an uppercase letter, a digit and a symbol!");
                else
                {
                    int ok = 1;
                    for(int i = 0; i < new_password_std.length(); i++)
                        if(new_password_std[i] != confirm_password_std[i])
                            ok = 0;
                    if(ok == 0)
                         QMessageBox::warning(this, "title", "passwords do not match!");
                    else
                    {
                          unsigned char* new_password_bytes = (unsigned char*)calloc(new_password_std.length(), sizeof(unsigned char));
                          for(int i = 0; i < new_password_std.length(); i++)
                              new_password_bytes[i] = new_password_std[i];
                          ret = update_password(new_password_bytes, new_password_std.length());
                          if(ret == 0)
                              QMessageBox::warning(this, "title", "Password updated successfully!");
                          else
                              QMessageBox::warning(this, "title", "An error encoutered while updating the password. Please try again!");

                          this->close();
                    }
                }
            }
        }
    }
}
