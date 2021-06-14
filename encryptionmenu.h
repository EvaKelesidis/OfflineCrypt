#ifndef ENCRYPTIONMENU_H
#define ENCRYPTIONMENU_H

#include <QMainWindow>

namespace Ui {
class EncryptionMenu;
}

class EncryptionMenu : public QMainWindow
{
    Q_OBJECT

public:
    explicit EncryptionMenu(QWidget *parent = 0);
    ~EncryptionMenu();

private slots:
    void on_radioButton_clicked();

    void on_radioButton_2_clicked();

    void on_browseplain_clicked();

    void on_browsekey_clicked();

    void on_browsefolder_clicked();

    void on_pushButton_4_clicked();

private:
    Ui::EncryptionMenu *ui;
    QString input_file;
    QString key_file;
    QString output_directory;
    int mode;
};

#endif // ENCRYPTIONMENU_H
