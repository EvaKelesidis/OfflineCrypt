#ifndef CHANGE_PASSWORD_H
#define CHANGE_PASSWORD_H

#include <QMainWindow>

namespace Ui {
class Change_Password;
}

class Change_Password : public QMainWindow
{
    Q_OBJECT

public:
    explicit Change_Password(QWidget *parent = 0);
    ~Change_Password();

private slots:
    void on_Ok_button_clicked();

private:
    Ui::Change_Password *ui;
};

#endif // CHANGE_PASSWORD_H
