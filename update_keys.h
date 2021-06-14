#ifndef UPDATE_KEYS_H
#define UPDATE_KEYS_H

#include <QMainWindow>

namespace Ui {
class update_keys;
}

class update_keys : public QMainWindow
{
    Q_OBJECT

public:
    explicit update_keys(QWidget *parent = 0);
    ~update_keys();

private slots:
    void on_pushButton_clicked();

private:
    Ui::update_keys *ui;
};

#endif // UPDATE_KEYS_H
