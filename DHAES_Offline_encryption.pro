#-------------------------------------------------
#
# Project created by QtCreator 2021-06-10T18:41:17
#
#-------------------------------------------------

QT       += core gui
QT       += gui widgets
QMAKE_LFLAGS += -no-pie

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = DHAES_Offline_encryption
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
        main.cpp \
        offlineencrypt.cpp \
    platform_util.c \
    platform.c \
    sha512.c \
    hmac.c \
    aes.c \
    cbc.c \
    gcm.c \
    generators.cpp \
    argon2.c \
    core.c \
    thread.c \
    blake2b.c \
    opt.c \
    change_password.cpp \
    password_functions.cpp \
    update_keys.cpp \
    keys.cpp \
    encryptionmenu.cpp \
    dhaes.cpp

HEADERS += \
        offlineencrypt.h \
    platform_util.h \
    platform.h \
    config.h \
    sha512.h \
    hmac.h \
    aes.h \
    cbc.h \
    gcm.h \
    generators.h \
    argon2.h \
    core.h \
    thread.h \
    blake2-impl.h \
    blake2.h \
    blamka-round-opt.h \
    change_password.h \
    password_functions.h \
    update_keys.h \
    keys.h \
    encryptionmenu.h \
    dhaes.h

FORMS += \
        offlineencrypt.ui \
    change_password.ui \
    update_keys.ui \
    encryptionmenu.ui

RESOURCES += \
    resources.qrc

LIBS += -lgmp
