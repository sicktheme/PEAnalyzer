QT       += core gui widgets

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

SOURCES += \
    src/main.cpp \
    src/mainwindow.cpp \
    src/peparser.cpp

HEADERS += \
    src/mainwindow.h \
    src/peparser.h

# FORMS += \
#     mainwindow.ui

RESOURCES += \
    resources/resources.qrc
