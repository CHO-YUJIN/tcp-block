TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        iphdr.cpp \
        mac.cpp \
        main.cpp \
        tcphdr.cpp

HEADERS += \
    arphdr.h \
    ethhdr.h \
    ip.h \
    iphdr.h \
    mac.h \
    tcphdr.h
