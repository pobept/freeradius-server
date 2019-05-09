ifneq "$(OPENSSL_LIBS)" ""
TARGET := libfreeradius-sim.a
endif

SOURCES	:= \
	comp128.c \
	milenage.c

TGT_PREREQS	:= libfreeradius-util.a
