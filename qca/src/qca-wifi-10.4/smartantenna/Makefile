DEPTH := ../

include $(obj)/$(DEPTH)/os/linux/Makefile-linux.common

obj-m += smart_antenna.o

EXTRA_CFLAGS+= $(INCS) $(COPTS) -Wno-unused-function
