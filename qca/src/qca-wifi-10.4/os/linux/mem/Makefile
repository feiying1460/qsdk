DEPTH := ../../..

include $(obj)/$(DEPTH)/os/linux/Makefile-linux.common

obj-m += mem_manager.o

EXTRA_CFLAGS+= $(INCS) $(COPTS) -Wno-unused-function
