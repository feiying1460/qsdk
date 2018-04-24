CC=$(TOOLPREFIX)gcc
AR=$(TOOLPREFIX)ar

CFLAGS += -I$(PWD)/../include

ifndef QSDK_ACFG
CFLAGS += -I$(PWD)/../../../include
else
CFLAGS += -I$(WLAN_TOP)/include
endif

CFLAGS += -I$(PWD)
CFLAGS += -MMD
CFLAGS += -Wall -O2 -Wsign-compare -Wpointer-sign -Wunused-parameter -Wtype-limits -Wmissing-field-initializers -Wunused-variable -Wstrict-aliasing -Wtype-limits -Wuninitialized -Werror -g
CFLAGS += -D_GNU_SOURCE

ifeq ($(strip ${ACFG_PARTIAL_OFFLOAD}),1)
CFLAGS += -DACFG_PARTIAL_OFFLOAD
endif

OBJ_OUT=acfg_api.o
LIB_OUT=acfg
LIB_TYPE=rcs
ACFG_BINARY=acfg_tool
ACFG_LIB=libacfg.a
ACFG_TEST_DIR=../acfg_test_app
ACFG_CONF_FILE=acfg_sample.conf

FILES=$(shell ls *.c)
OBJS=$(patsubst %.c,%.o,$(FILES))

%.o: %.c
	$(CC) -c $(CFLAGS) $(COPTS) $< -o $@

export LIB_OUT ACFG_BINARY

all: $(OBJS)
#$(CC) $(CFLAGS) -c $(FILES) -o $(OBJ_OUT)
#$(AR) $(LIB_TYPE) $(ACFG_LIB) $(OBJ_OUT) 
	$(AR) $(LIB_TYPE) $(ACFG_LIB) $(OBJS)
	make -C $(ACFG_TEST_DIR) all 

install:
	-cp -v $(ACFG_LIB) $(DESTDIR)/lib
	-cp -v $(ACFG_TEST_DIR)/$(ACFG_BINARY) $(DESTDIR)/sbin
	-cp -v $(ACFG_TEST_DIR)/$(ACFG_CONF_FILE) $(DESTDIR)/etc
	-cp -v acfg_common.conf $(DESTDIR)/etc


clean:
	rm -rvf *.o *.a
	make -C $(ACFG_TEST_DIR) clean
    
