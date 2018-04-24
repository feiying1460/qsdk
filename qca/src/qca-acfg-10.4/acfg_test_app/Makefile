CC=$(TOOLPREFIX)gcc

ACFG_BINARY ?= acfg_tool

SRCS=$(shell ls *.c)
OBJS=$(patsubst %.c,%.o,$(SRCS))
PWD=$(shell pwd)

CFLAGS := -I$(PWD)
CFLAGS += -I$(PWD)/../include

ifndef QSDK_ACFG
CFLAGS += -I$(PWD)/../../../include
else
CFLAGS += -I$(WLAN_TOP)/include
endif

CFLAGS += -I$(PWD) -I$(PWD)/../src -Wall -Werror
CFLAGS += -D_GNU_SOURCE
CFLAGS += -L $(PWD)/../src 

all:
	@echo -e "\nBuilding ACFG TESTAPP..."
	$(CC) $(SRCS) $(CFLAGS) $(COPTS) -o $(ACFG_BINARY) -l$(LIB_OUT)

clean:
	@echo -e "\nCleaning ACFG TESTAPP..."
	rm -f $(ACFG_BINARY)
	rm -f $(OBJS)

