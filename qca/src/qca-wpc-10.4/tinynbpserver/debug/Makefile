INCLUDE = -I ../include -I ../../../qca-wifi-10.4/os/linux/include/

all:
	gcc $(DEBUG) -c dump.c $(INCLUDE) `pkg-config  --libs --cflags gtk+-2.0`
	gcc $(DEBUG) -c err.c $(INCLUDE) `pkg-config  --libs --cflags gtk+-2.0`

clean:
	rm -f *.o
