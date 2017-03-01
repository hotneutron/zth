COMMON=mbox util zth_x64
ZTH=$(COMMON) zth
ZTH_TEST=$(COMMON) zth_test

CC=gcc 
AR=ar
CFLAGS=-Wall -g -Werror
LDFLAGS=-lpthread -ldl -lm
LIBOBJS=$(patsubst %,%.o,$(ZTH))
TESTOBJS=$(patsubst %,%.o,$(ZTH_TEST))

all: zth.a zth_test

zth.a: $(LIBOBJS)
	$(AR) -r $@ $^

zth_test: $(TESTOBJS)
	$(CC) $(LDFLAGS) $^ -o $@

zth_test.o: zth.c $(HEADERS)
	$(CC) -DZTH_TEST $(CFLAGS) -c $< -o $@

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -rf *.o *.a zth_test
