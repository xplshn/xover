DEBUG_BUILD ?= 0
CC ?= cc

all: libfopen_override.so

libfopen_override.so: override.c
	${CC} -DDEBUG_BUILD=$(DEBUG_BUILD) -S -Wall -pedantic -O2 -shared -fPIC -o $@ $<

clean:
	rm -f libfopen_override.so
