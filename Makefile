DEBUG_BUILD ?= 0
CC ?= cc

all: xover.so

xover.so: override.c
	${CC} -DDEBUG_BUILD=$(DEBUG_BUILD) -S -Wall -pedantic -O2 -shared -fPIC -o $@ $<

clean:
	rm -f xover.so
