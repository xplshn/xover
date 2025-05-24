DEBUG_BUILD ?= 0
CC ?= cc

all: xover.so

xover.so: xover.c
	${CC} -DDEBUG_BUILD=$(DEBUG_BUILD) -Wall -pedantic -O2 -shared -fPIC -o $@ $<

clean:
	rm -f xover.so
