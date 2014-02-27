SXE_DEBUG = 0
CFLAGS    = -I. -DSXE_DEBUG=$(SXE_DEBUG) -g -O9 -rdynamic -fstack-protector -fno-strict-aliasing -Wall -Werror -Wextra -Wcast-align -Wcast-qual -Wformat=2 -Wformat-security -Wmissing-prototypes -Wpointer-arith -Wredundant-decls -Wshadow -Wstrict-prototypes -Wno-unknown-pragmas -Wunused -Wno-unused-result -Wwrite-strings -Wno-attributes
CPPFLAGS  = -I../exs-util -I../Option-Parse -I../libev/libev-4.15/
LDLIBS    = -lm

all: packet-shuffler

packet-shuffler: packet-shuffler.o ../Option-Parse/option-parse.o  ../exs-util/exs-util.a ../libev/libev-4.15/.libs/libev.a

debug: SXE_DEBUG = 1
debug: clean all

.PHONY: clean

clean:
	rm -f *.o packet-shuffler
