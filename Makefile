SONAME=cygspawn
DLLNAME=cyg$(SONAME).dll
IMPLIBNAME=lib$(SONAME).a

CFLAGS=-O0 -Wall -g
override CFLAGS+=-std=gnu99

all: $(DLLNAME) $(IMPLIBNAME) listvma testspawn

cygspawn.o: cygspawn.c cygspawn.h

listvma: LDLIBS+=-lpsapi
listvma: listvma.o

testspawn: $(IMPLIBNAME)

$(DLLNAME) $(IMPLIBNAME): cygspawn.o
	gcc -shared -o $(DLLNAME) \
	    $(CPPFLAGS) $(CFLAGS) \
	    -Wl,--out-implib=$(IMPLIBNAME) \
	    -Wl,--export-all-symbols \
	    -Wl,--enable-auto-import \
	    -Wl,--no-whole-archive $+

clean:
	rm -f *.dll *.a *.o *.exe *.stackdump
