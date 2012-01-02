SONAME=cygspawn

prefix=/usr/local
includedir=$(prefix)/include
exec_prefix=$(prefix)
bindir=$(exec_prefix)/bin
libdir=$(exec_prefix)/lib

DLLNAME=cyg$(SONAME).dll
IMPLIBNAME=lib$(SONAME).a

INSTALL=install -D
INSTALL_PROGRAM=$(INSTALL) -s
INSTALL_DATA=$(INSTALL) -m 0644

CFLAGS=-Os -Wall -g -Werror
CFLAGS+= -DNDEBUG -Wno-unused-value
override CFLAGS+=-std=gnu99

.PHONY: all
all: $(DLLNAME) $(IMPLIBNAME) listvma testspawn.exe testfork.exe

cygspawn.o: cygspawn.c cygspawn.h

listvma: LDLIBS+=-lpsapi
listvma: listvma.o

testspawn.exe: testspawn.c $(IMPLIBNAME)
	$(CC) $(CFLAGS) -o $@ $+ $(LDFLAGS) $(LDLIBS)

testfork.exe: override CFLAGS+=-DUSE_FORK
testfork.exe: testspawn.c
	$(CC) $(CFLAGS) -o $@ $+ $(LDLIBS)

$(DLLNAME) $(IMPLIBNAME): cygspawn.o cygspawn.def
	gcc -shared -o $(DLLNAME) $(CFLAGS) \
	    -Wl,--out-implib=$(IMPLIBNAME) \
	    -Wl,--enable-auto-import \
	    -Wl,--no-whole-archive $+

.PHONY: clean
clean:
	rm -f *.dll *.a *.o *.exe *.stackdump

.PHONY: install
install: $(DLLNAME) $(IMPLIBNAME) cygspawn.h
	$(INSTALL_PROGRAM) $(DLLNAME) $(DESTDIR)$(bindir)/$(DLLNAME)
	$(INSTALL_DATA) $(IMPLIBNAME) $(DESTDIR)$(libdir)/$(IMPLIBNAME)
	$(INSTALL_DATA) cygspawn.h $(DESTDIR)$(includedir)/spawn.h

.DEFAULT_GOAL=all
