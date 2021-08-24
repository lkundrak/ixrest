PREFIX = /usr/local
MANDIR = $(PREFIX)/man
BINDIR = $(PREFIX)/bin

INSTALL = install

all: ixrest

install: ixrest
	mkdir -p $(DESTDIR)$(BINDIR)
	$(INSTALL) -m755 ixrest $(DESTDIR)$(BINDIR)/ixrest
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -m644 ixrest.1 $(DESTDIR)$(MANDIR)/man1/ixrest.1

clean:
	rm -f ixrest
