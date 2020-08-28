BINDIR = /usr/bin
PROG = tcpshow

tcpshow : tcpshow.c
	gcc tcpshow.c -Wall -O3 -o tcpshow -lpcap -lm

install:
	cp $(PROG) $(BINDIR)/$(PROG)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(PROG)
