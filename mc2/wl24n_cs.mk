# $Id: wl24n_cs.mk,v 1.2 2002/11/04 21:23:56 jal2 Exp $

# Makefile for wl24_cs
#


VERS = 1.51

FILES = \
  wl24n_cs.mk \
	README.wl24n \
  clients/wl24n_cs.mk \
  clients/wl24n.c \
  clients/wl24n.h \
	clients/wl24n_cs.c \
	clients/wl24n_cs.h \
	clients/wl24nfrm.c \
	clients/wl24nfrm.h \
  etc/wl24n_cs.mk \
  etc/AirLancer.conf

all:
	$(MAKE) -C clients -f wl24n_cs.mk WL24_VERSION=$(VERS) $@

install:
	$(MAKE) -C clients install-modules MODULES=wl24_cs.o

inst_etc:
	$(MAKE) -C etc -f wl24n_cs.mk $@

TAGS:
	$(MAKE) -C clients -f wl24n_cs.mk $@

dist:
	tar cvf wl24n_cs-$(VERS).tar $(FILES)

clean:
	$(MAKE) -C clients -f wl24n_cs.mk $@






