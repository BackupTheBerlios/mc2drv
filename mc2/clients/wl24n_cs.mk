# $Id: wl24n_cs.mk,v 1.5 2004/02/29 23:19:25 jal2 Exp $

# ===========================================================    
#    Copyright (C) 2002 Joerg Albert - joerg.albert@gmx.de
#    Copyright (C) 2002 Alfred Arnold alfred@ccac.rwth-aachen.de
#
#    Portions of the source code are based on code by
#    David A. Hinds under Copyright (C) 1999 David A. Hinds
#    and on code by Jean Tourrilhes under
#    Copyright (C) 2001 Jean Tourrilhes, HP Labs <jt@hpl.hp.com> 
#
#    This software may be used and distributed according to the
#    terms of the GNU Public License 2, incorporated herein by
#    reference.
#   =========================================================== */

#
# Makefile for wl24_cs
#

include ../config.mk

LIB := ../lib

CFLAGS = -O2 -Wall -Wstrict-prototypes -Winline -pipe -fno-strict-aliasing

# WL24_VERSION comes from above
CPPFLAGS = $(PCDEBUG) -D__KERNEL__ -DMODULE -I../include \
	   -I$(LINUX)/include -I$(LINUX) -DWL24_VERSION=\"$(WL24_VERSION)\"

.SUFFIXES: .c .o .i
.c.o:
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

.c.i:
	$(CC) -c $(CFLAGS) $(CPPFLAGS) -E $< -o $@


all: wl24_cs.o

wl24n.o: wl24n.h wl24n_cs.h wl24nfrm.h
wl24n_cs.o: wl24n_cs.h wl24n.h

wl24_cs.o: wl24n_cs.o wl24n.o wl24nfrm.o
	$(LD) -r -o $@ $^

TAGS: wl24n_cs.c wl24n.c wl24nfrm.c wl24n.h wl24n_cs.h wl24nfrm.h
	etags $^

clean:
	-rm wl24n_cs.o wl24_cs.o wl24n.o wl24nfrm.o
