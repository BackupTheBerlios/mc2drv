#
# Makefile for wavelan2_cs
#

include ../config.mk

ETC = $(PREFIX)/etc/pcmcia

all:

install:
  
	cp --backup=numbered AirLancer.conf $(ETC)/AirLancer.conf

clean:

