# $Id$
#
# registrar module makefile
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=registrar.so
LIBS=

REG_LIB_DIR = ../../lib/reg
_SRC=ci.c regtime.c rerrno.c sip_msg.c path.c
extra_sources=$(patsubst %,$(REG_LIB_DIR)/%,$(_SRC))

include ../../Makefile.modules
