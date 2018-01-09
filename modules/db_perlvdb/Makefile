# $Id$
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=db_perlvdb.so

ifeq ($(CC_NAME), gcc)
	DEFS+=-Wno-unused -Wno-redundant-decls
endif


LIBS=$(shell perl -MExtUtils::Embed -e ldopts)
DEFS+=$(shell perl -MExtUtils::Embed -e ccopts)

# if perl requires _FORTIFY_SOURCE, we need to enable optimizations
ifneq (,$(findstring -D_FORTIFY_SOURCE,$(DEFS)))
	DEFS+=-O2
endif


include ../../Makefile.modules
