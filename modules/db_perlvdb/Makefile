# $Id$
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=perlvdb.so

ifeq ($(CC_NAME), gcc)
	DEFS+=-Wno-unused -Wno-redundant-decls
endif


LIBS=$(shell perl -MExtUtils::Embed -e ldopts)
DEFS+=$(shell perl -MExtUtils::Embed -e ccopts)


include ../../Makefile.modules
