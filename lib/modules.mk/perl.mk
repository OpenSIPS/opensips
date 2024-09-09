# define it (or export this) to the dir where xsubpp is on your system (if
# not on the default path.
#PERLBINDIR=

ifeq ($(CC_NAME), gcc)
	DEFS+=-Wno-unused -Wno-redundant-decls
endif
ifeq ($(CC_NAME), clang)
	DEFS+=-Wno-unused -Wno-redundant-decls $(shell test `${CC} -dumpversion | sed 's|[.].*||'` -gt 11 && echo -Wno-compound-token-split-by-macro)
endif

ifeq ($(PERLLDOPTS),)
	LIBS+=$(shell perl -MExtUtils::Embed -e ldopts)
else
	LIBS+=$(PERLLDOPTS)
endif

ifeq ($(PERLCCOPTS),)
	DEFS+=$(shell perl -MExtUtils::Embed -e ccopts)
else
	DEFS+=$(PERLCCOPTS)
endif

# if perl requires _FORTIFY_SOURCE, we need to enable optimizations
ifneq (,$(findstring -D_FORTIFY_SOURCE,$(DEFS)))
	DEFS+=-O2
endif

auto_gen=

include ../../Makefile.modules
