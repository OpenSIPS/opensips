# $Id$
#
# perl module makefile
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=perl.so
LIBS=

# define it (or export this) to the dir where xsubpp is on your system (if
# not on the default path.
#PERLBINDIR=

ifeq ($(CC_NAME), gcc)
	DEFS+=-Wno-unused -Wno-redundant-decls
endif
ifeq ($(CC_NAME), clang)
	DEFS+=-Wno-unused -Wno-redundant-decls
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

include ../../Makefile.modules

PODFILES=opensipsxs.xs
PODFILES+=$(shell find lib/perl -name *.pm)

ifeq ($(TYPEMAP),)
	ifeq ($(PERLLIBPATH),)
		PERLLIBPATH=$(shell perl -MConfig -e 'print $$Config{installprivlib}')
	endif
	TYPEMAP=$(PERLLIBPATH)/ExtUtils/typemap
endif

perl.d: opensipsxs.o
perl.o: perl.c opensipsxs.o

opensipsxs.o: opensipsxs.c opensipsxs.d
	$(Q)$(CC) $(MOD_CFLAGS) $(DEFS) -c -o opensipsxs.o opensipsxs.c

opensipsxs.c: opensipsxs.xs typemap
	$(Q)$(PERLBINDIR)xsubpp -typemap $(TYPEMAP) -typemap typemap opensipsxs.xs > opensipsxs.c

clean:	clean-special

.PHONY: clean-special
clean-special:
	-$(Q)rm -f opensipsxs.c opensipsxs.o opensipsxs.d

.PHONY: perlpod
perlpod: doc/perl_pod.sgml

doc/perl_pod.sgml: opensipsxs.xs
	cat $(PODFILES) | pod2docbook --doctype=chapter --title='OpenSIPS Perl API' --no-header - doc/perl_pod.sgml

install_module_custom:
	echo "installing Perl OpenSIPS packages ..."
	mkdir -p $(modules_prefix)/$(lib_dir)/perl
	$(INSTALL_CFG) lib/perl/*.pm $(modules_prefix)/$(lib_dir)/perl
	mkdir -p $(modules_prefix)/$(lib_dir)/perl/OpenSIPS
	$(INSTALL_CFG) lib/perl/OpenSIPS/*.pm \
		$(modules_prefix)/$(lib_dir)/perl/OpenSIPS
	mkdir -p $(modules_prefix)/$(lib_dir)/perl/OpenSIPS/LDAPUtils
	$(INSTALL_CFG) lib/perl/OpenSIPS/LDAPUtils/*.pm \
		$(modules_prefix)/$(lib_dir)/perl/OpenSIPS/LDAPUtils
	mkdir -p $(modules_prefix)/$(lib_dir)/perl/OpenSIPS/Utils
	$(INSTALL_CFG) lib/perl/OpenSIPS/Utils/*.pm \
		$(modules_prefix)/$(lib_dir)/perl/OpenSIPS/Utils
	mkdir -p $(modules_prefix)/$(lib_dir)/perl/OpenSIPS/VDB
	$(INSTALL_CFG) lib/perl/OpenSIPS/VDB/*.pm \
		$(modules_prefix)/$(lib_dir)/perl/OpenSIPS/VDB
	mkdir -p $(modules_prefix)/$(lib_dir)/perl/OpenSIPS/VDB/Adapter
	$(INSTALL_CFG) lib/perl/OpenSIPS/VDB/Adapter/*.pm \
		$(modules_prefix)/$(lib_dir)/perl/OpenSIPS/VDB/Adapter

