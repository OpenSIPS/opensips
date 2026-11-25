#
# cachedb_perfd - perfcached client through libperfd
#
# WARNING: do not run this directly, it should be run by the master Makefile
#
# libperfd (0.7.6.1 or later) is linked, never compiled in: install
# libperfd-dev, or run `make install-lib` in perfcached; pkg-config finds it.
# PERFD_STATIC=1 links libperfd.a instead of libperfd.so; PKG_CONFIG_PATH
# points at a libperfd in another prefix.
include ../../Makefile.defs

ifeq ($(shell pkg-config --atleast-version=0.7.6.1 libperfd && echo yes),)
$(info [skip] cachedb_perfd.so - libperfd 0.7.6.1 or later not detected (install libperfd-dev, or `make install-lib` in perfcached and set PKG_CONFIG_PATH))
.PHONY: all clean install modules
all clean install modules: ; @true
else

auto_gen=
NAME=cachedb_perfd.so

DEFS+=$(shell pkg-config --cflags libperfd)
ifeq ($(PERFD_STATIC),1)
LIBS+=$(shell pkg-config --variable=libdir libperfd)/libperfd.a -lsodium -lpthread
else
LIBS+=$(shell pkg-config --libs libperfd)
endif

include ../../Makefile.modules

endif
