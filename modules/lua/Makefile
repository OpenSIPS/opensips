# $Id: Makefile,v 1.12 2009/01/20 03:00:05 folays Exp $
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=lua.so

MYSQLCFG=$(shell which mysql_config)
LIB_LUA_NAME?=$(shell \
	if pkg-config --exists lua; then echo lua; \
	elif pkg-config --exists lua5.3; then echo lua5.3; \
	elif pkg-config --exists lua-5.3; then echo lua-5.3; \
	elif pkg-config --exists lua53; then echo lua53; \
	elif pkg-config --exists lua5.2; then echo lua5.2; \
	elif pkg-config --exists lua-5.2; then echo lua-5.2; \
	elif pkg-config --exists lua52; then echo lua52; \
	elif pkg-config --exists lua5.1; then echo lua5.1; \
	elif pkg-config --exists lua-5.1; then echo lua-5.1; \
	elif pkg-config --exists lua51; then echo lua51; fi)

LIB_LUA = $(shell pkg-config --libs $(LIB_LUA_NAME) 2>/dev/null)
FLAGS_LUA = $(shell pkg-config --cflags $(LIB_LUA_NAME) 2>/dev/null)
ifeq (,$(findstring -l,$(LIB_LUA)))
LIB_LUA = -llua
endif
DEFS += $(shell $(MYSQLCFG) --include | sed 's/\(-I.*\)\/mysql/\1/g' ) $(FLAGS_LUA)
LIBS += $(shell $(MYSQLCFG) --libs) -lmemcached $(LIB_LUA)

ifneq ($(CROSS_COMPILE),)
DEFS += -I$(LOCALBASE)/include/memcached
LIBS = -L$(LOCALBASE)/lib $(LIBS)
endif

include ../../Makefile.modules
