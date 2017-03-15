#
# print example module makefile
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=cgrates.so

ifeq ($(CROSS_COMPILE),)
JSON_BUILDER = $(shell \
	if pkg-config --exists json; then \
		echo 'pkg-config json'; \
	elif pkg-config --exists json-c; then\
		echo 'pkg-config json-c'; \
	fi)

endif

ifeq ($(JSON_BUILDER),)
	DEFS += -I$(LOCALBASE)/include -I$(SYSBASE)/include
	LIBS += -L$(LOCALBASE)/lib -ljson
else
	JSON_LIB_VER = $(shell $(JSON_BUILDER) --modversion | sed  "s/\.\([0-9]\)\./.0\1./g" | sed  "s/\.\([0-9]\)\$$/.0\1/g" | tr -d "." | sed -e "s/^0*//" )
	DEFS += $(shell $(JSON_BUILDER) --cflags) -DJSON_LIB_VERSION=$(JSON_LIB_VER)
	LIBS += $(shell $(JSON_BUILDER) --libs)
endif

include ../../Makefile.modules

