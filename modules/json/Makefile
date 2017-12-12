#
# Json object manipulation
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=json.so

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
	JSON_PKG_VER = $(shell $(JSON_BUILDER) --modversion)
	JSON_PKG_MAJOR = $(shell \
		ver_tmp=`echo '$(JSON_PKG_VER)' | cut -f1 -d.`; \
		if [ -z "$$ver_tmp" ]; then ver_tmp=0; fi; \
		echo "$$ver_tmp";)
	JSON_PKG_MINOR = $(shell \
		ver_tmp=`echo '$(JSON_PKG_VER)' | cut -f2 -d.`; \
		if [ -z "$$ver_tmp" ]; then ver_tmp=0; fi; \
		echo "$$ver_tmp";)
	JSON_PKG_MICRO = $(shell \
		ver_tmp=`echo '$(JSON_PKG_VER)' | cut -f3 -d.`; \
		if [ -z "$$ver_tmp" ]; then ver_tmp=0; fi; \
		echo "$$ver_tmp";)
	DEFS += $(shell $(JSON_BUILDER) --cflags) \
		-DJSON_PKG_MAJOR=$(JSON_PKG_MAJOR) \
		-DJSON_PKG_MINOR=$(JSON_PKG_MINOR) \
		-DJSON_PKG_MICRO=$(JSON_PKG_MICRO)
	LIBS += $(shell $(JSON_BUILDER) --libs)
endif

include ../../Makefile.modules
