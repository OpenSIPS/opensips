# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=regex.so

# set CROSS_COMPILE to true if you want to skip
# the autodetection
# CROSS_COMPILE=true

ifeq ($(CROSS_COMPILE),)
PCRE_BUILDER := $(shell \
	if which pcre2-config >/dev/null 2>/dev/null; then \
		echo 'pcre2-config'; \
	elif pkg-config --exists libpcre2-8; then \
		echo 'pkg-config libpcre2-8'; \
	fi)
endif

ifeq ($(PCRE_BUILDER),)
	DEFS += -I$(SYSBASE)/include \
			-I$(LOCALBASE)/include
	LIBS += -L$(SYSBASE)/lib \
			-L$(LOCALBASE)/lib -lpcre2-8
else
	DEFS += $(shell $(PCRE_BUILDER) --cflags)
	LIBS += $(shell $(PCRE_BUILDER) --libs8)
endif

include ../../Makefile.modules
