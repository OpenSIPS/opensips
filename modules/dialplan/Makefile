# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=dialplan.so

# set CROSS_COMPILE to true if you want to skip
# the autodetection
# CROSS_COMPILE=true

PCRE_LIB ?= pcre2-8
PCRE_VERSION ?= $(word 1,$(subst -, , $(PCRE_LIB)))
PCRE_CONFIG ?= $(PCRE_VERSION)-config

ifeq ($(CROSS_COMPILE),)
PCRE_BUILDER := $(shell \
	if which $(PCRE_CONFIG) >/dev/null 2>/dev/null; then \
		echo '$(PCRE_CONFIG)'; \
	elif pkg-config --exists lib$(PCRE_LIB); then \
		echo 'pkg-config lib$(PCRE_LIB)'; \
	fi)
endif

ifeq ($(PCRE_BUILDER),)
	DEFS += -I$(SYSBASE)/include \
			-I$(LOCALBASE)/include
	LIBS += -L$(SYSBASE)/lib \
			-L$(LOCALBASE)/lib -l$(PCRE_LIB)
else
	DEFS += $(shell $(PCRE_BUILDER) --cflags)
	LIBS += $(shell $(PCRE_BUILDER) --libs 2>/dev/null) \
			$(shell $(PCRE_BUILDER) --libs$(word 2,$(subst -, ,$(PCRE_LIB))) 2>/dev/null)
endif
DEFS += -D$(shell echo $(PCRE_VERSION) | tr 'a-z' 'A-Z')_LIB

include ../../Makefile.modules
