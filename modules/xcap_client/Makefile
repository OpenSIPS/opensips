# $Id$
#
# XCAP client for OpenSIPs
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=xcap_client.so

ifeq ($(CROSS_COMPILE),)
XML2CFG=$(shell which xml2-config)
CURL_BUILDER=$(shell \
	if pkg-config --exists libcurl; then \
		echo 'pkg-config libcurl'; \
	else \
		which curl-config; \
	fi)
endif

ifneq ($(XML2CFG),)
	DEFS += $(shell $(XML2CFG) --cflags)
	LIBS += $(shell $(XML2CFG) --libs)
else
	DEFS += -I$(SYSBASE)/include/libxml2 \
			-I$(LOCALBASE)/include/libxml2 \
			-I$(LOCALBASE)/include
	LIBS += -L$(SYSBASE)/include/lib \
			-L$(LOCALBASE)/lib -lxml2
endif

ifneq ($(CURL_BUILDER),)
	DEFS += $(shell $(CURL_BUILDER) --cflags)
	LIBS += $(shell $(CURL_BUILDER) --libs)
else
	DEFS += -I$(SYSBASE)/include -I$(LOCALBASE)/include
	LIBS += -L$(SYSBASE)/include -L$(LOCALBASE)/lib -lcurl
endif

include ../../Makefile.modules

