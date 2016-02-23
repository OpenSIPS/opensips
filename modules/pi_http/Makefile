# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=pi_http.so

ifeq ($(CROSS_COMPILE),)
XML2CFG=$(shell which xml2-config)
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

include ../../Makefile.modules

install_module_custom:
	echo "installing pi_http framework samples ..."
	mkdir -p $(data_prefix)/$(data_dir)/pi_http
	for FILE in $(wildcard ../../scripts/pi_http/*) ; do \
		if [ -f $$FILE ] ; then \
			$(INSTALL_TOUCH) $$FILE \
				$(data_prefix)/$(data_dir)/pi_http/`basename "$$FILE"` ; \
			$(INSTALL_CFG) $$FILE \
				$(data_prefix)/$(data_dir)/pi_http/`basename "$$FILE"` ; \
		fi ; \
	done

