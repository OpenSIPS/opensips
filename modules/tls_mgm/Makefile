#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=tls_mgm.so

ETC_DIR?=../../etc/

tls_configs=$(patsubst $(ETC_DIR)/%, %, $(wildcard $(ETC_DIR)/tls/*) \
		$(wildcard $(ETC_DIR)/tls/rootCA/*) $(wildcard $(ETC_DIR)/tls/rootCA/certs/*) \
		$(wildcard $(ETC_DIR)/tls/rootCA/private/*) $(wildcard $(ETC_DIR)/tls/user/*))


ifeq ($(CROSS_COMPILE),)
SSL_BUILDER=$(shell \
	if pkg-config --exists libssl; then \
		echo 'pkg-config libssl'; \
	fi)
endif

ifneq ($(SSL_BUILDER),)
	DEFS += $(shell $(SSL_BUILDER) --cflags)
	LIBS += $(shell $(SSL_BUILDER) --libs)
else
	DEFS += -I$(LOCALBASE)/ssl/include \
			-I$(LOCALBASE)/include
	LIBS += -L$(LOCALBASE)/lib -L$(LOCALBASE)/ssl/lib \
			-L$(LOCALBASE)/lib64 -L$(LOCALBASE)/ssl/lib64 \
			-lssl -lcrypto
endif

include ../../Makefile.modules

install_module_custom: 
	mkdir -p $(cfg_prefix)/$(cfg_dir)/tls ; \
	mkdir -p $(cfg_prefix)/$(cfg_dir)/tls/rootCA ; \
	mkdir -p $(cfg_prefix)/$(cfg_dir)/tls/rootCA/certs ; \
	mkdir -p $(cfg_prefix)/$(cfg_dir)/tls/rootCA/private ; \
	mkdir -p $(cfg_prefix)/$(cfg_dir)/tls/user ; \
	for FILE in $(tls_configs) ; do \
		if [ -f $(ETC_DIR)/$$FILE ]; then \
			if [ "$(tls_overwrite_certs)" != "" -o \
					 ! -f $(cfg_prefix)/$(cfg_dir)/$$FILE ] ; then \
				$(INSTALL_TOUCH) $(ETC_DIR)/$$FILE \
					$(cfg_prefix)/$(cfg_dir)/$$FILE ; \
				$(INSTALL_CFG) $(ETC_DIR)/$$FILE \
					$(cfg_prefix)/$(cfg_dir)/$$FILE ; \
			fi; \
		fi ;\
	done ; \
