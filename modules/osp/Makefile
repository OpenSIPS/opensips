
# osp module makefile

# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=osp.so

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

DEFS+=-D_POSIX_THREADS -I$(LOCALBASE)/include
LIBS+=-L$(LOCALBASE)/lib -losptk -lutf8proc -lpthread -lm

include ../../Makefile.modules

install_module_custom:
	echo "OSP module overwrites the default configuration file"
	sed  \
		-e "s#/usr/local/lib/opensips#$(modules_prefix)/$(lib_dir)#g" \
		< etc/sample-osp-opensips.cfg \
		> $(cfg_prefix)/$(cfg_dir)/opensips.cfg.sample

