
# osp module makefile

# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=osp.so
DEFS+=-D_POSIX_THREADS -I$(LOCALBASE)/include
LIBS=-L$(LOCALBASE)/lib -losptk -lssl -lcrypto -lpthread -lm

include ../../Makefile.modules

install_module_custom: 
	echo "OSP module overwrites the default configuration file"
	sed  \
		-e "s#/usr/local/lib/opensips#$(modules-prefix)/$(lib-dir)#g" \
		< etc/sample-osp-opensips.cfg \
		> $(cfg-prefix)/$(cfg-dir)/opensips.cfg

