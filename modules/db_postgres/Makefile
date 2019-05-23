# $Id$
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=db_postgres.so

SCRIPTS_DIR?=../../scripts/

# set CROSS_COMPILE to true if you want to skip
# the autodetection
# CROSS_COMPILE=true

ifeq ($(CROSS_COMPILE),)
HAS_PGCFG=$(shell if which pg_config >/dev/null 2>/dev/null;then echo YES; fi)
endif


ifeq ($(HAS_PGCFG),YES)

	# use autodetection
	DEFS += -I$(shell pg_config --includedir)
	LIBS = -L$(shell pg_config --libdir) -lpq

else

	# use standard know paths
	# libpq-fe.h locations
	DEFS +=-I$(LOCALBASE)/include -I$(LOCALBASE)/pgsql/include \
		 -I$(SYSBASE)/include/pgsql -I$(SYSBASE)/include/postgresql \
		 -I$(SYSBASE)/include/postgresql/8.0 -I$(SYSBASE)/postgres/8.4/include
	LIBS=-L$(LOCALBASE)/lib -L$(LOCALBASE)/pgsql/lib -L$(LOCALBASE)/lib/pgsql \
		 -lpq

endif

include ../../Makefile.modules

install_module_custom: 
	mkdir -p $(data_prefix)/$(data_dir)/postgres ; \
	for FILE in $(wildcard $(SCRIPTS_DIR)/postgres/*) ; do \
		if [ -f $$FILE ] ; then \
		$(INSTALL_TOUCH) $$FILE \
			$(data_prefix)/$(data_dir)/postgres/`basename "$$FILE"` ; \
		$(INSTALL_CFG) $$FILE \
			$(data_prefix)/$(data_dir)/postgres/`basename "$$FILE"` ; \
		fi ;\
	done ; \
