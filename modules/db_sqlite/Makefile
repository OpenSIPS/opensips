# $Id$
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=db_sqlite.so

SCRIPTS_DIR?=../../scripts/

LIBS+=-lsqlite3

include ../../Makefile.modules

install_module_custom: 
	mkdir -p $(data_prefix)/$(data_dir)/sqlite ; \
	for FILE in $(wildcard $(SCRIPTS_DIR)/sqlite/*) ; do \
		if [ -f $$FILE ] ; then \
		$(INSTALL_TOUCH) $$FILE \
			$(data_prefix)/$(data_dir)/sqlite/`basename "$$FILE"` ; \
		$(INSTALL_CFG) $$FILE \
			$(data_prefix)/$(data_dir)/sqlite/`basename "$$FILE"` ; \
		fi ;\
	done ; \
