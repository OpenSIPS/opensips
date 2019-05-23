# $Id$
#
# example module makefile
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

# extra debug messages
DEFS+=-DDBT_EXTRA_DEBUG

SCRIPTS_DIR?=../../scripts/
 
include ../../Makefile.defs
auto_gen=
NAME=db_text.so
LIBS=

include ../../Makefile.modules

install_module_custom: 
	mkdir -p $(data_prefix)/$(data_dir)/dbtext/opensips ; \
	for FILE in $(wildcard $(SCRIPTS_DIR)/dbtext/opensips/*) ; do \
		if [ -f $$FILE ] ; then \
			$(INSTALL_TOUCH) $$FILE \
				$(data_prefix)/$(data_dir)/dbtext/opensips/`basename "$$FILE"` ; \
			$(INSTALL_CFG) $$FILE \
				$(data_prefix)/$(data_dir)/dbtext/opensips/`basename "$$FILE"` ; \
		fi ;\
	done ;\
