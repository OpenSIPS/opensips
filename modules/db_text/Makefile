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
	mkdir -p $(modules-prefix)/$(lib-dir)/opensipsctl ; \
	sed -e "s#/usr/local/share/opensips/#$(data-target)#g" \
		< $(SCRIPTS_DIR)/opensipsctl.dbtext > /tmp/opensipsctl.dbtext ; \
	$(INSTALL_CFG) /tmp/opensipsctl.dbtext \
		$(modules-prefix)/$(lib-dir)/opensipsctl/opensipsctl.dbtext ; \
	rm -fr /tmp/opensipsctl.dbtext ; \
	sed -e "s#/usr/local/share/opensips#$(data-target)#g" \
		< $(SCRIPTS_DIR)/opensipsdbctl.dbtext > /tmp/opensipsdbctl.dbtext ; \
	$(INSTALL_TOUCH) $(modules-prefix)/$(lib-dir)/opensipsctl/opensipsdbctl.dbtext ; \
	$(INSTALL_CFG) /tmp/opensipsdbctl.dbtext $(modules-prefix)/$(lib-dir)/opensipsctl/ ; \
	rm -fr /tmp/opensipsdbctl.dbtext ; \
	mkdir -p $(modules-prefix)/$(lib-dir)/opensipsctl/dbtextdb ; \
	$(INSTALL_TOUCH) $(modules-prefix)/$(lib-dir)/opensipsctl/dbtextdb/dbtextdb.py ; \
	$(INSTALL_BIN) $(SCRIPTS_DIR)/dbtextdb/dbtextdb.py $(modules-prefix)/$(lib-dir)/opensipsctl/dbtextdb/ ; \
	mkdir -p $(data-prefix)/$(data-dir)/dbtext/opensips ; \
	for FILE in $(wildcard $(SCRIPTS_DIR)/dbtext/opensips/*) ; do \
		if [ -f $$FILE ] ; then \
			$(INSTALL_TOUCH) $$FILE \
				$(data-prefix)/$(data-dir)/dbtext/opensips/`basename "$$FILE"` ; \
			$(INSTALL_CFG) $$FILE \
				$(data-prefix)/$(data-dir)/dbtext/opensips/`basename "$$FILE"` ; \
		fi ;\
	done ;\
