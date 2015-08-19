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
	mkdir -p $(modules-prefix)/$(lib-dir)/opensipsctl ; \
	sed -e "s#/usr/local/sbin#$(bin-target)#g" \
		< $(SCRIPTS_DIR)/opensipsctl.sqlite > /tmp/opensipsctl.sqlite ; \
	$(INSTALL_CFG) /tmp/opensipsctl.sqlite \
		$(modules-prefix)/$(lib-dir)/opensipsctl/opensipsctl.sqlite ; \
	rm -fr /tmp/opensipsctl.sqlite ; \
	sed -e "s#/usr/local/share/opensips#$(data-target)#g" \
		< $(SCRIPTS_DIR)/opensipsdbctl.sqlite > /tmp/opensipsdbctl.sqlite ; \
	$(INSTALL_TOUCH) $(modules-prefix)/$(lib-dir)/opensipsctl/opensipsdbctl.sqlite ; \
	$(INSTALL_CFG) /tmp/opensipsdbctl.sqlite $(modules-prefix)/$(lib-dir)/opensipsctl/ ; \
	rm -fr /tmp/opensipsdbctl.sqlite ; \
	mkdir -p $(data-prefix)/$(data-dir)/sqlite ; \
	for FILE in $(wildcard $(SCRIPTS_DIR)/sqlite/*) ; do \
		if [ -f $$FILE ] ; then \
		$(INSTALL_TOUCH) $$FILE \
			$(data-prefix)/$(data-dir)/sqlite/`basename "$$FILE"` ; \
		$(INSTALL_CFG) $$FILE \
			$(data-prefix)/$(data-dir)/sqlite/`basename "$$FILE"` ; \
		fi ;\
	done ; \
