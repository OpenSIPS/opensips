# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=pi_http.so

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
