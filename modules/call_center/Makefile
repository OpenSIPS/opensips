#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=call_center.so
LIBS= 

include ../../Makefile.modules

CALL_CENTER_SCENARIO ?= scenario_callcenter.xml
CALL_CENTER_AGENT_SCENARIO ?= scenario_callcenter.xml

install_module_custom:
	mkdir -p $(cfg_prefix)/$(cfg_dir); \
	$(INSTALL_TOUCH) $(cfg_prefix)/$(cfg_dir)/`basename $(CALL_CENTER_SCENARIO)`; \
	$(INSTALL_CFG) $(CALL_CENTER_SCENARIO) $(cfg_prefix)/$(cfg_dir)/`basename $(CALL_CENTER_SCENARIO)`; \
	$(INSTALL_TOUCH) $(cfg_prefix)/$(cfg_dir)/`basename $(CALL_CENTER_AGENT_SCENARIO)`; \
	$(INSTALL_CFG) $(CALL_CENTER_AGENT_SCENARIO) $(cfg_prefix)/$(cfg_dir)/`basename $(CALL_CENTER_AGENT_SCENARIO)`; \
