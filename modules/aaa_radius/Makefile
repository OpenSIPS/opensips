#
# radius module makefile
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=aaa_radius.so

ETC_DIR?=../../etc/

# Comment the next two line and uncomment the following two if you want
# to enable Radius support
DEFS+= -I$(LOCALBASE)/include
LIBS=-L$(LOCALBASE)/lib $(RADIUS_LIB)

include ../../Makefile.modules

install_module_custom: $(cfg_prefix)/$(cfg_dir)
	$(INSTALL_TOUCH) \
		$(cfg_prefix)/$(cfg_dir)/dictionary.opensips.sample ; \
	$(INSTALL_CFG) $(ETC_DIR)/dictionary.opensips \
		$(cfg_prefix)/$(cfg_dir)/dictionary.opensips.sample ; \
	if [ ! -f $(cfg_prefix)/$(cfg_dir)/dictionary.opensips ]; then \
		mv -f $(cfg_prefix)/$(cfg_dir)/dictionary.opensips.sample \
			$(cfg_prefix)/$(cfg_dir)/dictionary.opensips; \
	fi; \
