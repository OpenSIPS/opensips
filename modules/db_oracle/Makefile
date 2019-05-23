# $Id$
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=db_oracle.so

SCRIPTS_DIR?=../../scripts/
UTILS_DIR?=../../utils/

# can be defined for non standard placement of oracle so's
ORAPATH=
LIBS=

# use for multiple client sdk version install
ifneq ($(ORAVERSION),)
    ORAVERDIR=/$(ORAVERSION)
endif

# use include/library path's for full client installation
ifneq ($(ORAHOME),)
    DEFS +=-I$(ORAHOME)/include
    LIBS +=-L$(ORAHOME)/lib
ifeq ($(ORAPATH),)
    ORAPATH=$(ORAHOME)/lib
endif
else
# use standard know paths oci.h locations (linux)
DEFS +=-I$(LOCALBASE)/include/oracle$(ORAVERDIR) \
    -I$(SYSBASE)/include/oracle$(ORAVERDIR)
endif

# search 'so' path if it non standard (possible liboclntsh locations on linux)
ifeq ($(ORAPATH),)
    ORAPATH=$(shell [ -f $(LOCALBASE)/lib64/oracle$(ORAVERDIR)/libocci.so ] && \
	    echo $(LOCALBASE)/lib64/oracle$(ORAVERDIR) )
endif
ifeq ($(ORAPATH),)
    ORAPATH=$(shell [ -f $(SYSBASE)/lib64/oracle$(ORAVERDIR)/libocci.so ] && \
	    echo $(SYSBASE)/lib64/oracle$(ORAVERDIR) )
endif
ifeq ($(ORAPATH),)
    ORAPATH=$(shell [ -f $(LOCALBASE)/lib64/oracle$(ORAVERDIR)/lib/libocci.so ] && \
	    echo $(LOCALBASE)/lib64/oracle$(ORAVERDIR)/lib )
endif
ifeq ($(ORAPATH),)
    ORAPATH=$(shell [ -f $(SYSBASE)/lib64/oracle$(ORAVERDIR)/lib/libocci.so ] && \
	    echo $(SYSBASE)/lib64/oracle$(ORAVERDIR)/lib )
endif
ifeq ($(ORAPATH),)
    ORAPATH=$(shell [ -f $(LOCALBASE)/lib/oracle$(ORAVERDIR)/libocci.so ] && \
	    echo $(LOCALBASE)/lib/oracle$(ORAVERDIR) )
endif
ifeq ($(ORAPATH),)
    ORAPATH=$(shell [ -f $(SYSBASE)/lib/oracle$(ORAVERDIR)/libocci.so ] && \
	    echo $(SYSBASE)/lib/oracle$(ORAVERDIR) )
endif
ifeq ($(ORAPATH),)
    ORAPATH=$(shell [ -f $(LOCALBASE)/lib/oracle$(ORAVERDIR)/lib/libocci.so ] && \
	    echo $(LOCALBASE)/lib/oracle$(ORAVERDIR)/lib )
endif
ifeq ($(ORAPATH),)
    ORAPATH=$(shell [ -f $(SYSBASE)/lib/oracle$(ORAVERDIR)/lib/libocci.so ] && \
	    echo $(SYSBASE)/lib/oracle$(ORAVERDIR)/lib )
endif

ifneq ($(ORAPATH),)
    LIBS +=-L$(ORAPATH)
endif

LIBS +=-locci -lclntsh

#DEFS+=-DLINUX -D_GNU_SOURCE -D_REENTRANT
#LIBS+=-lpthread

ifneq ($(ORAPATH),)
    LIBS +=-Wl,-rpath $(ORAPATH)
endif

include ../../Makefile.modules

.PHONY: $(UTILS_DIR)/db_oracle/opensips_orasel
$(UTILS_DIR)/db_oracle/opensips_orasel:
	make -C $(UTILS_DIR)/db_oracle

install_module_custom: $(bin_prefix)/$(bin_dir) $(UTILS_DIR)/db_oracle/opensips_orasel
	mkdir -p $(data_prefix)/$(data_dir)/oracle ; \
	for FILE in $(wildcard $(SCRIPTS_DIR)/oracle/*) ; do \
		if [ -f $$FILE ] ; then \
		$(INSTALL_TOUCH) $$FILE \
			$(data_prefix)/$(data_dir)/oracle/`basename "$$FILE"` ; \
		$(INSTALL_CFG) $$FILE \
			$(data_prefix)/$(data_dir)/oracle/`basename "$$FILE"` ; \
		fi ;\
	done ; \
	mkdir -p $(data_prefix)/$(data_dir)/oracle/inc ; \
	for FILE in $(wildcard $(SCRIPTS_DIR)/oracle/inc/*) ; do \
		if [ -f $$FILE ] ; then \
		$(INSTALL_TOUCH) $$FILE \
			$(data_prefix)/$(data_dir)/oracle/inc/`basename "$$FILE"` ; \
		$(INSTALL_CFG) $$FILE \
			$(data_prefix)/$(data_dir)/oracle/inc/`basename "$$FILE"` ; \
		fi ;\
	done ; \
	mkdir -p $(data_prefix)/$(data_dir)/oracle/admin ; \
	for FILE in $(wildcard $(SCRIPTS_DIR)/oracle/admin/*) ; do \
		if [ -f $$FILE ] ; then \
		$(INSTALL_TOUCH) $$FILE \
			$(data_prefix)/$(data_dir)/oracle/admin/`basename "$$FILE"` ; \
		$(INSTALL_CFG) $$FILE \
			$(data_prefix)/$(data_dir)/oracle/admin/`basename "$$FILE"` ; \
		fi ;\
	done ; \
	$(INSTALL_BIN) $(UTILS_DIR)/db_oracle/opensips_orasel $(bin_prefix)/$(bin_dir) ; \
