# $Id$
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs

HAS_BUILDER = $(shell if which net-snmp-config >/dev/null 2>/dev/null;then echo YES; fi)

ifeq ($(HAS_BUILDER),YES)
	# use autodetection
	DEFS += $(shell net-snmp-config --cflags)
	LIBS = $(shell net-snmp-config --netsnmp-agent-libs --external-agent-libs)
	INSTALLMIBDIR = $(cfg-prefix)$(shell net-snmp-config --prefix)/share/snmp/mibs
else
	# use standard know paths
	DEFS +=-I$(LOCALBASE)/include
	LIBS =-L$(LOCALBASE)/lib -lnetsnmpmibs -lnetsnmpagent \
		-lnetsnmphelpers -lnetsnmp
	INSTALLMIBDIR = $(cfg-prefix)/share/snmp/mibs
endif 


CFLAGS+=
auto_gen=
NAME=snmpstats.so


include ../../Makefile.modules

install_module_custom:
	echo "installing mibs ..."
	mkdir -p $(INSTALLMIBDIR)
	$(INSTALL_CFG) mibs/OPENSER* $(INSTALLMIBDIR)

