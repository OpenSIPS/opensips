# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=clusterer.so
#DEFS+= -DCLUSTERER_DBG
#DEFS+= -DCLUSTERER_EXTRA_BIN_DBG

# Controller support (the clusterer_ctrl API, the cluster_options modparam and
# the controller hooks) is compiled only when the clusterer_controller module is
# part of this build - the top-level Makefile exports CLUSTERER_CTRL_SUPPORT=1 in
# that case.  A stock build produces the vanilla clusterer module.
ifeq ($(CLUSTERER_CTRL_SUPPORT),1)
DEFS+= -DCLUSTERER_CTRL_SUPPORT
endif

include ../../Makefile.modules
