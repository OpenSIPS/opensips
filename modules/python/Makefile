# $Id: Makefile 5901 2009-07-21 07:45:05Z bogdan_iancu $
#
# print example module makefile
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=python.so

PYTHON?=python2.5

PYTHON_VERSION=${shell ${PYTHON} -c "import distutils.sysconfig;print distutils.sysconfig.get_config_var('VERSION')"}
PYTHON_LIBDIR=${shell ${PYTHON} -c "import distutils.sysconfig;print distutils.sysconfig.get_config_var('LIBDIR')"}
PYTHON_LDFLAGS=${shell ${PYTHON} -c "import distutils.sysconfig;print distutils.sysconfig.get_config_var('LINKFORSHARED')"}
PYTHON_INCDIR=${shell ${PYTHON} -c "import distutils.sysconfig;print distutils.sysconfig.get_python_inc()"}

LIBS=-L${PYTHON_LIBDIR} ${PYTHON_LDFLAGS} -lpython${PYTHON_VERSION}

ifeq ($(OS), freebsd)
LIBS+=-pthread
endif

DEFS+=-I${PYTHON_INCDIR}

include ../../Makefile.modules

