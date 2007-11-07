# $Id$
#
# sip_router makefile
#
# WARNING: requires gmake (GNU Make)
#  Arch supported: Linux, FreeBSD, SunOS (tested on Solaris 8), OpenBSD (3.2),
#  NetBSD (1.6).
#
#  History:
#  --------
#              created by andrei
#  2003-02-24  make install no longer overwrites openser.cfg  - patch provided
#               by Maxim Sobolev   <sobomax@FreeBSD.org> and 
#                  Tomas Bjoerklund <tomas@webservices.se>
#  2003-03-11  PREFIX & LOCALBASE must also be exported (andrei)
#  2003-04-07  hacked to work with solaris install (andrei)
#  2003-04-17  exclude modules overwritable from env. or cmd. line,
#               added include_modules and skip_modules (andrei)
#  2003-05-30  added extra_defs & EXTRA_DEFS
#               Makefile.defs force-included to allow recursive make
#               calls -- see comment (andrei)
#  2003-06-02  make tar changes -- unpacks in $NAME-$RELEASE  (andrei)
#  2003-06-03  make install-cfg will properly replace the module path
#               in the cfg (re: /usr/.*lib/openser/modules)
#              openser.cfg.default is installed only if there is a previous
#               cfg. -- fixes packages containing openser.cfg.default (andrei)
#  2003-08-29  install-modules-doc split from install-doc, added 
#               install-modules-all, removed README.cfg (andrei)
#              added skip_cfg_install (andrei)
#  2004-09-02  install-man will automatically "fix" the path of the files
#               referred in the man pages
#  2007-09-28  added db_berkeley (wiquan)
#

#TLS=1
#FREERADIUS=1
auto_gen=lex.yy.c cfg.tab.c   #lexx, yacc etc

#include  source related defs
include Makefile.sources

# whether or not to install openser.cfg or just openser.cfg.default
# (openser.cfg will never be overwritten by make install, this is usefull
#  when creating packages)
skip_cfg_install?=

#extra modules to exclude
skip_modules?=

# if not set on the cmd. line or the env, exclude this modules:
exclude_modules?= jabber cpl-c mysql pa postgres osp unixodbc \
	avp_radius auth_radius group_radius uri_radius xmpp \
	presence presence_xml presence_mwi pua pua_bla pua_mi \
	pua_usrloc pua_xmpp rls mi_xmlrpc perl perlvdb \
	ldap seas carrierroute h350 xcap_client benchmark
ifeq ($(TLS),)
	exclude_modules+= tlsops
endif
# always exclude the SVN dir
override exclude_modules+= .svn $(skip_modules)

#always include this modules
include_modules?=

# first 2 lines are excluded because of the experimental or incomplete
# status of the modules
# the rest is excluded because it depends on external libraries
#
static_modules=
static_modules_path=$(addprefix modules/, $(static_modules))
extra_sources=$(wildcard $(addsuffix /*.c, $(static_modules_path)))
extra_objs=$(extra_sources:.c=.o)

static_defs= $(foreach  mod, $(static_modules), \
		-DSTATIC_$(shell echo $(mod) | tr [:lower:] [:upper:]) )

override extra_defs+=$(static_defs) $(EXTRA_DEFS)
export extra_defs

modules=$(filter-out $(addprefix modules/, \
			$(exclude_modules) $(static_modules)), \
			$(wildcard modules/*))
modules:=$(filter-out $(modules), $(addprefix modules/, $(include_modules) )) \
			$(modules)
modules_names=$(shell echo $(modules)| \
				sed -e 's/modules\/\([^/ ]*\)\/*/\1.so/g' )
modules_basenames=$(shell echo $(modules)| \
				sed -e 's/modules\/\([^/ ]*\)\/*/\1/g' )
#modules_names=$(patsubst modules/%, %.so, $(modules))
modules_full_path=$(join  $(modules), $(addprefix /, $(modules_names)))

tls_configs=$(patsubst etc/%, %, $(wildcard etc/tls/*) \
			$(wildcard etc/tls/rootCA/*) $(wildcard etc/tls/rootCA/certs/*) \
			$(wildcard etc/tls/rootCA/private/*) $(wildcard etc/tls/user/*))

MODULE_MYSQL_INCLUDED=$(shell echo $(modules)| grep mysql )
ifeq (,$(MODULE_MYSQL_INCLUDED))
	MYSQLON=no
else
	MYSQLON=yes
endif
MODULE_PGSQL_INCLUDED=$(shell echo $(modules)| grep postgres )
ifeq (,$(MODULE_PGSQL_INCLUDED))
	PGSQLON=no
else
	PGSQLON=yes
endif
MODULE_BERKELEYDB_INCLUDED=$(shell echo $(modules)| grep db_berkeley )
ifeq (,$(MODULE_BERKELEYDB_INCLUDED))
	BERKELEYDBON=no
else
	BERKELEYDBON=yes
endif

ALLDEP=Makefile Makefile.sources Makefile.defs Makefile.rules

#include general defs (like CC, CFLAGS  a.s.o)
# hack to force makefile.defs re-inclusion (needed when make calls itself with
# other options -- e.g. make bin)
makefile_defs=0
DEFS:=
include Makefile.defs

NAME=$(MAIN_NAME)

#export relevant variables to the sub-makes
export DEFS PROFILE CC LD MKDEP MKTAGS CFLAGS LDFLAGS MOD_CFLAGS MOD_LDFLAGS 
export LIBS RADIUS_LIB
export LEX YACC YACC_FLAGS
export PREFIX LOCALBASE SYSBASE
# export relevant variables for recursive calls of this makefile 
# (e.g. make deb)
#export LIBS
#export TAR 
export NAME RELEASE OS ARCH 
export cfg-prefix cfg-dir bin-prefix bin-dir modules-prefix modules-dir
export doc-prefix doc-dir man-prefix man-dir ut-prefix ut-dir lib-dir
export cfg-target modules-target data-dir data-prefix data-target
export INSTALL INSTALL_CFG INSTALL_BIN INSTALL_MODULES INSTALL_DOC INSTALL_MAN 
export INSTALL_TOUCH

ifneq ($(TLS),)
	tar_extra_args+=
else
	tar_extra_args+=--exclude=$(notdir $(CURDIR))/tls* 
endif
# include the common rules
include Makefile.rules

#extra targets 

$(NAME): $(extra_objs) # static_modules

lex.yy.c: cfg.lex cfg.tab.h $(ALLDEP)
	$(LEX) $<

cfg.tab.c cfg.tab.h: cfg.y  $(ALLDEP)
	$(YACC) $(YACC_FLAGS) $<

.PHONY: all
all: $(NAME) modules utils


.PHONY: modules
modules:
	@set -e; \
	for r in $(modules) "" ; do \
		if [ -n "$$r" ]; then \
			if [ -d "$$r" ]; then \
				echo  "" ; \
				echo  "" ; \
				$(MAKE) -C $$r ; \
			fi ; \
		fi ; \
	done 

.PHONY: modules-readme
modules-readme:
	@set -e; \
	for r in  $(modules_basenames) "" ; do \
		if [ -d "modules/$$r/doc" ]; then \
			cd "modules/$$r/doc" ; \
			if [ -f "$$r".sgml ]; then \
				echo  "" ; \
				echo  "docbook2txt $$r.sgml" ; \
				docbook2txt "$$r".sgml ; \
				mv "$$r".txt ../README ; \
			fi ; \
			cd ../../.. ; \
		fi ; \
	done 

.PHONY: modules-docbook-txt
modules-docbook-txt:
	@set -e; \
	for r in  $(modules_basenames) "" ; do \
		if [ -d "modules/$$r/doc" ]; then \
			cd "modules/$$r/doc" ; \
			if [ -f "$$r".sgml ]; then \
				echo  "" ; \
				echo  "docbook2txt $$r.sgml" ; \
				docbook2txt "$$r".sgml ; \
			fi ; \
			cd ../../.. ; \
		fi ; \
	done 

.PHONY: modules-docbook-html
modules-docbook-html:
	@set -e; \
	for r in  $(modules_basenames) "" ; do \
		if [ -d "modules/$$r/doc" ]; then \
			cd "modules/$$r/doc" ; \
			if [ -f "$$r".sgml ]; then \
				echo  "" ; \
				echo  "docbook2html -u $$r.sgml" ; \
				docbook2html -u "$$r".sgml ; \
			fi ; \
			cd ../../.. ; \
		fi ; \
	done 

.PHONY: modules-docbook-pdf
modules-docbook-pdf:
	@set -e; \
	for r in  $(modules_basenames) "" ; do \
		if [ -d "modules/$$r/doc" ]; then \
			cd "modules/$$r/doc" ; \
			if [ -f "$$r".sgml ]; then \
				echo  "" ; \
				echo  "docbook2pdf $$r.sgml" ; \
				docbook2pdf "$$r".sgml ; \
			fi ; \
			cd ../../.. ; \
		fi ; \
	done 

.PHONY: modules-docbook
modules-docbook: modules-docbook-txt modules-docbook-html modules-docbook-pdf

.PHONY: dbschema-docbook-txt
dbschema-docbook-txt: dbschema
	@set -e; \
	for r in $(wildcard doc/database/*.sgml) "" ; do \
		if [ -f "$$r" ]; then \
			echo  "" ; \
			echo  "docbook2txt $$r" ; \
			docbook2txt -o "doc/database/" "$$r" ; \
		fi ; \
	done

.PHONY: dbschema-docbook-html
dbschema-docbook-html: dbschema
	@set -e; \
	for r in $(wildcard doc/database/*.sgml) "" ; do \
		if [ -f "$$r" ]; then \
			echo  "" ; \
			echo  "docbook2html $$r" ; \
			docbook2html --nochunks -o "doc/database/" "$$r" ; \
		fi ; \
	done

.PHONY: dbschema-docbook-pdf
dbschema-docbook-pdf: dbschema
	@set -e; \
	for r in $(wildcard doc/database/*.sgml) "" ; do \
		if [ -f "$$r" ]; then \
			echo  "" ; \
			echo  "docbook2pdf $$r" ; \
			docbook2pdf -o "doc/database/" "$$r" ; \
		fi ; \
	done

.PHONY: dbschema-docbook
dbschema-docbook: dbschema-docbook-txt dbschema-docbook-html dbschema-docbook-pdf


$(extra_objs):
	-@echo "Extra objs: $(extra_objs)" 
	@set -e; \
	for r in $(static_modules_path) "" ; do \
		if [ -n "$$r" ]; then \
			echo  "" ; \
			echo  "Making static module $r" ; \
			$(MAKE) -C $$r static ; \
		fi ; \
	done 


	
dbg: $(NAME)
	gdb -command debug.gdb

.PHONY: tar
.PHONY: dist

dist: tar

tar: 
	$(TAR) -C .. \
		--exclude=$(notdir $(CURDIR))/test* \
		--exclude=$(notdir $(CURDIR))/tmp* \
		--exclude=$(notdir $(CURDIR))/debian* \
		--exclude=.svn* \
		--exclude=*.[do] \
		--exclude=*.so \
		--exclude=*.il \
		--exclude=$(notdir $(CURDIR))/$(NAME) \
		--exclude=*.gz \
		--exclude=*.bz2 \
		--exclude=*.tar \
		--exclude=*.patch \
		--exclude=.\#* \
		--exclude=*.swp \
		--exclude=*~ \
		${tar_extra_args} \
		-cf - $(notdir $(CURDIR)) | \
			(mkdir -p tmp/_tar1; mkdir -p tmp/_tar2 ; \
			    cd tmp/_tar1; $(TAR) -xf - ) && \
			    mv tmp/_tar1/$(notdir $(CURDIR)) \
			       tmp/_tar2/"$(NAME)-$(RELEASE)" && \
			    (cd tmp/_tar2 && $(TAR) \
			                    -zcf ../../"$(NAME)-$(RELEASE)_src".tar.gz \
			                               "$(NAME)-$(RELEASE)" ) ; \
			    rm -rf tmp/_tar1; rm -rf tmp/_tar2

# binary dist. tar.gz
.PHONY: bin
bin:
	mkdir -p tmp/$(NAME)/usr/local
	$(MAKE) install basedir=tmp/$(NAME) prefix=/usr/local 
	$(TAR) -C tmp/$(NAME)/ -zcf ../$(NAME)-$(RELEASE)_$(OS)_$(ARCH).tar.gz .
	rm -rf tmp/$(NAME)
	
.PHONY: bin-sn
bin-sn:
	mkdir -p tmp/$(NAME)/usr/local
	$(MAKE) install basedir=tmp/$(NAME) prefix=/usr/local/$(NAME)/$(VERSION).$(PATCHLEVEL)
	$(TAR) -C tmp/$(NAME)/ -zcf ../$(NAME)-$(RELEASE)_$(OS)_$(ARCH).tar.gz .
	rm -rf tmp/$(NAME)

.PHONY: deb
deb:
	ln -sf packaging/debian
	dpkg-buildpackage -rfakeroot -tc $(DEBBUILD_EXTRA_OPTIONS)
	rm -f debian

.PHONY: sunpkg
sunpkg:
	mkdir -p tmp/$(NAME)
	mkdir -p tmp/$(NAME)_sun_pkg
	$(MAKE) install basedir=tmp/$(NAME) prefix=/usr/local
	(cd packaging/solaris; \
	pkgmk -r ../../tmp/$(NAME)/usr/local -o -d ../../tmp/$(NAME)_sun_pkg/ -v "$(RELEASE)" ;\
	cd ../..)
	cat /dev/null > ../$(NAME)-$(RELEASE)-$(OS)-$(ARCH)-local
	pkgtrans -s tmp/$(NAME)_sun_pkg/ ../$(NAME)-$(RELEASE)-$(OS)-$(ARCH)-local \
		OpenSER
	gzip -9 ../$(NAME)-$(RELEASE)-$(OS)-$(ARCH)-local
	rm -rf tmp/$(NAME)
	rm -rf tmp/$(NAME)_sun_pkg


.PHONY: install
install: all mk-install-dirs install-cfg install-bin install-modules \
	install-doc install-man

.PHONY: dbinstall
dbinstall:
	-@echo "Initializing $(NAME) database"
	scripts/mysqldb.sh create
	-@echo "Done"

.PHONY: dbschema
dbschema:
	-@echo "Build database schemas"
	$(MAKE) -C db/schema
	-@echo "Done"

mk-install-dirs: $(cfg-prefix)/$(cfg-dir) $(bin-prefix)/$(bin-dir) \
			$(modules-prefix)/$(modules-dir) $(doc-prefix)/$(doc-dir) \
			$(man-prefix)/$(man-dir)/man8 $(man-prefix)/$(man-dir)/man5 \
			$(data-prefix)/$(data-dir)

$(cfg-prefix)/$(cfg-dir): 
		mkdir -p $(cfg-prefix)/$(cfg-dir)

$(bin-prefix)/$(bin-dir):
		mkdir -p $(bin-prefix)/$(bin-dir)

$(modules-prefix)/$(modules-dir):
		mkdir -p $(modules-prefix)/$(modules-dir)

$(doc-prefix)/$(doc-dir):
		mkdir -p $(doc-prefix)/$(doc-dir)

$(man-prefix)/$(man-dir)/man8:
		mkdir -p $(man-prefix)/$(man-dir)/man8

$(man-prefix)/$(man-dir)/man5:
		mkdir -p $(man-prefix)/$(man-dir)/man5

$(data-prefix)/$(data-dir):
		mkdir -p $(data-prefix)/$(data-dir)

		
# note: on solaris 8 sed: ? or \(...\)* (a.s.o) do not work
install-cfg: $(cfg-prefix)/$(cfg-dir)
		sed -e "s#/usr/.*lib/$(NAME)/modules/#$(modules-target)#g" \
			< etc/$(NAME).cfg > $(cfg-prefix)/$(cfg-dir)$(NAME).cfg.sample0
		sed -e "s#/usr/.*etc/$(NAME)/tls/#$(cfg-target)tls/#g" \
			< $(cfg-prefix)/$(cfg-dir)$(NAME).cfg.sample0 \
			> $(cfg-prefix)/$(cfg-dir)$(NAME).cfg.sample
		rm -fr $(cfg-prefix)/$(cfg-dir)$(NAME).cfg.sample0
		chmod 644 $(cfg-prefix)/$(cfg-dir)$(NAME).cfg.sample
		if [ -z "${skip_cfg_install}" -a \
				! -f $(cfg-prefix)/$(cfg-dir)$(NAME).cfg ]; then \
			mv -f $(cfg-prefix)/$(cfg-dir)$(NAME).cfg.sample \
				$(cfg-prefix)/$(cfg-dir)$(NAME).cfg; \
		fi
		# radius dictionary
		$(INSTALL_TOUCH) $(cfg-prefix)/$(cfg-dir)/dictionary.radius
		$(INSTALL_CFG) etc/dictionary.radius $(cfg-prefix)/$(cfg-dir)
		# openserctl config
		$(INSTALL_TOUCH)   $(cfg-prefix)/$(cfg-dir)/openserctlrc.sample
		$(INSTALL_CFG) scripts/openserctlrc \
			$(cfg-prefix)/$(cfg-dir)/openserctlrc.sample
		if [ ! -f $(cfg-prefix)/$(cfg-dir)/openserctlrc ]; then \
			mv -f $(cfg-prefix)/$(cfg-dir)/openserctlrc.sample \
				$(cfg-prefix)/$(cfg-dir)/openserctlrc; \
		fi
		#$(INSTALL_CFG) etc/$(NAME).cfg $(cfg-prefix)/$(cfg-dir)
		if [ "$(TLS)" != "" ] ; then \
			mkdir -p $(cfg-prefix)/$(cfg-dir)/tls ; \
			mkdir -p $(cfg-prefix)/$(cfg-dir)/tls/rootCA ; \
			mkdir -p $(cfg-prefix)/$(cfg-dir)/tls/rootCA/certs ; \
			mkdir -p $(cfg-prefix)/$(cfg-dir)/tls/rootCA/private ; \
			mkdir -p $(cfg-prefix)/$(cfg-dir)/tls/user ; \
			for FILE in $(tls_configs) ; do \
				if [ -f etc/$$FILE ] ; then \
					$(INSTALL_TOUCH) etc/$$FILE \
						$(cfg-prefix)/$(cfg-dir)/$$FILE ; \
					$(INSTALL_CFG) etc/$$FILE \
						$(cfg-prefix)/$(cfg-dir)/$$FILE ; \
				fi ;\
			done ; \
		fi

install-bin: $(bin-prefix)/$(bin-dir) utils
		$(INSTALL_TOUCH) $(bin-prefix)/$(bin-dir)/$(NAME) 
		$(INSTALL_BIN) $(NAME) $(bin-prefix)/$(bin-dir)
		cat scripts/openserctl | \
		sed -e "s#/usr/local/sbin#$(bin-target)#g" | \
		sed -e "s#/usr/local/lib/openser#$(lib-target)#g" | \
		sed -e "s#/usr/local/etc/openser#$(cfg-target)#g"  >/tmp/openserctl
		$(INSTALL_TOUCH) $(bin-prefix)/$(bin-dir)/openserctl
		$(INSTALL_BIN) /tmp/openserctl $(bin-prefix)/$(bin-dir)
		rm -fr /tmp/openserctl
		sed -e "s#/usr/local/sbin#$(bin-target)#g" \
			< scripts/openserctl.base > /tmp/openserctl.base
		mkdir -p $(modules-prefix)/$(lib-dir)/openserctl 
		$(INSTALL_TOUCH) \
			$(modules-prefix)/$(lib-dir)/openserctl
		$(INSTALL_CFG) /tmp/openserctl.base \
			$(modules-prefix)/$(lib-dir)/openserctl/openserctl.base
		rm -fr /tmp/openserctl.base
		sed -e "s#/usr/local#$(bin-target)#g" \
			< scripts/openserctl.ctlbase > /tmp/openserctl.ctlbase
		$(INSTALL_CFG) /tmp/openserctl.ctlbase \
			$(modules-prefix)/$(lib-dir)/openserctl/openserctl.ctlbase
		rm -fr /tmp/openserctl.ctlbase
		sed -e "s#/usr/local#$(bin-target)#g" \
			< scripts/openserctl.fifo > /tmp/openserctl.fifo
		$(INSTALL_CFG) /tmp/openserctl.fifo \
			$(modules-prefix)/$(lib-dir)/openserctl/openserctl.fifo
		rm -fr /tmp/openserctl.fifo
		sed -e "s#/usr/local#$(bin-target)#g" \
			< scripts/openserctl.unixsock > /tmp/openserctl.unixsock
		$(INSTALL_CFG) /tmp/openserctl.unixsock \
			$(modules-prefix)/$(lib-dir)/openserctl/openserctl.unixsock
		rm -fr /tmp/openserctl.unixsock
		sed -e "s#/usr/local#$(bin-target)#g" \
			< scripts/openserctl.sqlbase > /tmp/openserctl.sqlbase
		$(INSTALL_CFG) /tmp/openserctl.sqlbase \
			$(modules-prefix)/$(lib-dir)/openserctl/openserctl.sqlbase
		rm -fr /tmp/openserctl.sqlbase
		sed -e "s#/usr/local#$(bin-target)#g" \
			< scripts/openserctl.dbtext > /tmp/openserctl.dbtext
		$(INSTALL_CFG) /tmp/openserctl.dbtext \
			$(modules-prefix)/$(lib-dir)/openserctl/openserctl.dbtext
		rm -fr /tmp/openserctl.dbtext
		# install db setup base script
		sed -e "s#/usr/local/sbin#$(bin-target)#g" \
			-e "s#/usr/local/etc/openser#$(cfg-target)#g" \
			< scripts/openserdbctl.base > /tmp/openserdbctl.base
		$(INSTALL_CFG) /tmp/openserdbctl.base \
			$(modules-prefix)/$(lib-dir)/openserctl/openserdbctl.base
		rm -fr /tmp/openserdbctl.base
		cat scripts/openserdbctl | \
		sed -e "s#/usr/local/sbin#$(bin-target)#g" | \
		sed -e "s#/usr/local/lib/openser#$(lib-target)#g" | \
		sed -e "s#/usr/local/etc/openser#$(cfg-target)#g"  >/tmp/openserdbctl
		$(INSTALL_TOUCH) $(bin-prefix)/$(bin-dir)/openserdbctl
		$(INSTALL_BIN) /tmp/openserdbctl $(bin-prefix)/$(bin-dir)
		rm -fr /tmp/openserdbctl
		$(INSTALL_TOUCH)   $(bin-prefix)/$(bin-dir)/$(NAME)unix
		$(INSTALL_BIN) utils/$(NAME)unix/$(NAME)unix $(bin-prefix)/$(bin-dir)
		# install dbtext stuff
		mkdir -p $(modules-prefix)/$(lib-dir)/openserctl ; \
		sed -e "s#/usr/local/share/openser#$(data-target)#g" \
			< scripts/openserdbctl.dbtext > /tmp/openserdbctl.dbtext ; \
			$(INSTALL_TOUCH) $(modules-prefix)/$(lib-dir)/openserctl/openserdbctl.dbtext ; \
			$(INSTALL_CFG) /tmp/openserdbctl.dbtext $(modules-prefix)/$(lib-dir)/openserctl/ ; \
			rm -fr /tmp/openserdbctl.dbtext ; \
		mkdir -p $(data-prefix)/$(data-dir)/dbtext/openser ; \
		for FILE in $(wildcard scripts/dbtext/openser/*) ; do \
			if [ -f $$FILE ] ; then \
				$(INSTALL_TOUCH) $$FILE \
					$(data-prefix)/$(data-dir)/dbtext/openser/`basename "$$FILE"` ; \
				$(INSTALL_CFG) $$FILE \
					$(data-prefix)/$(data-dir)/dbtext/openser/`basename "$$FILE"` ; \
			fi ;\
		done ; \

.PHONY: utils
utils:
		cd utils/$(NAME)unix; $(MAKE) all
		if [ "$(BERKELEYDBON)" = "yes" ]; then \
			cd utils/db_berkeley; $(MAKE) all ; \
		fi ; \

install-modules: modules install-modules-tools $(modules-prefix)/$(modules-dir)
	@for r in $(modules_full_path) "" ; do \
		if [ -n "$$r" ]; then \
			if [ -f "$$r" ]; then \
				$(INSTALL_TOUCH) \
					$(modules-prefix)/$(modules-dir)/`basename "$$r"` ; \
				$(INSTALL_MODULES)  "$$r"  $(modules-prefix)/$(modules-dir) ; \
				$(MAKE) -C `dirname "$$r"` install_module_custom ; \
			else \
				echo "ERROR: module $$r not compiled" ; \
			fi ;\
		fi ; \
	done 


install-modules-all: install-modules install-modules-doc

install-modules-tools: $(bin-prefix)/$(bin-dir)
		# install MySQL stuff
		if [ "$(MYSQLON)" = "yes" ]; then \
			mkdir -p $(modules-prefix)/$(lib-dir)/openserctl ; \
			sed -e "s#/usr/local/sbin#$(bin-target)#g" \
				< scripts/openserctl.mysql > /tmp/openserctl.mysql ; \
			$(INSTALL_CFG) /tmp/openserctl.mysql \
				$(modules-prefix)/$(lib-dir)/openserctl/openserctl.mysql ; \
			rm -fr /tmp/openserctl.mysql ; \
			sed -e "s#/usr/local/share/openser#$(data-target)#g" \
			< scripts/openserdbctl.mysql > /tmp/openserdbctl.mysql ; \
			$(INSTALL_TOUCH) $(modules-prefix)/$(lib-dir)/openserctl/openserdbctl.mysql ; \
			$(INSTALL_CFG) /tmp/openserdbctl.mysql $(modules-prefix)/$(lib-dir)/openserctl/ ; \
			rm -fr /tmp/openserdbctl.mysql ; \
			mkdir -p $(data-prefix)/$(data-dir)/mysql ; \
			for FILE in $(wildcard scripts/mysql/*) ; do \
				if [ -f $$FILE ] ; then \
				$(INSTALL_TOUCH) $$FILE \
					$(data-prefix)/$(data-dir)/mysql/`basename "$$FILE"` ; \
				$(INSTALL_CFG) $$FILE \
					$(data-prefix)/$(data-dir)/mysql/`basename "$$FILE"` ; \
				fi ;\
			done ; \
		fi
		# install PostgreSQL stuff
		if [ "$(PGSQLON)" = "yes" ]; then \
			mkdir -p $(modules-prefix)/$(lib-dir)/openserctl ; \
			sed -e "s#/usr/local/sbin#$(bin-target)#g" \
				< scripts/openserctl.pgsql > /tmp/openserctl.pgsql ; \
			$(INSTALL_CFG) /tmp/openserctl.pgsql \
				$(modules-prefix)/$(lib-dir)/openserctl/openserctl.pgsql ; \
			rm -fr /tmp/openserctl.pgsql ; \
			sed -e "s#/usr/local/share/openser#$(data-target)#g" \
				< scripts/openserdbctl.pgsql > /tmp/openserdbctl.pgsql ; \
			$(INSTALL_TOUCH) $(modules-prefix)/$(lib-dir)/openserctl/openserdbctl.pgsql ; \
			$(INSTALL_CFG) /tmp/openserdbctl.pgsql $(modules-prefix)/$(lib-dir)/openserctl/ ; \
			rm -fr /tmp/openserdbctl.pgsql ; \
			mkdir -p $(data-prefix)/$(data-dir)/postgres ; \
			for FILE in $(wildcard scripts/postgres/*) ; do \
				if [ -f $$FILE ] ; then \
				$(INSTALL_TOUCH) $$FILE \
					$(data-prefix)/$(data-dir)/postgres/`basename "$$FILE"` ; \
				$(INSTALL_CFG) $$FILE \
					$(data-prefix)/$(data-dir)/postgres/`basename "$$FILE"` ; \
				fi ;\
			done ; \
		fi
		# install Berkeley database stuff
		if [ "$(BERKELEYDBON)" = "yes" ]; then \
			mkdir -p $(modules-prefix)/$(lib-dir)/openserctl ; \
			sed -e "s#/usr/local/share/openser#$(data-target)#g" \
				< scripts/openserdbctl.db_berkeley > /tmp/openserdbctl.db_berkeley ; \
			$(INSTALL_TOUCH) $(modules-prefix)/$(lib-dir)/openserctl/openserdbctl.db_berkeley ; \
			$(INSTALL_CFG) /tmp/openserdbctl.db_berkeley $(modules-prefix)/$(lib-dir)/openserctl/ ; \
			rm -fr /tmp/openserdbctl.db_berkeley ; \
			mkdir -p $(data-prefix)/$(data-dir)/db_berkeley/openser ; \
			for FILE in $(wildcard scripts/db_berkeley/openser/*) ; do \
				if [ -f $$FILE ] ; then \
				$(INSTALL_TOUCH) $$FILE \
					$(data-prefix)/$(data-dir)/db_berkeley/openser/`basename "$$FILE"` ; \
				$(INSTALL_CFG) $$FILE \
					$(data-prefix)/$(data-dir)/db_berkeley/openser/`basename "$$FILE"` ; \
				fi ;\
			done ; \
			$(INSTALL_BIN) utils/db_berkeley/bdb_recover $(bin-prefix)/$(bin-dir) ; \
		fi


install-doc: $(doc-prefix)/$(doc-dir) install-modules-doc
	$(INSTALL_TOUCH) $(doc-prefix)/$(doc-dir)/INSTALL 
	$(INSTALL_DOC) INSTALL $(doc-prefix)/$(doc-dir)
	$(INSTALL_TOUCH) $(doc-prefix)/$(doc-dir)/README-MODULES 
	$(INSTALL_DOC) README-MODULES $(doc-prefix)/$(doc-dir)
	$(INSTALL_TOUCH) $(doc-prefix)/$(doc-dir)/AUTHORS 
	$(INSTALL_DOC) AUTHORS $(doc-prefix)/$(doc-dir)
	$(INSTALL_TOUCH) $(doc-prefix)/$(doc-dir)/NEWS
	$(INSTALL_DOC) NEWS $(doc-prefix)/$(doc-dir)
	$(INSTALL_TOUCH) $(doc-prefix)/$(doc-dir)/README 
	$(INSTALL_DOC) README $(doc-prefix)/$(doc-dir)


install-modules-doc: $(doc-prefix)/$(doc-dir)
	-@for r in $(modules_basenames) "" ; do \
		if [ -n "$$r" ]; then \
			if [ -f modules/"$$r"/README ]; then \
				$(INSTALL_TOUCH)  $(doc-prefix)/$(doc-dir)/README ; \
				$(INSTALL_DOC)  modules/"$$r"/README  \
									$(doc-prefix)/$(doc-dir)/README ; \
				mv -f $(doc-prefix)/$(doc-dir)/README \
						$(doc-prefix)/$(doc-dir)/README."$$r" ; \
			fi ; \
		fi ; \
	done 


install-man: $(man-prefix)/$(man-dir)/man8 $(man-prefix)/$(man-dir)/man5
		sed -e "s#/etc/$(NAME)/$(NAME)\.cfg#$(cfg-target)$(NAME).cfg#g" \
			-e "s#/usr/sbin/#$(bin-target)#g" \
			-e "s#/usr/lib/$(NAME)/modules/#$(modules-target)#g" \
			-e "s#/usr/share/doc/$(NAME)/#$(doc-target)#g" \
			< $(NAME).8 >  $(man-prefix)/$(man-dir)/man8/$(NAME).8
		chmod 644  $(man-prefix)/$(man-dir)/man8/$(NAME).8
		sed -e "s#/etc/$(NAME)/$(NAME)\.cfg#$(cfg-target)$(NAME).cfg#g" \
			-e "s#/usr/sbin/#$(bin-target)#g" \
			-e "s#/usr/lib/$(NAME)/modules/#$(modules-target)#g" \
			-e "s#/usr/share/doc/$(NAME)/#$(doc-target)#g" \
			< $(NAME).cfg.5 >  $(man-prefix)/$(man-dir)/man5/$(NAME).cfg.5
		chmod 644  $(man-prefix)/$(man-dir)/man5/$(NAME).cfg.5
		sed -e "s#/etc/$(NAME)/$(NAME)\.cfg#$(cfg-target)$(NAME).cfg#g" \
			-e "s#/usr/sbin/#$(bin-target)#g" \
			-e "s#/usr/lib/$(NAME)/modules/#$(modules-target)#g" \
			-e "s#/usr/share/doc/$(NAME)/#$(doc-target)#g" \
			< scripts/openserctl.8 > $(man-prefix)/$(man-dir)/man8/openserctl.8
		chmod 644  $(man-prefix)/$(man-dir)/man8/openserctl.8
		sed -e "s#/etc/$(NAME)/$(NAME)\.cfg#$(cfg-target)$(NAME).cfg#g" \
			-e "s#/usr/sbin/#$(bin-target)#g" \
			-e "s#/usr/lib/$(NAME)/modules/#$(modules-target)#g" \
			-e "s#/usr/share/doc/$(NAME)/#$(doc-target)#g" \
			< utils/openserunix/openserunix.8 > \
			$(man-prefix)/$(man-dir)/man8/openserunix.8
		chmod 644  $(man-prefix)/$(man-dir)/man8/openserunix.8

install-modules-docbook: $(doc-prefix)/$(doc-dir)
	-@for r in $(modules_basenames) "" ; do \
		if [ -n "$$r" ]; then \
			if [ -d modules/"$$r"/doc ]; then \
				if [ -f modules/"$$r"/doc/"$$r".txt ]; then \
					$(INSTALL_TOUCH)  $(doc-prefix)/$(doc-dir)/"$$r".txt ; \
					$(INSTALL_DOC)  modules/"$$r"/doc/"$$r".txt  \
									$(doc-prefix)/$(doc-dir)/"$$r".txt ; \
				fi ; \
				if [ -f modules/"$$r"/doc/"$$r".html ]; then \
					$(INSTALL_TOUCH)  $(doc-prefix)/$(doc-dir)/"$$r".html ; \
					$(INSTALL_DOC)  modules/"$$r"/doc/"$$r".html  \
									$(doc-prefix)/$(doc-dir)/"$$r".html ; \
				fi ; \
				if [ -f modules/"$$r"/doc/"$$r".pdf ]; then \
					$(INSTALL_TOUCH)  $(doc-prefix)/$(doc-dir)/"$$r".pdf ; \
					$(INSTALL_DOC)  modules/"$$r"/doc/"$$r".pdf  \
									$(doc-prefix)/$(doc-dir)/"$$r".pdf ; \
				fi ; \
			fi ; \
		fi ; \
	done
