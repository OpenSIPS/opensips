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
#  2003-02-24  make install no longer overwrites opensips.cfg  - patch provided
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
#               in the cfg (re: /usr/.*lib/opensips/modules)
#              opensips.cfg.default is installed only if there is a previous
#               cfg. -- fixes packages containing opensips.cfg.default (andrei)
#  2003-08-29  install-modules-doc split from install-doc, added 
#               install-modules-all, removed README.cfg (andrei)
#              added skip_cfg_install (andrei)
#  2004-09-02  install-man will automatically "fix" the path of the files
#               referred in the man pages
#  2007-09-28  added db_berkeley (wiquan)
#

#TLS=1
#SCTP=1
#FREERADIUS=1
NICER=1
auto_gen=lex.yy.c cfg.tab.c   #lexx, yacc etc

#include  source related defs
include Makefile.sources

# whether or not to install opensips.cfg or just opensips.cfg.default
# (opensips.cfg will never be overwritten by make install, this is usefull
#  when creating packages)
skip_cfg_install?=

#extra modules to exclude
skip_modules?=

# if not set on the cmd. line or the env, exclude this modules:
exclude_modules?= b2b_logic jabber cpl-c xmpp rls mi_xmlrpc xcap_client \
	db_mysql db_postgres db_unixodbc db_oracle db_berkeley aaa_radius \
	osp perl snmpstats perlvdb carrierroute mmgeoip \
	presence presence_xml presence_mwi presence_dialoginfo \
	pua pua_bla pua_mi pua_usrloc pua_xmpp pua_dialoginfo \
	ldap h350 identity regex memcached db_http json python dialplan
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

ifeq ($(TLS),)
	tls_configs=""
else
	tls_configs=$(patsubst etc/%, %, $(wildcard etc/tls/*) \
			$(wildcard etc/tls/rootCA/*) $(wildcard etc/tls/rootCA/certs/*) \
			$(wildcard etc/tls/rootCA/private/*) $(wildcard etc/tls/user/*))
endif

MODULE_MYSQL_INCLUDED=$(shell echo $(modules)| grep db_mysql )
ifeq (,$(MODULE_MYSQL_INCLUDED))
	MYSQLON=no
else
	MYSQLON=yes
endif
MODULE_PGSQL_INCLUDED=$(shell echo $(modules)| grep db_postgres )
ifeq (,$(MODULE_PGSQL_INCLUDED))
	PGSQLON=no
else
	PGSQLON=yes
endif
MODULE_ORACLE_INCLUDED=$(shell echo $(modules)| grep db_oracle )
ifeq (,$(MODULE_ORACLE_INCLUDED))
	ORACLEON=no
else
	ORACLEON=yes
endif
MODULE_BERKELEYDB_INCLUDED=$(shell echo $(modules)| grep db_berkeley )
ifeq (,$(MODULE_BERKELEYDB_INCLUDED))
	BERKELEYDBON=no
else
	BERKELEYDBON=yes
endif
MODULE_DBTEXT_INCLUDED=$(shell echo $(modules)| grep db_text )
ifeq (,$(MODULE_DBTEXT_INCLUDED))
	DBTEXTON=no
else
	DBTEXTON=yes
endif
MODULE_RADIUSDEP_INCLUDED=$(shell echo $(modules)| grep _radius )
ifeq (,$(MODULE_RADIUSDEP_INCLUDED))
	RADIUSDEPON=no
else
	RADIUSDEPON=yes
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
	tar_extra_args+=--exclude=$(notdir $(CURDIR))/tls* \
		--exclude=$(notdir $(CURDIR))/etc/tls* \
		--exclude=$(notdir $(CURDIR))/modules/tls* 
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

.PHONY: app
app: $(NAME)


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
	if [ "$(DBXML2HTML)" = "" ]; then \
		echo "error: xsltproc not found"; exit ; \
	fi ; \
	if [ "$(DBHTML2TXT)" = "" ]; then \
		echo "error: lynx not found"; exit ; \
	fi ; \
	for r in  $(modules_basenames) "" ; do \
		if [ -d "modules/$$r/doc" ]; then \
			cd "modules/$$r/doc" ; \
			if [ -f "$$r".xml ]; then \
				echo  "" ; \
				echo  "docbook xml to html: $$r.xml" ; \
				$(DBXML2HTML) -o $$r.html $(DBXML2HTMLPARAMS) $(DBHTMLXSL) \
							$$r.xml ; \
				echo  "docbook html to txt: $$r.html" ; \
				$(DBHTML2TXT) $(DBHTML2TXTPARAMS) $$r.html >$$r.txt ; \
				echo  "docbook txt to readme: $$r.txt" ; \
				rm $$r.html ; \
				mv $$r.txt ../README ; \
				echo  "" ; \
			fi ; \
			cd ../../.. ; \
		fi ; \
	done 

.PHONY: modules-docbook-txt
modules-docbook-txt:
	@set -e; \
	if [ "$(DBXML2HTML)" = "" ]; then \
		echo "error: xsltproc not found"; exit ; \
	fi ; \
	if [ "$(DBHTML2TXT)" = "" ]; then \
		echo "error: lynx not found"; exit ; \
	fi ; \
	for r in  $(modules_basenames) "" ; do \
		if [ -d "modules/$$r/doc" ]; then \
			cd "modules/$$r/doc" ; \
			if [ -f "$$r".xml ]; then \
				echo  "" ; \
				echo  "docbook xml to html: $$r.xml" ; \
				$(DBXML2HTML) -o $$r.html $(DBXML2HTMLPARAMS) $(DBHTMLXSL) \
							$$r.xml ; \
				echo  "docbook html to txt: $$r.html" ; \
				$(DBHTML2TXT) $(DBHTML2TXTPARAMS) $$r.html >$$r.txt ; \
				rm $$r.html ; \
				echo  "" ; \
			fi ; \
			cd ../../.. ; \
		fi ; \
	done 

.PHONY: modules-docbook-html
modules-docbook-html:
	@set -e; \
	if [ "$(DBXML2HTML)" = "" ]; then \
		echo "error: xsltproc not found"; exit ; \
	fi ; \
	for r in  $(modules_basenames) "" ; do \
		if [ -d "modules/$$r/doc" ]; then \
			cd "modules/$$r/doc" ; \
			if [ -f "$$r".xml ]; then \
				echo  "" ; \
				echo  "docbook xml to html: $$r.xml" ; \
				$(DBXML2HTML) -o $$r.html $(DBXML2HTMLPARAMS) $(DBHTMLXSL) \
							$$r.xml ; \
				echo  "" ; \
			fi ; \
			cd ../../.. ; \
		fi ; \
	done 

.PHONY: modules-docbook-pdf
modules-docbook-pdf:
	@set -e; \
	if [ "$(DBXML2PDF)" = "" ]; then \
		echo "error: docbook2pdf not found"; exit ; \
	fi ; \
	for r in  $(modules_basenames) "" ; do \
		if [ -d "modules/$$r/doc" ]; then \
			cd "modules/$$r/doc" ; \
			if [ -f "$$r".xml ]; then \
				echo  "" ; \
				echo  "docbook xml to pdf: $$r.xml" ; \
				$(DBXML2PDF) "$$r".xml ; \
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

.PHONY: deb
deb:
	rm -f debian
	ln -sf packaging/debian
	dpkg-buildpackage -rfakeroot -tc $(DEBBUILD_EXTRA_OPTIONS)
	rm -f debian

.PHONY: deb-lenny
deb-lenny:
	rm -f debian
	ln -sf packaging/debian-lenny debian
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
		OpenSIPS
	gzip -9 ../$(NAME)-$(RELEASE)-$(OS)-$(ARCH)-local
	rm -rf tmp/$(NAME)
	rm -rf tmp/$(NAME)_sun_pkg


.PHONY: install-app install-modules-all install
# Install app only, excluding console, modules and module docs
install-app: app mk-install-dirs install-cfg install-bin \
	install-app-doc install-man

# Install all module stuff (except modules-docbook?)
install-modules-all: install-modules install-modules-doc

# Install everything (except modules-docbook?)
install: install-app install-console install-modules-all


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
		chmod 600 $(cfg-prefix)/$(cfg-dir)$(NAME).cfg.sample
		chmod 700 $(cfg-prefix)/$(cfg-dir)
		if [ -z "${skip_cfg_install}" -a \
				! -f $(cfg-prefix)/$(cfg-dir)$(NAME).cfg ]; then \
			mv -f $(cfg-prefix)/$(cfg-dir)$(NAME).cfg.sample \
				$(cfg-prefix)/$(cfg-dir)$(NAME).cfg; \
		fi
		# radius dictionary
		if [ "$(RADIUSDEPON)" = "yes" ]; then \
			$(INSTALL_TOUCH) \
				$(cfg-prefix)/$(cfg-dir)/dictionary.opensips.sample ; \
			$(INSTALL_CFG) etc/dictionary.opensips \
				$(cfg-prefix)/$(cfg-dir)/dictionary.opensips.sample ; \
			if [ ! -f $(cfg-prefix)/$(cfg-dir)/dictionary.opensips ]; then \
				mv -f $(cfg-prefix)/$(cfg-dir)/dictionary.opensips.sample \
					$(cfg-prefix)/$(cfg-dir)/dictionary.opensips; \
			fi; \
		fi
		# opensipsctl config
		$(INSTALL_TOUCH)   $(cfg-prefix)/$(cfg-dir)/opensipsctlrc.sample
		$(INSTALL_CFG) scripts/opensipsctlrc \
			$(cfg-prefix)/$(cfg-dir)/opensipsctlrc.sample
		if [ ! -f $(cfg-prefix)/$(cfg-dir)/opensipsctlrc ]; then \
			mv -f $(cfg-prefix)/$(cfg-dir)/opensipsctlrc.sample \
				$(cfg-prefix)/$(cfg-dir)/opensipsctlrc; \
		fi
		# osipsconsole config
		$(INSTALL_TOUCH)   $(cfg-prefix)/$(cfg-dir)/osipsconsolerc.sample
		$(INSTALL_CFG) scripts/osipsconsolerc \
			$(cfg-prefix)/$(cfg-dir)/osipsconsolerc.sample
		if [ ! -f $(cfg-prefix)/$(cfg-dir)/osipsconsolerc ]; then \
			mv -f $(cfg-prefix)/$(cfg-dir)/osipsconsolerc.sample \
				$(cfg-prefix)/$(cfg-dir)/osipsconsolerc; \
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

install-console: $(bin-prefix)/$(bin-dir)
		# install osipsconsole
		cat scripts/osipsconsole | \
		sed -e "s#PATH_BIN[ \t]*=[ \t]*\"\./\"#PATH_BIN = \"$(bin-target)\"#g" | \
		sed -e "s#PATH_CTLRC[ \t]*=[ \t]*\"\./scripts/\"#PATH_CTLRC = \"$(cfg-target)\"#g" | \
		sed -e "s#PATH_ETC[ \t]*=[ \t]*\"\./etc/\"#PATH_ETC = \"$(cfg-target)\"#g" \
		> /tmp/osipsconsole
		$(INSTALL_TOUCH) $(bin-prefix)/$(bin-dir)/osipsconsole
		$(INSTALL_BIN) /tmp/osipsconsole $(bin-prefix)/$(bin-dir)
		rm -fr /tmp/osipsconsole

install-bin: $(bin-prefix)/$(bin-dir) utils
		# install opensips binary
		$(INSTALL_TOUCH) $(bin-prefix)/$(bin-dir)/$(NAME) 
		$(INSTALL_BIN) $(NAME) $(bin-prefix)/$(bin-dir)
		# install opensipsctl (and family) tool
		cat scripts/opensipsctl | \
		sed -e "s#/usr/local/sbin#$(bin-target)#g" | \
		sed -e "s#/usr/local/lib/opensips#$(lib-target)#g" | \
		sed -e "s#/usr/local/etc/opensips#$(cfg-target)#g"  >/tmp/opensipsctl
		$(INSTALL_TOUCH) $(bin-prefix)/$(bin-dir)/opensipsctl
		$(INSTALL_BIN) /tmp/opensipsctl $(bin-prefix)/$(bin-dir)
		rm -fr /tmp/opensipsctl
		sed -e "s#/usr/local/sbin#$(bin-target)#g" \
			< scripts/opensipsctl.base > /tmp/opensipsctl.base
		mkdir -p $(modules-prefix)/$(lib-dir)/opensipsctl 
		$(INSTALL_TOUCH) \
			$(modules-prefix)/$(lib-dir)/opensipsctl
		$(INSTALL_CFG) /tmp/opensipsctl.base \
			$(modules-prefix)/$(lib-dir)/opensipsctl/opensipsctl.base
		rm -fr /tmp/opensipsctl.base
		sed -e "s#/usr/local#$(bin-target)#g" \
			< scripts/opensipsctl.ctlbase > /tmp/opensipsctl.ctlbase
		$(INSTALL_CFG) /tmp/opensipsctl.ctlbase \
			$(modules-prefix)/$(lib-dir)/opensipsctl/opensipsctl.ctlbase
		rm -fr /tmp/opensipsctl.ctlbase
		sed -e "s#/usr/local#$(bin-target)#g" \
			< scripts/opensipsctl.fifo > /tmp/opensipsctl.fifo
		$(INSTALL_CFG) /tmp/opensipsctl.fifo \
			$(modules-prefix)/$(lib-dir)/opensipsctl/opensipsctl.fifo
		rm -fr /tmp/opensipsctl.fifo
		sed -e "s#/usr/local#$(bin-target)#g" \
			< scripts/opensipsctl.unixsock > /tmp/opensipsctl.unixsock
		$(INSTALL_CFG) /tmp/opensipsctl.unixsock \
			$(modules-prefix)/$(lib-dir)/opensipsctl/opensipsctl.unixsock
		rm -fr /tmp/opensipsctl.unixsock
		sed -e "s#/usr/local#$(bin-target)#g" \
			< scripts/opensipsctl.sqlbase > /tmp/opensipsctl.sqlbase
		$(INSTALL_CFG) /tmp/opensipsctl.sqlbase \
			$(modules-prefix)/$(lib-dir)/opensipsctl/opensipsctl.sqlbase
		rm -fr /tmp/opensipsctl.sqlbase
		# install db setup base script
		sed -e "s#/usr/local/sbin#$(bin-target)#g" \
			-e "s#/usr/local/etc/opensips#$(cfg-target)#g" \
			< scripts/opensipsdbctl.base > /tmp/opensipsdbctl.base
		$(INSTALL_CFG) /tmp/opensipsdbctl.base \
			$(modules-prefix)/$(lib-dir)/opensipsctl/opensipsdbctl.base
		rm -fr /tmp/opensipsdbctl.base
		cat scripts/opensipsdbctl | \
		sed -e "s#/usr/local/sbin#$(bin-target)#g" | \
		sed -e "s#/usr/local/lib/opensips#$(lib-target)#g" | \
		sed -e "s#/usr/local/etc/opensips#$(cfg-target)#g"  >/tmp/opensipsdbctl
		$(INSTALL_TOUCH) $(bin-prefix)/$(bin-dir)/opensipsdbctl
		$(INSTALL_BIN) /tmp/opensipsdbctl $(bin-prefix)/$(bin-dir)
		rm -fr /tmp/opensipsdbctl
		$(INSTALL_TOUCH)   $(bin-prefix)/$(bin-dir)/$(NAME)unix
		$(INSTALL_BIN) utils/$(NAME)unix/$(NAME)unix $(bin-prefix)/$(bin-dir)

.PHONY: utils
utils:
		cd utils/$(NAME)unix; $(MAKE) all
		if [ "$(BERKELEYDBON)" = "yes" ]; then \
			cd utils/db_berkeley; $(MAKE) all ; \
		fi ;
		if [ "$(ORACLEON)" = "yes" ]; then \
			cd utils/db_oracle; $(MAKE) all ; \
		fi ;

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



install-modules-tools: $(bin-prefix)/$(bin-dir)
		# install MySQL stuff
		if [ "$(MYSQLON)" = "yes" ]; then \
			mkdir -p $(modules-prefix)/$(lib-dir)/opensipsctl ; \
			sed -e "s#/usr/local/sbin#$(bin-target)#g" \
				< scripts/opensipsctl.mysql > /tmp/opensipsctl.mysql ; \
			$(INSTALL_CFG) /tmp/opensipsctl.mysql \
				$(modules-prefix)/$(lib-dir)/opensipsctl/opensipsctl.mysql ; \
			rm -fr /tmp/opensipsctl.mysql ; \
			sed -e "s#/usr/local/share/opensips#$(data-target)#g" \
			< scripts/opensipsdbctl.mysql > /tmp/opensipsdbctl.mysql ; \
			$(INSTALL_TOUCH) $(modules-prefix)/$(lib-dir)/opensipsctl/opensipsdbctl.mysql ; \
			$(INSTALL_CFG) /tmp/opensipsdbctl.mysql $(modules-prefix)/$(lib-dir)/opensipsctl/ ; \
			rm -fr /tmp/opensipsdbctl.mysql ; \
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
			mkdir -p $(modules-prefix)/$(lib-dir)/opensipsctl ; \
			sed -e "s#/usr/local/sbin#$(bin-target)#g" \
				< scripts/opensipsctl.pgsql > /tmp/opensipsctl.pgsql ; \
			$(INSTALL_CFG) /tmp/opensipsctl.pgsql \
				$(modules-prefix)/$(lib-dir)/opensipsctl/opensipsctl.pgsql ; \
			rm -fr /tmp/opensipsctl.pgsql ; \
			sed -e "s#/usr/local/share/opensips#$(data-target)#g" \
				< scripts/opensipsdbctl.pgsql > /tmp/opensipsdbctl.pgsql ; \
			$(INSTALL_TOUCH) $(modules-prefix)/$(lib-dir)/opensipsctl/opensipsdbctl.pgsql ; \
			$(INSTALL_CFG) /tmp/opensipsdbctl.pgsql $(modules-prefix)/$(lib-dir)/opensipsctl/ ; \
			rm -fr /tmp/opensipsdbctl.pgsql ; \
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
		# install Oracle stuff
		if [ "$(ORACLEON)" = "yes" ]; then \
			mkdir -p $(modules-prefix)/$(lib-dir)/opensipsctl ; \
			sed -e "s#/usr/local/sbin#$(bin-target)#g" \
				< scripts/opensipsctl.oracle > /tmp/opensipsctl.oracle ; \
			$(INSTALL_CFG) /tmp/opensipsctl.oracle \
				$(modules-prefix)/$(lib-dir)/opensipsctl/opensipsctl.oracle ; \
			rm -fr /tmp/opensipsctl.oracle ; \
			sed -e "s#/usr/local/share/opensips#$(data-target)#g" \
			< scripts/opensipsdbctl.oracle > /tmp/opensipsdbctl.oracle ; \
			$(INSTALL_TOUCH) $(modules-prefix)/$(lib-dir)/opensipsctl/opensipsdbctl.oracle ; \
			$(INSTALL_CFG) /tmp/opensipsdbctl.oracle $(modules-prefix)/$(lib-dir)/opensipsctl/ ; \
			rm -fr /tmp/opensipsdbctl.oracle ; \
			sed -e "s#/usr/local/share/opensips#$(data-target)#g" \
			< scripts/opensipsdbfunc.oracle > /tmp/opensipsdbfunc.oracle ; \
			$(INSTALL_TOUCH) $(modules-prefix)/$(lib-dir)/opensipsctl/opensipsdbfunc.oracle ; \
			$(INSTALL_CFG) /tmp/opensipsdbfunc.oracle $(modules-prefix)/$(lib-dir)/opensipsctl/ ; \
			rm -fr /tmp/opensipsdbfunc.oracle ; \
			mkdir -p $(data-prefix)/$(data-dir)/oracle ; \
			for FILE in $(wildcard scripts/oracle/*) ; do \
				if [ -f $$FILE ] ; then \
				$(INSTALL_TOUCH) $$FILE \
					$(data-prefix)/$(data-dir)/oracle/`basename "$$FILE"` ; \
				$(INSTALL_CFG) $$FILE \
					$(data-prefix)/$(data-dir)/oracle/`basename "$$FILE"` ; \
				fi ;\
			done ; \
			mkdir -p $(data-prefix)/$(data-dir)/oracle/inc ; \
			for FILE in $(wildcard scripts/oracle/inc/*) ; do \
				if [ -f $$FILE ] ; then \
				$(INSTALL_TOUCH) $$FILE \
					$(data-prefix)/$(data-dir)/oracle/inc/`basename "$$FILE"` ; \
				$(INSTALL_CFG) $$FILE \
					$(data-prefix)/$(data-dir)/oracle/inc/`basename "$$FILE"` ; \
				fi ;\
			done ; \
			mkdir -p $(data-prefix)/$(data-dir)/oracle/admin ; \
			for FILE in $(wildcard scripts/oracle/admin/*) ; do \
				if [ -f $$FILE ] ; then \
				$(INSTALL_TOUCH) $$FILE \
					$(data-prefix)/$(data-dir)/oracle/admin/`basename "$$FILE"` ; \
				$(INSTALL_CFG) $$FILE \
					$(data-prefix)/$(data-dir)/oracle/admin/`basename "$$FILE"` ; \
				fi ;\
			done ; \
			$(INSTALL_BIN) utils/db_oracle/opensips_orasel $(bin-prefix)/$(bin-dir) ; \
		fi
		# install Berkeley database stuff
		if [ "$(BERKELEYDBON)" = "yes" ]; then \
			mkdir -p $(modules-prefix)/$(lib-dir)/opensipsctl ; \
			sed -e "s#/usr/local/share/opensips/#$(data-target)#g" \
				< scripts/opensipsctl.db_berkeley > /tmp/opensipsctl.db_berkeley ; \
			$(INSTALL_CFG) /tmp/opensipsctl.db_berkeley \
				$(modules-prefix)/$(lib-dir)/opensipsctl/opensipsctl.db_berkeley ; \
			rm -fr /tmp/opensipsctl.db_berkeley ; \
			sed -e "s#/usr/local/share/opensips#$(data-target)#g" \
				< scripts/opensipsdbctl.db_berkeley > /tmp/opensipsdbctl.db_berkeley ; \
			$(INSTALL_TOUCH) $(modules-prefix)/$(lib-dir)/opensipsctl/opensipsdbctl.db_berkeley ; \
			$(INSTALL_CFG) /tmp/opensipsdbctl.db_berkeley $(modules-prefix)/$(lib-dir)/opensipsctl/ ; \
			rm -fr /tmp/opensipsdbctl.db_berkeley ; \
			mkdir -p $(data-prefix)/$(data-dir)/db_berkeley/opensips ; \
			for FILE in $(wildcard scripts/db_berkeley/opensips/*) ; do \
				if [ -f $$FILE ] ; then \
				$(INSTALL_TOUCH) $$FILE \
					$(data-prefix)/$(data-dir)/db_berkeley/opensips/`basename "$$FILE"` ; \
				$(INSTALL_CFG) $$FILE \
					$(data-prefix)/$(data-dir)/db_berkeley/opensips/`basename "$$FILE"` ; \
				fi ;\
			done ; \
			$(INSTALL_BIN) utils/db_berkeley/bdb_recover $(bin-prefix)/$(bin-dir) ; \
		fi
		# install dbtext stuff
		if [ "$(DBTEXTON)" = "yes" ]; then \
			mkdir -p $(modules-prefix)/$(lib-dir)/opensipsctl ; \
			sed -e "s#/usr/local/share/opensips/#$(data-target)#g" \
				< scripts/opensipsctl.dbtext > /tmp/opensipsctl.dbtext ; \
			$(INSTALL_CFG) /tmp/opensipsctl.dbtext \
				$(modules-prefix)/$(lib-dir)/opensipsctl/opensipsctl.dbtext ; \
			rm -fr /tmp/opensipsctl.dbtext ; \
			sed -e "s#/usr/local/share/opensips#$(data-target)#g" \
				< scripts/opensipsdbctl.dbtext > /tmp/opensipsdbctl.dbtext ; \
			$(INSTALL_TOUCH) $(modules-prefix)/$(lib-dir)/opensipsctl/opensipsdbctl.dbtext ; \
			$(INSTALL_CFG) /tmp/opensipsdbctl.dbtext $(modules-prefix)/$(lib-dir)/opensipsctl/ ; \
			rm -fr /tmp/opensipsdbctl.dbtext ; \
			mkdir -p $(modules-prefix)/$(lib-dir)/opensipsctl/dbtextdb ; \
			$(INSTALL_TOUCH) $(modules-prefix)/$(lib-dir)/opensipsctl/dbtextdb/dbtextdb.py ; \
			$(INSTALL_BIN) scripts/dbtextdb/dbtextdb.py $(modules-prefix)/$(lib-dir)/opensipsctl/dbtextdb/ ; \
			mkdir -p $(data-prefix)/$(data-dir)/dbtext/opensips ; \
			for FILE in $(wildcard scripts/dbtext/opensips/*) ; do \
				if [ -f $$FILE ] ; then \
					$(INSTALL_TOUCH) $$FILE \
						$(data-prefix)/$(data-dir)/dbtext/opensips/`basename "$$FILE"` ; \
					$(INSTALL_CFG) $$FILE \
						$(data-prefix)/$(data-dir)/dbtext/opensips/`basename "$$FILE"` ; \
				fi ;\
			done ;\
		fi


.PHONY: install-doc install-app-doc install-modules-doc
install-doc: install-app-doc install-modules-doc

install-app-doc: $(doc-prefix)/$(doc-dir)
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
				$(INSTALL_TOUCH)  $(doc-prefix)/$(doc-dir)/README."$$r" ; \
				$(INSTALL_DOC)  modules/"$$r"/README  \
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
			< scripts/opensipsctl.8 > $(man-prefix)/$(man-dir)/man8/opensipsctl.8
		chmod 644  $(man-prefix)/$(man-dir)/man8/opensipsctl.8
		sed -e "s#/etc/$(NAME)/$(NAME)\.cfg#$(cfg-target)$(NAME).cfg#g" \
			-e "s#/usr/sbin/#$(bin-target)#g" \
			-e "s#/usr/lib/$(NAME)/modules/#$(modules-target)#g" \
			-e "s#/usr/share/doc/$(NAME)/#$(doc-target)#g" \
			< utils/opensipsunix/opensipsunix.8 > \
			$(man-prefix)/$(man-dir)/man8/opensipsunix.8
		chmod 644  $(man-prefix)/$(man-dir)/man8/opensipsunix.8

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

.PHONY: test
test:
	-@echo "Start tests"
	$(MAKE) -C test/
	-@echo "Tests finished"

doxygen:
	-@echo "Create Doxygen documentation"
	# disable call graphes, because of the DOT dependencies
	(cat doc/doxygen/opensips-doxygen; \
	echo "HAVE_DOT=no" ;\
	echo "PROJECT_NUMBER=$(NAME)-$(RELEASE)" )| doxygen -
	-@echo "Doxygen documentation created"
