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
#                  Tomas Björklund <tomas@webservices.se>
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
#

#TLS=1
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
exclude_modules?= 		jabber cpl-c pa postgres osp unixodbc \
						avp_radius auth_radius group_radius uri_radius
# always exclude the CVS dir
override exclude_modules+= CVS $(skip_modules)

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
export LIBS
export LEX YACC YACC_FLAGS
export PREFIX LOCALBASE
# export relevant variables for recursive calls of this makefile 
# (e.g. make deb)
#export LIBS
#export TAR 
#export NAME RELEASE OS ARCH 
#export cfg-prefix cfg-dir bin-prefix bin-dir modules-prefix modules-dir
#export doc-prefix doc-dir man-prefix man-dir ut-prefix ut-dir
#export cfg-target modules-target
#export INSTALL INSTALL-CFG INSTALL-BIN INSTALL-MODULES INSTALL-DOC INSTALL-MAN 
#export INSTALL-TOUCH

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
all: $(NAME) modules



.PHONY: modules
modules:
	-@for r in $(modules) "" ; do \
		if [ -n "$$r" ]; then \
			echo  "" ; \
			echo  "" ; \
			$(MAKE) -C $$r ; \
		fi ; \
	done 

.PHONY: modules-readme
modules-readme:
	-@for r in  $(modules_basenames) "" ; do \
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
	-@for r in  $(modules_basenames) "" ; do \
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
	-@for r in  $(modules_basenames) "" ; do \
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
	-@for r in  $(modules_basenames) "" ; do \
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


$(extra_objs):
	-@echo "Extra objs: $(extra_objs)" 
	-@for r in $(static_modules_path) "" ; do \
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
		--exclude=$(notdir $(CURDIR))/packaging/debian/ser* \
		--exclude=$(notdir $(CURDIR))/ser_tls* \
		--exclude=CVS* \
		--exclude=.cvsignore \
		--exclude=.svn* \
		--exclude=*.[do] \
		--exclude=*.so \
		--exclude=*.il \
		--exclude=$(notdir $(CURDIR))/ser \
		--exclude=$(notdir $(CURDIR))/$(NAME) \
		--exclude=*.gz \
		--exclude=*.bz2 \
		--exclude=*.tar \
		--exclude=*.patch \
		--exclude=.\#* \
		--exclude=*.swp \
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
	ln -sf packaging/debian debian
	dpkg-buildpackage -rfakeroot -tc
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

mk-install-dirs: $(cfg-prefix)/$(cfg-dir) $(bin-prefix)/$(bin-dir) \
			$(modules-prefix)/$(modules-dir) $(doc-prefix)/$(doc-dir) \
			$(man-prefix)/$(man-dir)/man8 $(man-prefix)/$(man-dir)/man5

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
		
# note: on solaris 8 sed: ? or \(...\)* (a.s.o) do not work
install-cfg: $(cfg-prefix)/$(cfg-dir)
		sed -e "s#/usr/.*lib/openser/modules/#$(modules-target)#g" \
			< etc/openser.cfg > $(cfg-prefix)/$(cfg-dir)$(NAME).cfg.sample
		chmod 644 $(cfg-prefix)/$(cfg-dir)$(NAME).cfg.sample
		if [ -z "${skip_cfg_install}" -a \
				! -f $(cfg-prefix)/$(cfg-dir)$(NAME).cfg ]; then \
			mv -f $(cfg-prefix)/$(cfg-dir)$(NAME).cfg.sample \
				$(cfg-prefix)/$(cfg-dir)$(NAME).cfg; \
		fi
		# radius dictionary
		$(INSTALL-TOUCH) $(cfg-prefix)/$(cfg-dir)/dictionary.radius
		$(INSTALL-CFG) etc/dictionary.radius $(cfg-prefix)/$(cfg-dir)
		#$(INSTALL-CFG) etc/$(NAME).cfg $(cfg-prefix)/$(cfg-dir)
		if [ -z $(TLS) ]; then \
			echo  "No TLS scripts installed" ; \
		else \
			mkdir $(cfg-prefix)/$(cfg-dir)/tls ; \
			mkdir $(cfg-prefix)/$(cfg-dir)/tls/rootCA ; \
			mkdir $(cfg-prefix)/$(cfg-dir)/tls/rootCA/certs ; \
			mkdir $(cfg-prefix)/$(cfg-dir)/tls/rootCA/private ; \
			mkdir $(cfg-prefix)/$(cfg-dir)/tls/user ; \
			$(INSTALL-TOUCH) etc/tls/README $(cfg-prefix)/$(cfg-dir)/tls/; \
			$(INSTALL) etc/tls/README $(cfg-prefix)/$(cfg-dir)/tls/; \
			$(INSTALL-TOUCH) etc/tls/rootCA/index.txt $(cfg-prefix)/$(cfg-dir)/tls/rootCA/; \
			$(INSTALL) etc/tls/rootCA/index.txt $(cfg-prefix)/$(cfg-dir)/tls/rootCA/; \
			$(INSTALL-TOUCH) etc/tls/rootCA/serial $(cfg-prefix)/$(cfg-dir)/tls/rootCA/; \
			$(INSTALL) etc/tls/rootCA/serial $(cfg-prefix)/$(cfg-dir)/tls/rootCA/; \
			$(INSTALL-TOUCH) etc/tls/rootCA/cacert.pem $(cfg-prefix)/$(cfg-dir)/tls/rootCA/; \
			$(INSTALL) etc/tls/rootCA/cacert.pem $(cfg-prefix)/$(cfg-dir)/tls/rootCA/; \
			$(INSTALL-TOUCH) etc/tls/rootCA/certs/01.pem $(cfg-prefix)/$(cfg-dir)/tls/rootCA/certs/; \
			$(INSTALL) etc/tls/rootCA/certs/01.pem $(cfg-prefix)/$(cfg-dir)/tls/rootCA/certs/; \
			$(INSTALL-TOUCH) etc/tls/rootCA/private/cakey.pem $(cfg-prefix)/$(cfg-dir)/tls/rootCA/private/; \
			$(INSTALL) etc/tls/rootCA/private/cakey.pem $(cfg-prefix)/$(cfg-dir)/tls/rootCA/private/; \
			$(INSTALL-TOUCH) etc/tls/user/user-calist.pem $(cfg-prefix)/$(cfg-dir)/tls/user/; \
			$(INSTALL) etc/tls/user/user-calist.pem $(cfg-prefix)/$(cfg-dir)/tls/user/; \
			$(INSTALL-TOUCH) etc/tls/user/user-cert.pem $(cfg-prefix)/$(cfg-dir)/tls/users/; \
			$(INSTALL) etc/tls/user/user-cert.pem $(cfg-prefix)/$(cfg-dir)/tls/user/; \
			$(INSTALL-TOUCH) etc/tls/user/user-privkey.pem $(cfg-prefix)/$(cfg-dir)/tls/user/; \
			$(INSTALL) etc/tls/user/user-privkey.pem $(cfg-prefix)/$(cfg-dir)/tls/user/; \
			$(INSTALL-TOUCH) etc/tls/user/user-cert_req.pem $(cfg-prefix)/$(cfg-dir)/tls/user/; \
			$(INSTALL) etc/tls/user/user-cert_req.pem $(cfg-prefix)/$(cfg-dir)/tls/user/; \
		fi

install-bin: $(bin-prefix)/$(bin-dir) utils/gen_ha1/gen_ha1 utils/$(NAME)unix/$(NAME)unix
		$(INSTALL-TOUCH) $(bin-prefix)/$(bin-dir)/$(NAME) 
		$(INSTALL-BIN) $(NAME) $(bin-prefix)/$(bin-dir)
		$(INSTALL-TOUCH)   $(bin-prefix)/$(bin-dir)/sc
		$(INSTALL-BIN) scripts/sc $(bin-prefix)/$(bin-dir)
		mv -f $(bin-prefix)/$(bin-dir)/sc $(bin-prefix)/$(bin-dir)/$(NAME)ctl
		$(INSTALL-TOUCH)   $(bin-prefix)/$(bin-dir)/mysqldb.sh  
		$(INSTALL-BIN) scripts/mysqldb.sh  $(bin-prefix)/$(bin-dir)
		mv -f $(bin-prefix)/$(bin-dir)/mysqldb.sh $(bin-prefix)/$(bin-dir)/$(NAME)_mysql.sh
		$(INSTALL-TOUCH)   $(bin-prefix)/$(bin-dir)/$(NAME)_gen_ha1
		$(INSTALL-BIN) utils/gen_ha1/gen_ha1 $(bin-prefix)/$(bin-dir)/$(NAME)_gen_ha1
		$(INSTALL-TOUCH)   $(bin-prefix)/$(bin-dir)/$(NAME)unix
		$(INSTALL-BIN) utils/$(NAME)unix/$(NAME)unix $(bin-prefix)/$(bin-dir)

utils/gen_ha1/gen_ha1:
		cd utils/gen_ha1; $(MAKE) all

utils/$(NAME)unix/$(NAME)unix:
		cd utils/$(NAME)unix; $(MAKE) all

install-modules: modules $(modules-prefix)/$(modules-dir)
	-@for r in $(modules_full_path) "" ; do \
		if [ -n "$$r" ]; then \
			if [ -f "$$r" ]; then \
				$(INSTALL-TOUCH) \
					$(modules-prefix)/$(modules-dir)/`basename "$$r"` ; \
				$(INSTALL-MODULES)  "$$r"  $(modules-prefix)/$(modules-dir) ; \
			else \
				echo "ERROR: module $$r not compiled" ; \
			fi ;\
		fi ; \
	done 


install-modules-all: install-modules install-modules-doc


install-doc: $(doc-prefix)/$(doc-dir) install-modules-doc
	$(INSTALL-TOUCH) $(doc-prefix)/$(doc-dir)/INSTALL 
	$(INSTALL-DOC) INSTALL $(doc-prefix)/$(doc-dir)
	$(INSTALL-TOUCH) $(doc-prefix)/$(doc-dir)/README-MODULES 
	$(INSTALL-DOC) README-MODULES $(doc-prefix)/$(doc-dir)
	$(INSTALL-TOUCH) $(doc-prefix)/$(doc-dir)/AUTHORS 
	$(INSTALL-DOC) AUTHORS $(doc-prefix)/$(doc-dir)
	$(INSTALL-TOUCH) $(doc-prefix)/$(doc-dir)/NEWS
	$(INSTALL-DOC) NEWS $(doc-prefix)/$(doc-dir)
	$(INSTALL-TOUCH) $(doc-prefix)/$(doc-dir)/README 
	$(INSTALL-DOC) README $(doc-prefix)/$(doc-dir)


install-modules-doc: $(doc-prefix)/$(doc-dir)
	-@for r in $(modules_basenames) "" ; do \
		if [ -n "$$r" ]; then \
			if [ -f modules/"$$r"/README ]; then \
				$(INSTALL-TOUCH)  $(doc-prefix)/$(doc-dir)/README ; \
				$(INSTALL-DOC)  modules/"$$r"/README  \
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

install-modules-docbook: $(doc-prefix)/$(doc-dir)
	-@for r in $(modules_basenames) "" ; do \
		if [ -n "$$r" ]; then \
			if [ -d modules/"$$r"/doc ]; then \
				if [ -f modules/"$$r"/doc/"$$r".txt ]; then \
					$(INSTALL-TOUCH)  $(doc-prefix)/$(doc-dir)/"$$r".txt ; \
					$(INSTALL-DOC)  modules/"$$r"/doc/"$$r".txt  \
									$(doc-prefix)/$(doc-dir)/"$$r".txt ; \
				fi ; \
				if [ -f modules/"$$r"/doc/"$$r".html ]; then \
					$(INSTALL-TOUCH)  $(doc-prefix)/$(doc-dir)/"$$r".html ; \
					$(INSTALL-DOC)  modules/"$$r"/doc/"$$r".html  \
									$(doc-prefix)/$(doc-dir)/"$$r".html ; \
				fi ; \
				if [ -f modules/"$$r"/doc/"$$r".pdf ]; then \
					$(INSTALL-TOUCH)  $(doc-prefix)/$(doc-dir)/"$$r".pdf ; \
					$(INSTALL-DOC)  modules/"$$r"/doc/"$$r".pdf  \
									$(doc-prefix)/$(doc-dir)/"$$r".pdf ; \
				fi ; \
			fi ; \
		fi ; \
	done
