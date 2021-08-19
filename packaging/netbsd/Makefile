# New ports collection makefile for:    opensips
#
# $NetBSD$
#
# $Id$
#

COMMENT= "OpenSIPS"

PORTNAME= opensips
PORTVERSION= 3.1.5
CATEGORIES= net
MASTER_SITES= https://opensips.org/pub/opensips/3.1.5/

MAINTAINER= bogdan@opensips.org

MAN8=opensips.8
MAN5=opensips.cfg.5
# MANCOMPRESSED must not be specified (if defined is assumed to be yes)


USE_GMAKE= yes
USE_TOOLS+= gmake
# we override the DISTFILE NAME
DISTNAME= ${PORTNAME}-${PORTVERSION}
DISTFILES= ${DISTNAME}_src.tar.gz
WRKSRC= ${WRKDIR}/${PORTNAME}-${PORTVERSION}

# build by default mysql and jabber
MAKE_ENV= include_modules="mysql jabber"

# depends on expat and mysqlclient because of the above modules
DEPENDS= expat-[0-9]*:../../textproc/expat \
         mysql-client>=3.23.35:../../databases/mysql-client

#.include "/usr/pkgsrc/mk/bsd.prefs.mk"

pre-fetch:

.include "../../mk/bsd.pkg.mk"


