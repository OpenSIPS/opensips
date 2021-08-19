# New ports collection makefile for:	opensips
# Date created:				20 October 2005
# Whom:					jesusr
#
# $FreeBSD: ports/net/opensips/Makefile,v 1.9 2007/08/20 09:12:42 miwi Exp $
#

PORTNAME=	opensips
PORTVERSION=	3.1.5
CATEGORIES=	net
MASTER_SITES=	https://opensips.org/pub/opensips/${PORTVERSION}/
DISTNAME=	${PORTNAME}-${PORTVERSION}-tls_src

MAINTAINER=	jesusr@FreeBSD.org
COMMENT=	A very fast and configurable SIP server with TLS support

LIB_DEPENDS=	radiusclient-ng.2:${PORTSDIR}/net/radiusclient

WRKSRC=		${WRKDIR}/${PORTNAME}-${PORTVERSION}-tls

USE_GMAKE=	yes
MAKE_ENV=	CC="${CC}" \
		CC_EXTRA_OPTS="${CFLAGS}" \
		PTHREAD_CFLAGS="${PTHREAD_CFLAGS}" \
		PTHREAD_LIBS="${PTHREAD_LIBS}"

PLIST_FILES=	sbin/opensips

PLIST_DIRS=	lib/opensips/modules lib/opensips

MODULES=	acc alias_db auth auth_db auth_diameter avpops benchmark \
		cfgutils dbtext dialog dispatcher diversion domain \
		domainpolicy enum exec flatstore gflags group imc \
		mangler maxfwd mediaproxy mi_datagram mi_fifo msilo nathelper \
		options path permissions pike registrar rr \
		siptrace sl speeddial sst statistics textops tm uac \
		uac_redirect uri_db usrloc xlog

RC_FILES=	acc/radiusclient.conf \
		acc/servers \
		dictionary.opensips \
		opensips.cfg
RC_DIRS=	acc

ONLY_FOR_ARCHS=	i386

MAN5=		opensips.cfg.5
MAN8=		opensips.8

PORTDOCS=	*

SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	RC_DIRS="${RC_DIRS}" RC_FILES="${RC_FILES}"

OPTIONS=	MYSQL "MySQL support" on \
		POSTGRESQL "PostgreSQL support" off \
		UNIXODBC "UnixODBC support" off \
		CPL "CPL_C support" off \
		TLS "TLS support" off \
		SNMPSTATS "SNMPStats support" off

.include <bsd.port.pre.mk>

.if defined(WITH_MYSQL)
USE_MYSQL=	yes
MODULES+=	mysql
.else
MAKE_ENV+=	MYSQL=mysql
.endif

.if defined(WITH_POSTGRESQL)
USE_PGSQL=	yes
MODULES+=	postgres
.else
MAKE_ENV+=	POSTGRESQL=postgres
.endif

.if defined(WITH_UNIXODBC)
LIB_DEPENDS+=	odbc.1:${PORTSDIR}/databases/unixODBC
MODULES+=	unixodbc
.else
MAKE_ENV+=	UNIXODBC=unixodbc
.endif

.if defined(WITH_CPL)
USE_GNOME=	libxml2
MODULES+=	cpl_c
PLIST_FILES+=	etc/opensips/cpl-06.dtd
.else
MAKE_ENV+=	CPL=cpl_c
.endif

.if defined(WITH_TLS)
MODULES+=	tlsops
.include "${PORTSDIR}/Mk/bsd.openssl.mk"
TLS_RC_FILES=	tls/rootCA/cacert.pem \
		tls/rootCA/certs/01.pem \
		tls/rootCA/index.txt \
		tls/rootCA/private/cakey.pem \
		tls/rootCA/serial \
		tls/user/user-calist.pem \
		tls/user/user-cert.pem \
		tls/user/user-cert_req.pem \
		tls/user/user-privkey.pem \
		tls/README \
		tls/ca.conf \
		tls/request.conf \
		tls/user.conf
RC_FILES+=	${TLS_RC_FILES}
TLS_RC_DIRS=	tls/user \
		tls/rootCA/certs \
		tls/rootCA/private \
		tls/rootCA \
		tls
RC_DIRS+=	${TLS_RC_DIRS}
.else
MAKE_ENV+=	TLSOPS=tlsops
MAKE_ARGS+=	TLS=""
.endif

.if defined(WITH_SNMPSTATS)
RUN_DEPENDS+=	snmpcheck:${PORTSDIR}/net-mgmt/net-snmp
MODULES+=	snmpstats
.else
MAKE_ENV+=	SNMPSTATS=snmpstats
.endif

PLIST_FILES+=	${MODULES:S|^|lib/opensips/modules/|:S|$|.so|} \
		${RC_FILES:S|^|etc/opensips/|:S|$|.default|}

post-patch:
.if defined(NOPORTDOCS)
	@${REINPLACE_CMD} -e 's|install-doc install-man|install-man|' \
		${WRKSRC}/Makefile
.endif
	@${REINPLACE_CMD} -e 's|-g -O9 ||' -e 's|-O9 ||' ${WRKSRC}/Makefile.defs
	@${REINPLACE_CMD} -e 's|/etc/opensips|${PREFIX}/etc/opensips|' \
		${WRKSRC}/modules/mediaproxy/README \
		${WRKSRC}/modules/cpl_c/README \
		${WRKSRC}/INSTALL
	@${REINPLACE_CMD} -e 's|/usr/local/sbin/opensips|${PREFIX}/sbin/opensips|' \
		${WRKSRC}/INSTALL
	@${REINPLACE_CMD} -e 's|/usr/local|${PREFIX}|' \
		${WRKSRC}/etc/opensips.cfg \
		${WRKSRC}/modules/acc/README \
		${WRKSRC}/modules/avp_radius/README \
		${WRKSRC}/modules/db_berkeley/README \
		${WRKSRC}/modules/ldap/README \
		${WRKSRC}/modules/osp/README \
		${WRKSRC}/modules/perl/README \
		${WRKSRC}/modules/snmpstats/README \
		${WRKSRC}/modules/speeddial/README \
		${WRKSRC}/modules/unixodbc/README
	@${REINPLACE_CMD} -e 's|/usr/local|${LOCALBASE}|' \
		${WRKSRC}/modules/acc/etc/radiusclient.conf
	@${REINPLACE_CMD} -e 's|/usr/local/etc/radiusclient|${PREFIX}/etc/opensips/acc|' \
		${WRKSRC}/modules/acc/acc_mod.c ${WRKSRC}/modules/acc/README

post-install:
	${INSTALL_DATA} ${WRKSRC}/etc/opensips.cfg \
		${PREFIX}/etc/opensips/opensips.cfg.default
	${MKDIR} ${PREFIX}/etc/opensips/acc
	${INSTALL_DATA} ${WRKSRC}/modules/acc/etc/radiusclient.conf \
		${PREFIX}/etc/opensips/acc/radiusclient.conf.default
	${INSTALL_DATA} ${WRKSRC}/modules/acc/etc/servers \
		${PREFIX}/etc/opensips/acc/servers.default
.for d in ${TLS_RC_DIRS}
	${MKDIR} ${PREFIX}/etc/opensips/${d}
.endfor
.for f in ${TLS_RC_FILES}
	${INSTALL_DATA} ${WRKSRC}/etc/${f} ${PREFIX}/etc/opensips/${f}.default
.endfor
	@PKG_PREFIX=${PREFIX} ${SH} ${PKGINSTALL} ${PKGNAME} POST-INSTALL

.include <bsd.port.post.mk>
