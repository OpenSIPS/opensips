# Copyright 1999-2005 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header$

inherit eutils

DESCRIPTION="OpenSIPS - flexible and robust SIP (RFC3261) server"
HOMEPAGE="https://opensips.org/"
MY_P="${P}_src"
SRC_URI="https://opensips.org/pub/opensips/${PV}/src/${MY_P}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~x86"
IUSE="debug ipv6 mysql postgres radius jabber ssl cpl unixodbc"

RDEPEND="
	mysql? ( >=dev-db/mysql-4.1.20 )
	radius? ( >=net-dialup/radiusclient-ng-0.5.0 )
	postgres? ( >=dev-db/postgresql-8.0.8 )
	jabber? ( dev-libs/expat )
	ssl? ( dev-libs/openssl )
	cpl? ( dev-libs/libxml2 )
	b2bua? ( dev-libs/libxml2 )
	presence? ( dev-libs/libxml2 )
	unixodbc? ( dev-libs/unixodbc-2.2.6 )"

inc_mod=""
make_options=""

pkg_setup() {
	use mysql && \
		inc_mod="${inc_mod} db_mysql"

	use postgres && \
		inc_mod="${inc_mod} db_postgres"

	use radius && \
		inc_mod="${inc_mod} aaa_radius peering"

	use jabber && \
		inc_mod="${inc_mod} jabber"

	use cpl && \
		inc_mod="${inc_mod} cpl_c"

	use b2bua && \
		inc_mod="${inc_mod} b2b_entities b2bua_logic"

	use presence && \
		inc_mod="${inc_mod} presence presence_dialoginfo presence_mwi presence_xcapdiff presence_xml pua pua_bla pua_dialoginfo pua_mi pua_usrloc pua_xmpp rls xcap xcap_client"

	use unixodbc && \
		inc_mod="${inc_mod} db_unixodbc"

	export inc_mod
}

src_unpack() {
	unpack ${MY_P}.tar.gz

	cd ${S}
	use ipv6
}

src_compile() {
	local compile_options

	pkg_setup

	# optimization can result in strange debuging symbols so omit it in case
	if use debug; then
		compile_options="${compile_options} mode=debug"
	else
		compile_options="${compile_options} CFLAGS=${CFLAGS}"
	fi
	
	if use ssl; then
		compile_options="TLS=1 ${compile_options}"
	fi

	emake all "${compile_options}" \
		prefix=${ROOT}/ \
		include_modules="${inc_mod}" \
		cfg_prefix=${ROOT}/ \
		cfg_target=${ROOT}/etc/opensips/ || die
}

src_install () {
	local install_options

	emake install \
		prefix=${D}/ \
		include_modules="${inc_mod}" \
		bin_prefix=${D}/usr/sbin \
		bin_dir="" \
		cfg_prefix=${D}/etc \
		cfg_dir=opensips/ \
		cfg_target=${D}/etc/opensips \
		modules_prefix=${D}/usr/lib/opensips \
		modules_dir=modules \
		modules_target=${D}/usr/lib/opensips/modules/ \
		man_prefix=${D}/usr/share/man \
		man_dir="" \
		doc_prefix=${D}/usr/share/doc \
		doc_dir=${PF} || die
	exeinto /etc/init.d
	newexe ${FILESDIR}/opensips.init opensips

	# fix what the Makefile don't do
	use mysql || \
		rm ${D}/usr/sbin/opensips_mysql.sh
}

pkg_postinst() {
	einfo "WARNING: If you upgraded from a previous OpenSIPS version"
	einfo "please read the README, NEWS and INSTALL files in the"
	einfo "documentation directory because the database and the"
	einfo "configuration file of old OpenSIPS versions are incompatible"
	einfo "with the current version."
}

pkg_prerm () {
	${D}/etc/init.d/opensips stop >/dev/null
}
