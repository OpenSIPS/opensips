%define	EXCLUDE_MODULES	mi_xmlrpc osp

Summary:	Open Source SIP Server
Name:		opensips
Version:	1.6.0
Release:	1%{?dist}
License:	GPLv2+
Group:		System Environment/Daemons
Source0:	http://www.opensips.org/pub/%{name}/%{version}/src/%{name}-%{version}-tls_src.tar.gz
Source1:	opensips.init
Patch1:		opensips--openssl-paths.diff
URL:		http://www.opensips.org/

BuildRequires:	expat-devel
BuildRequires:	libxml2-devel
BuildRequires: 	bison
BuildRequires: 	flex
# needed by snmpstats
BuildRequires:	radiusclient-ng-devel
BuildRequires:	mysql-devel
BuildRequires:	postgresql-devel
# required by snmpstats module
BuildRequires:	lm_sensors-devel
BuildRequires:	net-snmp-devel
BuildRequires:	unixODBC-devel
BuildRequires:	openssl-devel
BuildRequires:	expat-devel
#BuildRequires:	xmlrpc-c-devel
BuildRequires:	libconfuse-devel
BuildRequires:	db4-devel
BuildRequires:	openldap-devel
BuildRequires:	curl-devel

Requires(post):	/sbin/chkconfig
Requires(preun):/sbin/chkconfig
Requires(preun):/sbin/service
BuildRoot: 	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
OpenSIPS or Open SIP Server is a very fast and flexible SIP (RFC3261)
server. Written entirely in C, OpenSIPS can handle thousands calls
per second even on low-budget hardware. A C Shell like scripting language
provides full control over the server's behaviour. It's modular
architecture allows only required functionality to be loaded.
Currently the following modules are available: digest authentication,
CPL scripts, instant messaging, MySQL and UNIXODBC support, a presence agent,
radius authentication, record routing, an SMS gateway, a jabber gateway, a 
transaction and dialog module, OSP module, statistics support, 
registrar and user location.

%package	acc
Summary:	Accounts transactions information to different backends
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	acc
ACC module is used to account transactions information to different backends 
like syslog, SQL, AAA.

%package	auth_diameter
Summary:	Performs authentication using a Diameter server
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	auth_diameter
This module implements SIP authentication and authorization with DIAMETER
server, namely DIameter Server Client (DISC).

%package	auth_aaa
Summary:	Performs authentication using a Radius server
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	auth_aaa
This module contains functions that are used to perform authentication using
a Radius server.  Basically the proxy will pass along the credentials to the
radius server which will in turn send a reply containing result of the
authentication. So basically the whole authentication is done in the Radius
server.

%package	carrierroute
Summary:	Routing extension suitable for carriers
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	carrierroute
A module which provides routing, balancing and blacklisting capabilities.

%package	cpl-c
Summary:	Call Processing Language interpreter
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	cpl-c
This module implements a CPL (Call Processing Language) interpreter.
Support for uploading/downloading/removing scripts via SIP REGISTER method
is present.

%package	aaa_radius
Summary:	RADIUS backend for AAA api
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	aaa_radius
This module provides the RADIUS backend for the AAA API - group, auth, uri
module use the AAA API for performing RADIUS ops.

%package	db_berkeley
Summary:	Berkley DB backend support
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	db_berkeley
This is a module which integrates the Berkeley DB into OpenSIPS. It implements 
the DB API defined in OpenSIPS.

%package	h350
Summary:	H350 implementation	
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	h350
The OpenSIPS H350 module enables an OpenSIPS SIP server to access SIP 
account data stored in an LDAP [RFC4510] directory  containing H.350 [H.350] 
commObjects. 

%package	jabber
Summary:	Gateway between OpenSIPS and a jabber server
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description 	jabber
Jabber module that integrates XODE XML parser for parsing Jabber messages.

%package	ldap
Summary:	LDAP connector
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	ldap
The LDAP module implements an LDAP search interface for OpenSIPS.

%package	mysql
Summary:	MySQL Storage Support for the OpenSIPS
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description 	mysql
The %{name}-mysql package contains the MySQL plugin for %{name}, which allows
a MySQL-Database to be used for persistent storage.

%package 	perl
Summary:	Helps implement your own OpenSIPS extensions in Perl
Group:		System Environment/Daemons
# require perl-devel for >F7 and perl for <=F6
BuildRequires:	perl(ExtUtils::MakeMaker)
Requires:	%{name} = %{version}-%{release}
Requires:	perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))

%description	perl
The time needed when writing a new OpenSIPS module unfortunately is quite
high, while the options provided by the configuration file are limited to
the features implemented in the modules. With this Perl module, you can
easily implement your own OpenSIPS extensions in Perl.  This allows for
simple access to the full world of CPAN modules. SIP URI rewriting could be
implemented based on regular expressions; accessing arbitrary data backends,
e.g. LDAP or Berkeley DB files, is now extremely simple.

%package	perlvdb
Summary:	Perl virtual database engine
Group:		System Environment/Daemons
# require perl-devel for >F7 and perl for <=F6
BuildRequires:	perl(ExtUtils::MakeMaker)
Requires:	%{name} = %{version}-%{release}
Requires:	%{name}-perl
Requires:	perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))

%description	perlvdb
The Perl Virtual Database (VDB) provides a virtualization framework for 
OpenSIPS's database access. It does not handle a particular database engine 
itself but lets the user relay database requests to arbitrary Perl functions.

%package	postgresql
Summary:	PostgreSQL Storage Support for the OpenSIPS
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	postgresql
The %{name}-postgresql package contains the PostgreSQL plugin for %{name},
which allows a PostgreSQL-Database to be used for persistent storage.

%package	b2bua
Summary:	Back-2-Back User Agent
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	b2bua
This package provides modules for B2BUA suppor in OpenSIPS. Both the 
implementation and controll (XML based scenario description) are included.

%package	presence
Summary:	Presence server
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	presence
This module implements a presence server. It handles PUBLISH and SUBSCRIBE
messages and generates NOTIFY messages. It offers support for aggregation
of published presence information for the same presentity using more devices.
It can also filter the information provided to watchers according to privacy
rules.

%package	presence_mwi
Summary:	Extension to Presence server for Message Waiting Indication
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	%{name}-presence

%description	presence_mwi
The module does specific handling for notify-subscribe message-summary 
(message waiting indication) events as specified in RFC 3842. It is used 
with the general event handling module, presence. It constructs and adds 
message-summary event to it.

%package	presence_xml
Summary:	SIMPLE Presence extension
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	%{name}-presence
Requires:	%{name}-xcap_client

%description	presence_xml
The module does specific handling for notify-subscribe events using xml bodies.
It is used with the general event handling module, presence.

%package	presence_dialoginfo
Summary:	SIMPLE Presence extension for dialog info
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	%{name}-presence
Requires:	%{name}-xcap_client

%description	presence_dialoginfo
The module enables the handling of "Event: dialog" (as defined
in RFC 4235) inside of the presence module. This can be used
distribute the dialog-info status to the subscribed watchers.

%package	presence_xcapdiff
Summary:	SIMPLE Presence extension for XCAP diff
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	%{name}-presence
Requires:	%{name}-xcap_client

%description	presence_xcapdiff
The presence_xcapdiff is an OpenSIPS module that adds support
for the "xcap-diff" event to presence and pua.

%package	pua
Summary:	Offer the functionality of a presence user agent client
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	pua
This module offer the functionality of a presence user agent client, sending
Subscribe and Publish messages.

%package	pua_bla
Summary:	BLA extension for PUA
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	%{name}-pua
Requires:	%{name}-presence

%description	pua_bla
The pua_bla module enables Bridged Line Appearances support according to the 
specifications in draft-anil-sipping-bla-03.txt.

%package	pua_dialoginfo
Summary:	Dialog Info extension for PUA
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	%{name}-pua
Requires:	%{name}-presence

%description	pua_dialoginfo
The pua_dialoginfo retrieves dialog state information from the
dialog module and PUBLISHes the dialog-information using the
pua module (RFC 4235)

%package	pua_mi
Summary:	Connector between usrloc and MI interface
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	%{name}-pua

%description	pua_mi
The pua_mi sends offer the possibility to publish presence information
via MI transports.  Using this module you can create independent
applications/scripts to publish not sip-related information (e.g., system
resources like CPU-usage, memory, number of active subscribers ...)

%package	pua_usrloc
Summary:	Connector between usrloc and pua modules
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	%{name}-pua

%description	pua_usrloc
This module is the connector between usrloc and pua modules. It creates the
environment to send PUBLISH requests for user location records, on specific
events (e.g., when new record is added in usrloc, a PUBLISH with status open
(online) is issued; when expires, it sends closed (offline)). Using this
module, phones which have no support for presence can be seen as
online/offline.

%package	pua_xmpp
Summary:	SIMPLE-XMPP Presence gateway 
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	%{name}-pua
Requires:	%{name}-presence
Requires:	%{name}-xmpp

%description	pua_xmpp
This module is a gateway for presence between SIP and XMPP. It translates one 
format into another and uses xmpp, pua and presence modules to manage the 
transmition of presence state information.

%package	rls
Summary:	Resource List Server
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}
Requires:	%{name}-pua
Requires:	%{name}-presence

%description	rls
The modules is a Resource List Server implementation following the 
specification in RFC 4662 and RFC 4826.

%package	seas
Summary:	Transfers the execution logic control to a given external entity
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	seas
SEAS module enables OpenSIPS to transfer the execution logic control of a sip
message to a given external entity, called the Application Server. When the
OpenSIPS script is being executed on an incoming SIP message, invocation of
the as_relay_t() function makes this module send the message along with some
transaction information to the specified Application Server. The Application
Server then executes some call-control logic code, and tells OpenSIPS to take
some actions, ie. forward the message downstream, or respond to the message
with a SIP repy, etc

%package	sms
Summary:	Gateway between SIP and GSM networks via sms
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	sms
This module provides a way of communication between SIP network (via SIP
MESSAGE) and GSM networks (via ShortMessageService). Communication is
possible from SIP to SMS and vice versa.  The module provides facilities
like SMS confirmation--the gateway can confirm to the SIP user if his
message really reached its destination as a SMS--or multi-part messages--if
a SIP messages is too long it will be split and sent as multiple SMS.

%package	snmpstats
Summary:	SNMP management interface for the OpenSIPS
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	snmpstats
The %{name}-snmpstats package provides an SNMP management interface to
OpenSIPS.  Specifically, it provides general SNMP queryable scalar statistics,
table representations of more complicated data such as user and contact
information, and alarm monitoring capabilities.

%package	tlsops
Summary:	TLS-relating functions for the OpenSIPS
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	tlsops
The %{name}-tlsops package implements TLS related functions to use in the
routing script, and exports pseudo variables with certificate and TLS
parameters.

%package	unixodbc
Summary:	OpenSIPS unixODBC Storage support
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	unixodbc
The %{name}-unixodbc package contains the unixODBC plugin for %{name}, which
allows a unixODBC to be used for persistent storage

%package	xcap_client
Summary:	XCAP client
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	xcap_client
The modules is an XCAP client for OpenSIPS that can be used by other modules.
It fetches XCAP elements, either documents or part of them, by sending HTTP 
GET requests. It also offers support for conditional queries. It uses libcurl 
library as a client-side HTTP transfer library.

%package	xmpp
Summary:	Gateway between OpenSIPS and a jabber server
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description	xmpp
This modules is a gateway between OpenSIPS and a jabber server. It enables
the exchange of instant messages between SIP clients and XMPP(jabber)
clients.

%prep
%setup -q -n %{name}-%{version}-tls
%patch1

%build
LOCALBASE=/usr CFLAGS="%{optflags}" %{__make} all %{?_smp_mflags} TLS=1 \
  exclude_modules="%EXCLUDE_MODULES" \
  cfg-target=%{_sysconfdir}/opensips/ \
  modules-dir=%{_lib}/opensips/modules

%install
rm -rf $RPM_BUILD_ROOT
%{__make} install TLS=1 exclude_modules="%EXCLUDE_MODULES" \
  basedir=%{buildroot} prefix=%{_prefix} \
  cfg-prefix=%{buildroot} \
  modules-dir=%{_lib}/opensips/modules

# clean some things
mkdir -p $RPM_BUILD_ROOT/%{perl_vendorlib}
mv $RPM_BUILD_ROOT/%{_libdir}/opensips/perl/* \
  $RPM_BUILD_ROOT/%{perl_vendorlib}/
mv $RPM_BUILD_ROOT/%{_sysconfdir}/opensips/tls/README \
  $RPM_BUILD_ROOT/%{_docdir}/opensips/README.tls
rm -f $RPM_BUILD_ROOT%{_docdir}/opensips/INSTALL
mv $RPM_BUILD_ROOT/%{_docdir}/opensips docdir

# recode documentation
for i in docdir/*; do
  mv -f $i $i.old
  iconv -f iso8859-1 -t UTF-8 $i.old > $i
  rm -f $i.old
done

mkdir -p $RPM_BUILD_ROOT%{_initrddir}
%{__install} -p -D -m 755 %{SOURCE1} \
  $RPM_BUILD_ROOT%{_initrddir}/opensips
echo -e "\nETCDIR=\"%{_sysconfdir}/opensips\"\n" \
  >> $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/opensipsctlrc

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/chkconfig --add opensips

%preun
if [ $1 = 0 ]; then
 /sbin/service opensips stop > /dev/null 2>&1
 /sbin/chkconfig --del opensips
fi

%files
%defattr(-,root,root,-)
%{_sbindir}/opensips
%{_sbindir}/opensipsctl
%{_sbindir}/opensipsdbctl
%{_sbindir}/opensipsunix

%dir %{_sysconfdir}/opensips
%dir %{_sysconfdir}/opensips/tls
%dir %{_libdir}/opensips/
%dir %{_libdir}/opensips/modules/
%dir %{_libdir}/opensips/opensipsctl/

%attr(755,root,root) %{_initrddir}/opensips

%config(noreplace) %{_sysconfdir}/opensips/dictionary.opensips
%config(noreplace) %{_sysconfdir}/opensips/opensips.cfg
%config(noreplace) %{_sysconfdir}/opensips/opensipsctlrc

%config(noreplace) %{_sysconfdir}/opensips/tls/ca.conf
%config(noreplace) %{_sysconfdir}/opensips/tls/request.conf
%config(noreplace) %{_sysconfdir}/opensips/tls/rootCA/cacert.pem
%config(noreplace) %{_sysconfdir}/opensips/tls/rootCA/certs/01.pem
%config(noreplace) %{_sysconfdir}/opensips/tls/rootCA/index.txt
%config(noreplace) %{_sysconfdir}/opensips/tls/rootCA/private/cakey.pem
%config(noreplace) %{_sysconfdir}/opensips/tls/rootCA/serial
%config(noreplace) %{_sysconfdir}/opensips/tls/user.conf
%config(noreplace) %{_sysconfdir}/opensips/tls/user/user-calist.pem
%config(noreplace) %{_sysconfdir}/opensips/tls/user/user-cert.pem
%config(noreplace) %{_sysconfdir}/opensips/tls/user/user-cert_req.pem
%config(noreplace) %{_sysconfdir}/opensips/tls/user/user-privkey.pem

%{_libdir}/opensips/opensipsctl/opensipsctl.*
%{_libdir}/opensips/opensipsctl/opensipsdbctl.base
%{_libdir}/opensips/opensipsctl/opensipsdbctl.dbtext

%{_datadir}/opensips/dbtext/opensips/*

%{_mandir}/man5/opensips.cfg.5*
%{_mandir}/man8/opensips.8*
%{_mandir}/man8/opensipsctl.8*
%{_mandir}/man8/opensipsunix.8*

%doc docdir/AUTHORS
%doc docdir/NEWS
%doc docdir/README
%doc docdir/README-MODULES
%doc docdir/README.tls

%{_libdir}/opensips/modules/alias_db.so
%{_libdir}/opensips/modules/auth.so
%{_libdir}/opensips/modules/auth_aaa.so
%{_libdir}/opensips/modules/auth_db.so
%{_libdir}/opensips/modules/avpops.so
%{_libdir}/opensips/modules/benchmark.so
%{_libdir}/opensips/modules/call_control.so
%{_libdir}/opensips/modules/cfgutils.so
%{_libdir}/opensips/modules/closeddial.so
%{_libdir}/opensips/modules/db_flatstore.so
%{_libdir}/opensips/modules/db_text.so
%{_libdir}/opensips/modules/db_virtual.so
%{_libdir}/opensips/modules/dialog.so
%{_libdir}/opensips/modules/dialplan.so
%{_libdir}/opensips/modules/dispatcher.so
%{_libdir}/opensips/modules/diversion.so
%{_libdir}/opensips/modules/domain.so
%{_libdir}/opensips/modules/drouting.so
%{_libdir}/opensips/modules/enum.so
%{_libdir}/opensips/modules/exec.so
%{_libdir}/opensips/modules/gflags.so
%{_libdir}/opensips/modules/group.so
%{_libdir}/opensips/modules/imc.so
%{_libdir}/opensips/modules/lcr.so
%{_libdir}/opensips/modules/load_balancer.so
%{_libdir}/opensips/modules/localcache.so
%{_libdir}/opensips/modules/mangler.so
%{_libdir}/opensips/modules/maxfwd.so
%{_libdir}/opensips/modules/mediaproxy.so
%{_libdir}/opensips/modules/mi_datagram.so
%{_libdir}/opensips/modules/mi_fifo.so
%{_libdir}/opensips/modules/msilo.so
%{_libdir}/opensips/modules/nathelper.so
%{_libdir}/opensips/modules/nat_traversal.so
%{_libdir}/opensips/modules/options.so
%{_libdir}/opensips/modules/path.so
%{_libdir}/opensips/modules/pdt.so
%{_libdir}/opensips/modules/permissions.so
%{_libdir}/opensips/modules/pike.so
%{_libdir}/opensips/modules/qos.so
%{_libdir}/opensips/modules/ratelimit.so
%{_libdir}/opensips/modules/registrar.so
%{_libdir}/opensips/modules/rr.so
%{_libdir}/opensips/modules/signaling.so
%{_libdir}/opensips/modules/siptrace.so
%{_libdir}/opensips/modules/sl.so
%{_libdir}/opensips/modules/speeddial.so
%{_libdir}/opensips/modules/sst.so
%{_libdir}/opensips/modules/statistics.so
%{_libdir}/opensips/modules/textops.so
%{_libdir}/opensips/modules/stun.so
%{_libdir}/opensips/modules/tm.so
%{_libdir}/opensips/modules/uac.so
%{_libdir}/opensips/modules/uac_redirect.so
%{_libdir}/opensips/modules/uri.so
%{_libdir}/opensips/modules/userblacklist.so
%{_libdir}/opensips/modules/usrloc.so
%{_libdir}/opensips/modules/xlog.so

%doc docdir/opensips/README.alias_db
%doc docdir/opensips/README.auth
%doc docdir/opensips/README.auth_aaa
%doc docdir/opensips/README.auth_db
%doc docdir/opensips/README.avpops
%doc docdir/opensips/README.benchmark
%doc docdir/opensips/README.call_control
%doc docdir/opensips/README.cfgutils
%doc docdir/opensips/README.closeddial
%doc docdir/opensips/README.db_flatstore
%doc docdir/opensips/README.db_text
%doc docdir/opensips/README.db_virtual
%doc docdir/opensips/README.dialog
%doc docdir/opensips/README.dialplan
%doc docdir/opensips/README.dispatcher
%doc docdir/opensips/README.diversion
%doc docdir/opensips/README.domain
%doc docdir/opensips/README.drouting
%doc docdir/opensips/README.enum
%doc docdir/opensips/README.exec
%doc docdir/opensips/README.gflags
%doc docdir/opensips/README.group
%doc docdir/opensips/README.imc
%doc docdir/opensips/README.lcr
%doc docdir/opensips/README.load_balancer
%doc docdir/opensips/README.localcache
%doc docdir/opensips/README.mangler
%doc docdir/opensips/README.maxfwd
%doc docdir/opensips/README.mediaproxy
%doc docdir/opensips/README.mi_datagram
%doc docdir/opensips/README.mi_fifo
%doc docdir/opensips/README.msilo
%doc docdir/opensips/README.nathelper
%doc docdir/opensips/README.nat_traversal
%doc docdir/opensips/README.options
%doc docdir/opensips/README.path
%doc docdir/opensips/README.pdt
%doc docdir/opensips/README.permissions
%doc docdir/opensips/README.pike
%doc docdir/opensips/README.qos
%doc docdir/opensips/README.ratelimit
%doc docdir/opensips/README.registrar
%doc docdir/opensips/README.rr
%doc docdir/opensips/README.signaling
%doc docdir/opensips/README.siptrace
%doc docdir/opensips/README.sl
%doc docdir/opensips/README.speeddial
%doc docdir/opensips/README.sst
%doc docdir/opensips/README.statistics
%doc docdir/opensips/README.stun
%doc docdir/opensips/README.textops
%doc docdir/opensips/README.tm
%doc docdir/opensips/README.uac
%doc docdir/opensips/README.uac_redirect
%doc docdir/opensips/README.uri
%doc docdir/opensips/README.userblacklist
%doc docdir/opensips/README.usrloc
%doc docdir/opensips/README.xlog

%files acc
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/acc.so
%doc docdir/README.acc

%files auth_diameter
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/auth_diameter.so
%doc docdir/README.auth_diameter

%files auth_aaa
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/auth_aaa.so
%doc docdir/README.auth_aaa

%files carrierroute
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/carrierroute.so
%doc docdir/README.carrierroute

%files cpl-c
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/cpl-c.so
%doc docdir/README.cpl-c

%files db_berkeley
%defattr(-,root,root,-)
%{_sbindir}/bdb_recover
%{_libdir}/opensips/modules/db_berkeley.so
%{_libdir}/opensips/opensipsctl/opensipsdbctl.db_berkeley
%{_datadir}/opensips/db_berkeley/opensips/*
%doc docdir/README.db_berkeley

%files aaa_radius
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/aaa_radius.so
%doc docdir/README.aaa_radius

%files h350
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/h350.so
%doc docdir/README.h350

%files jabber
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/jabber.so
%doc docdir/README.jabber

%files ldap
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/ldap.so
%doc docdir/README.ldap

%files mysql
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/db_mysql.so
%{_libdir}/opensips/opensipsctl/opensipsdbctl.mysql
%{_datadir}/opensips/mysql/*.sql
%doc docdir/README.mysql

%files perl
%defattr(-,root,root,-)
%dir %{perl_vendorlib}/OpenSIPS
%dir %{perl_vendorlib}/OpenSIPS/LDAPUtils
%dir %{perl_vendorlib}/OpenSIPS/Utils
%{_libdir}/opensips/modules/perl.so
%{perl_vendorlib}/OpenSIPS.pm
%{perl_vendorlib}/OpenSIPS/Constants.pm
%{perl_vendorlib}/OpenSIPS/LDAPUtils/LDAPConf.pm
%{perl_vendorlib}/OpenSIPS/LDAPUtils/LDAPConnection.pm
%{perl_vendorlib}/OpenSIPS/Message.pm
%{perl_vendorlib}/OpenSIPS/Utils/PhoneNumbers.pm
%{perl_vendorlib}/OpenSIPS/Utils/Debug.pm
%doc docdir/README.perl

%files perlvdb
%defattr(-,root,root,-)
%dir %{perl_vendorlib}/OpenSIPS/VDB
%dir %{perl_vendorlib}/OpenSIPS/VDB/Adapter
%{_libdir}/opensips/modules/perlvdb.so
%{perl_vendorlib}/OpenSIPS/VDB.pm
%{perl_vendorlib}/OpenSIPS/VDB/Adapter/AccountingSIPtrace.pm
%{perl_vendorlib}/OpenSIPS/VDB/Adapter/Alias.pm
%{perl_vendorlib}/OpenSIPS/VDB/Adapter/Auth.pm
%{perl_vendorlib}/OpenSIPS/VDB/Adapter/Describe.pm
%{perl_vendorlib}/OpenSIPS/VDB/Adapter/Speeddial.pm
%{perl_vendorlib}/OpenSIPS/VDB/Adapter/TableVersions.pm
%{perl_vendorlib}/OpenSIPS/VDB/Column.pm
%{perl_vendorlib}/OpenSIPS/VDB/Pair.pm
%{perl_vendorlib}/OpenSIPS/VDB/ReqCond.pm
%{perl_vendorlib}/OpenSIPS/VDB/Result.pm
%{perl_vendorlib}/OpenSIPS/VDB/VTab.pm
%{perl_vendorlib}/OpenSIPS/VDB/Value.pm
%doc docdir/README.perlvdb

%files postgresql
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/db_postgres.so
%{_libdir}/opensips/opensipsctl/opensipsdbctl.pgsql
%{_datadir}/opensips/postgres/*.sql
%doc docdir/README.postgres

%files b2bua
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/b2b_entities.so
%{_libdir}/opensips/modules/b2b_logic.so
%doc docdir/README.b2b_entities
%doc docdir/README.b2b_logic

%files presence
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/presence.so
%doc docdir/README.presence

%files presence_mwi
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/presence_mwi.so
%doc docdir/README.presence_mwi

%files presence_xml
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/presence_xml.so
%doc docdir/README.presence_xml

%files presence_dialoginfo
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/presence_dialoginfo.so
%doc docdir/README.presence_dialoginfo

%files presence_xcapdiff
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/presence_xcapdiff.so
%doc docdir/README.presence_xcapdiff

%files pua
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/pua.so
%doc docdir/README.pua

%files pua_bla
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/pua_bla.so
%doc docdir/README.pua_bla

%files pua_dialoginfo
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/pua_dialoginfo.so
%doc docdir/README.pua_dialoginfo

%files pua_mi
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/pua_mi.so
%doc docdir/README.pua_mi

%files pua_usrloc
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/pua_usrloc.so
%doc docdir/README.pua_usrloc

%files pua_xmpp
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/pua_xmpp.so
%doc docdir/README.pua_xmpp

%files rls
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/rls.so
%doc docdir/README.rls

%files seas
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/seas.so
%doc docdir/README.seas

%files sms
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/sms.so
%doc docdir/README.sms

%files snmpstats
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/snmpstats.so
%doc docdir/README.snmpstats
%{_datadir}/snmp/mibs/OPENSIPS-MIB
%{_datadir}/snmp/mibs/OPENSIPS-REG-MIB
%{_datadir}/snmp/mibs/OPENSIPS-SIP-COMMON-MIB
%{_datadir}/snmp/mibs/OPENSIPS-SIP-SERVER-MIB
%{_datadir}/snmp/mibs/OPENSIPS-TC

%files tlsops
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/tlsops.so
%doc docdir/README.tlsops

%files unixodbc
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/db_unixodbc.so
%doc docdir/README.unixodbc

%files xcap_client
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/xcap_client.so
%doc docdir/README.xcap_client

%files xmpp
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/xmpp.so
%doc docdir/README.xmpp

%changelog

* Mon Oct 12 2009 Bogdan-Andrei Iancu <bogdan@voice-system.ro> 1.6.0-1
- Final ver. 1.6.0
- fix module renaming
- added the new modules
- acc_radius removed as now it is part of acc

* Mon Mar 23 2009 Bogdan-Andrei Iancu <bogdan@voice-system.ro> 1.5.0-1
- Final ver. 1.5.0
- fix module renaming
- added the new modules

* Thu Dec 13 2007 Peter Lemenkov <lemenkov@gmail.com> 1.3.0-1
- Final ver. 1.3.0
- Removed some leftovers from spec-file

* Wed Dec 12 2007 Peter Lemenkov <lemenkov@gmail.com> 1.3.0-0.1.pre1
- Latest snapshot - 1.3.0pre1

* Mon Dec 10 2007 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk> 1.2.2-11
- added ETCDIR into opensipsctlrc (need opensips-1.3 to work)

* Mon Sep 24 2007 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk> 1.2.2-10
- perl scripts moved to perl_vendorlib directory
- added LDAPUtils and Utils subdirectories
- changed perl module BuildRequires

* Mon Sep 24 2007 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk> 1.2.2-9
- added reload section to init script
- init script specified with initrddir macro
- documentation converted to UTF-8
- added doc macro for documentation
- documentation moved do proper place (/usr/share/doc/NAME-VERSION/)
- which removed from BuildRequires, it's in guidelines exceptions
- unixodbc subpackage summary update

* Thu Sep  6 2007 Peter Lemenkov <lemenkov@gmail.com> 1.2.2-8
- Added another one missing BR - which (needs by snmpstats module)
- Cosmetic: dropped commented out 'Requires'
 
* Thu Sep 06 2007 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk> 1.2.2-7
- added attr macro for init script
- added -p to install arguments to preserve timestamp
- parallel make used

* Sun Aug 26 2007 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk> 1.2.2-6
- Fedora Core 6 build updates
- changed attributes for opensips.init to be rpmlint more silent

* Sun Aug 26 2007 Peter Lemenkov <lemenkov@gmail.com> 1.2.2-5
- fixed paths for openssl libs and includes

* Sun Aug 26 2007 Peter Lemenkov <lemenkov@gmail.com> 1.2.2-4
- Introduced acc and acc_radius modules (Jan Ondrej)
- Dropped radius_accounting condition

* Sat Aug 25 2007 Peter Lemenkov <lemenkov@gmail.com> 1.2.2-3
- Changed license according to Fedora's policy
- Make rpmlint more silent

* Fri Aug 24 2007 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk> 1.2.2-2
- added opensips.init script
- removed Patch0: opensips--Makefile.diff and updated build section
- spec file is 80 characters wide
- added radius_accounting condition

* Wed Aug 22 2007 Peter Lemenkov <lemenkov@gmail.com> 1.2.2-1
- Ver. 1.2.2

* Tue Jul 24 2007 Peter Lemenkov <lemenkov@gmail.com> 1.2.1-1
- Initial spec.
