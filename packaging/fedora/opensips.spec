%if 0%{?rhel}
# copied from lm_sensors exclusive arch
%ifnarch alpha i386 i486 i586 i686 pentium3 pentium4 athlon x86_64
%define disable_snmpstats snmpstats
%endif
%endif

%define	EXCLUDE_MODULES	mi_xmlrpc osp json %{?disable_snmpstats} %{!?_with_oracle:db_oracle}

Summary:  Open Source SIP Server
Name:     opensips
Version:  1.8.0
Release:  4%{?dist}
License:  GPLv2+
Group:    System Environment/Daemons
Source0:  http://opensips.org/pub/%{name}/%{version}/src/%{name}-%{version}-tls_src.tar.gz
Source1:  %{name}.sysconfig
Patch1:   opensips--init.patch
Patch2:   opensips--openssl10.patch
URL:      http://opensips.org

BuildRequires:  expat-devel
BuildRequires:  libxml2-devel
BuildRequires:  bison
BuildRequires:  flex
#BuildRequires:  subversion
# needed by snmpstats
BuildRequires:  radiusclient-ng-devel
BuildRequires:  mysql-devel
BuildRequires:  postgresql-devel

# required by snmpstats module
%if %{undefined disable_snmpstats}
BuildRequires:  lm_sensors-devel
%endif
BuildRequires:  net-snmp-devel
BuildRequires:  unixODBC-devel
BuildRequires:  openssl-devel
BuildRequires:  expat-devel
#BuildRequires: xmlrpc-c-devel
BuildRequires:  libconfuse-devel
BuildRequires:  db4-devel
BuildRequires:  openldap-devel
BuildRequires:  curl-devel
BuildRequires:  libmemcached-devel
BuildRequires:  GeoIP-devel
BuildRequires:  pcre-devel


Requires(post): chkconfig
Requires(preun):chkconfig
# for /sbin/service
Requires(preun):initscripts
BuildRoot:  %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
OpenSIPS or Open SIP Server is a very fast and flexible SIP (RFC3261)
proxy server. Written entirely in C, opensips can handle thousands calls
per second even on low-budget hardware. A C Shell like scripting language
provides full control over the server's behaviour. It's modular
architecture allows only required functionality to be loaded.
Currently the following modules are available: digest authentication,
CPL scripts, instant messaging, MySQL and UNIXODBC support, a presence agent,
radius authentication, record routing, an SMS gateway, a jabber gateway, a
transaction and dialog module, OSP module, statistics support,
registrar and user location.

%package  aaa_radius
Summary:  RADIUS backend for AAA api
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  aaa_radius
This module provides the RADIUS backend for the AAA API - group, auth, uri
module use the AAA API for performing RADIUS ops.

%package  acc
Summary:  Accounts transactions information to different backends
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  acc
ACC module is used to account transactions information to different backends
like syslog, SQL, AAA.

%package  auth_aaa
Summary:  Performs authentication using an AAA server
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  auth_aaa
This module contains functions that are used to perform authentication using
an AAA server.  Basically the proxy will pass along the credentials to the
AAA server which will in turn send a reply containing result of the
authentication. So basically the whole authentication is done in the AAA
server.

%package  auth_diameter
Summary:  Performs authentication using a Diameter server
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  auth_diameter
This module implements SIP authentication and authorization with DIAMETER
server, namely DIameter Server Client (DISC).

%package  b2bua
Summary:  Back-2-Back User Agent
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  b2bua
B2BUA is an implementation of the behavior of a B2BUA as defined in RFC 3261
that offers the possibility to build certain services on top of it.

%package  carrierroute
Summary:  Routing extension suitable for carriers
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description	carrierroute
A module which provides routing, balancing and blacklisting capabilities.

%package  cpl-c
Summary:  Call Processing Language interpreter
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description	cpl-c
This module implements a CPL (Call Processing Language) interpreter.
Support for uploading/downloading/removing scripts via SIP REGISTER method
is present.

%package  db_berkeley
Summary:  Berkley DB backend support
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  db_berkeley
This is a module which integrates the Berkeley DB into OpenSIPS. It implements
the DB API defined in OpenSIPS.

%package  db_http
Summary:  HTTP DB backend support
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  db_http
This module provides access to a database that is implemented as a
HTTP server.

%package  h350
Summary:  H350 implementation
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  h350
The OpenSIPS H350 module enables an OpenSIPS SIP proxy server to access SIP
account data stored in an LDAP [RFC4510] directory  containing H.350 [H.350]
commObjects.

%package  jabber
Summary:  Gateway between OpenSIPS and a jabber server
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  jabber
Jabber module that integrates XODE XML parser for parsing Jabber messages.

%package  ldap
Summary:  LDAP connector
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  ldap
The LDAP module implements an LDAP search interface for OpenSIPS.

%package  memcached
Summary:  Memcached connector
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  memcached
Memcached module is an implementation of a cache system designed to
work with a memcached server.

%package  mmgeoip
Summary:  Wrapper for the MaxMind GeoIP API
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  mmgeoip
Mmgeoip is a lightweight wrapper for the MaxMind GeoIP API. It adds
IP address-to-location lookup capability to OpenSIPS scripts.

%if %{defined db_oracle}
%package  oracle
Summary:  Oracle Storage Support for the OpenSIPS
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  oracle
The %{name}-oracle package contains the Oracle plugin for %{name}, which allows
a Oracle-Database to be used for persistent storage.
%endif

%package  mysql
Summary:  MySQL Storage Support for the OpenSIPS
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}


%description  mysql
The %{name}-mysql package contains the MySQL plugin for %{name}, which allows
a MySQL-Database to be used for persistent storage.

%package  perl
Summary:  Helps implement your own OpenSIPS extensions in Perl
Group:    System Environment/Daemons
# require perl-devel for >F7 and perl for <=F6
BuildRequires:  perl(ExtUtils::MakeMaker)
%if 0%{?rhel}
BuildRequires:  perl(ExtUtils::Embed)
%else
BuildRequires:  perl(ExtUtils::Embed), perl-devel
%endif
Requires: %{name} = %{version}-%{release}
Requires: perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))

%description  perl
The time needed when writing a new OpenSIPS module unfortunately is quite
high, while the options provided by the configuration file are limited to
the features implemented in the modules. With this Perl module, you can
easily implement your own OpenSIPS extensions in Perl.  This allows for
simple access to the full world of CPAN modules. SIP URI rewriting could be
implemented based on regular expressions; accessing arbitrary data backends,
e.g. LDAP or Berkeley DB files, is now extremely simple.

%package  perlvdb
Summary:  Perl virtual database engine
Group:    System Environment/Daemons
# require perl-devel for >F7 and perl for <=F6
BuildRequires:  perl(ExtUtils::MakeMaker)
Requires: %{name} = %{version}-%{release}
Requires: %{name}-perl
Requires: perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))

%description  perlvdb
The Perl Virtual Database (VDB) provides a virtualization framework for
OpenSIPS's database access. It does not handle a particular database engine
itself but lets the user relay database requests to arbitrary Perl functions.

%package  peering
Summary:  Radius peering
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  peering
Peering module allows SIP providers (operators or organizations)
to verify from a broker if source or destination  of a SIP request
is a trusted peer.

%package  postgresql
Summary:  PostgreSQL Storage Support for the OpenSIPS
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  postgresql
The %{name}-postgresql package contains the PostgreSQL plugin for %{name},
which allows a PostgreSQL-Database to be used for persistent storage.

%package  presence
Summary:  Presence server
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  presence
This module implements a presence server. It handles PUBLISH and SUBSCRIBE
messages and generates NOTIFY messages. It offers support for aggregation
of published presence information for the same presentity using more devices.
It can also filter the information provided to watchers according to privacy
rules.

%package  presence_dialoginfo
Summary:  Extension to Presence server for Dialog-Info
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: %{name}-presence

%description  presence_dialoginfo
The module enables the handling of "Event: dialog" (as defined
in RFC 4235) inside of the presence module. This can be used
distribute the dialog-info status to the subscribed watchers.

%package  presence_mwi
Summary:  Extension to Presence server for Message Waiting Indication
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: %{name}-presence

%description  presence_mwi
The module does specific handling for notify-subscribe message-summary
(message waiting indication) events as specified in RFC 3842. It is used
with the general event handling module, presence. It constructs and adds
message-summary event to it.

%package  presence_xcapdiff
Summary:  Extension to Presence server for XCAP-DIFF event
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: %{name}-presence
Requires: %{name}-pua_mi

%description  presence_xcapdiff
The presence_xcapdiff is an OpenSIPS module that adds support
for the "xcap-diff" event to presence and pua.

%package  presence_xml
Summary:  SIMPLE Presence extension
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: %{name}-presence
Requires: %{name}-xcap_client

%description  presence_xml
The module does specific handling for notify-subscribe events using xml bodies.
It is used with the general event handling module, presence.

%package  pua
Summary:  Offer the functionality of a presence user agent client
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  pua
This module offer the functionality of a presence user agent client, sending
Subscribe and Publish messages.

%package  pua_dialoginfo
Summary:  Dialog-Info extension for PUA
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: %{name}-pua

%description  pua_dialoginfo
The pua_dialoginfo retrieves dialog state information from the
dialog module and PUBLISHes the dialog-information using the
pua module. Thus, in combination with the presence_xml module
this can be used to derive dialog-info from the dialog module
and NOTIFY the subscribed watchers about dialog-info changes.

%package  pua_bla
Summary:  BLA extension for PUA
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: %{name}-pua
Requires: %{name}-presence

%description  pua_bla
The pua_bla module enables Bridged Line Appearances support according to the
specifications in draft-anil-sipping-bla-03.txt.

%package  pua_mi
Summary:  Connector between usrloc and MI interface
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: %{name}-pua

%description  pua_mi
The pua_mi sends offer the possibility to publish presence information
via MI transports.  Using this module you can create independent
applications/scripts to publish not sip-related information (e.g., system
resources like CPU-usage, memory, number of active subscribers ...)

%package  pua_usrloc
Summary:  Connector between usrloc and pua modules
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: %{name}-pua

%description  pua_usrloc
This module is the connector between usrloc and pua modules. It creates the
environment to send PUBLISH requests for user location records, on specific
events (e.g., when new record is added in usrloc, a PUBLISH with status open
(online) is issued; when expires, it sends closed (offline)). Using this
module, phones which have no support for presence can be seen as
online/offline.

%package  pua_xmpp
Summary:  SIMPLE-XMPP Presence gateway
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: %{name}-pua
Requires: %{name}-presence
Requires: %{name}-xmpp

%description  pua_xmpp
This module is a gateway for presence between SIP and XMPP. It translates one
format into another and uses xmpp, pua and presence modules to manage the
transmition of presence state information.

%package  regex
Summary:  RegExp via PCRE library
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  regex
This module offers matching operations against regular
expressions using the powerful PCRE library.

%package  rls
Summary:  Resource List Server
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires:	%{name}-pua
Requires:	%{name}-presence

%description  rls
The modules is a Resource List Server implementation following the
specification in RFC 4662 and RFC 4826.

%package  seas
Summary:  Transfers the execution logic control to a given external entity
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  seas
SEAS module enables OpenSIPS to transfer the execution logic control of a sip
message to a given external entity, called the Application Server. When the
OpenSIPS script is being executed on an incoming SIP message, invocation of
the as_relay_t() function makes this module send the message along with some
transaction information to the specified Application Server. The Application
Server then executes some call-control logic code, and tells OpenSIPS to take
some actions, ie. forward the message downstream, or respond to the message
with a SIP repy, etc

%package  sms
Summary:  Gateway between SIP and GSM networks via sms
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  sms
This module provides a way of communication between SIP network (via SIP
MESSAGE) and GSM networks (via ShortMessageService). Communication is
possible from SIP to SMS and vice versa.  The module provides facilities
like SMS confirmation--the gateway can confirm to the SIP user if his
message really reached its destination as a SMS--or multi-part messages--if
a SIP messages is too long it will be split and sent as multiple SMS.

%if %{undefined disable_snmpstats}
%package  snmpstats
Summary:  SNMP management interface for the OpenSIPS
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))

%description  snmpstats
The %{name}-snmpstats package provides an SNMP management interface to
OpenSIPS.  Specifically, it provides general SNMP queryable scalar statistics,
table representations of more complicated data such as user and contact
information, and alarm monitoring capabilities.
%endif

%package  tlsops
Summary:  TLS-relating functions for the OpenSIPS
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  tlsops
The %{name}-tlsops package implements TLS related functions to use in the
routing script, and exports pseudo variables with certificate and TLS
parameters.

%package  unixodbc
Summary:  OpenSIPS unixODBC Storage support
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  unixodbc
The %{name}-unixodbc package contains the unixODBC plugin for %{name}, which
allows a unixODBC to be used for persistent storage

%package  xcap_client
Summary:  XCAP client
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  xcap_client
The modules is an XCAP client for OpenSIPS that can be used by other modules.
It fetches XCAP elements, either documents or part of them, by sending HTTP
GET requests. It also offers support for conditional queries. It uses libcurl
library as a client-side HTTP transfer library.

%package  xmpp
Summary:  Gateway between OpenSIPS and a jabber server
Group:    System Environment/Daemons
Requires: %{name} = %{version}-%{release}

%description  xmpp
This modules is a gateway between Openser and a jabber server. It enables
the exchange of instant messages between SIP clients and XMPP(jabber)
clients.

%prep
%setup -q -n %{name}-%{version}-tls
%patch1 -p1
%patch2 -p1

%build
LOCALBASE=/usr CFLAGS="%{optflags}" %{__make} all %{?_smp_mflags} TLS=1 \
  exclude_modules="%EXCLUDE_MODULES" \
  cfg-target=%{_sysconfdir}/opensips/ \
  modules-prefix=%{buildroot}/%{_prefix} \
  modules-dir=%{_lib}/%{name}/modules

%install
rm -rf $RPM_BUILD_ROOT
%{__make} install TLS=1 LIBDIR=%{_lib} \
  exclude_modules="%EXCLUDE_MODULES" \
  basedir=%{buildroot} prefix=%{_prefix} \
  cfg-prefix=%{buildroot} \
  modules-prefix=%{buildroot}/%{_prefix} \
  modules-dir=%{_lib}/%{name}/modules \
  DBTEXTON=yes # fixed dbtext documentation installation

# clean some things
mkdir -p $RPM_BUILD_ROOT/%{perl_vendorlib}
if [ -d "$RPM_BUILD_ROOT/%{_prefix}/perl" ]; then
  # for fedora>=11
  mv $RPM_BUILD_ROOT/%{_prefix}/perl/* \
    $RPM_BUILD_ROOT/%{perl_vendorlib}/
else
  # for fedora<=10
  mv $RPM_BUILD_ROOT/%{_libdir}/opensips/perl/* \
    $RPM_BUILD_ROOT/%{perl_vendorlib}/
fi
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
%{__install} -p -D -m 755 packaging/fedora/opensips.init \
  $RPM_BUILD_ROOT%{_initrddir}/opensips
echo -e "\nETCDIR=\"%{_sysconfdir}/opensips\"\n" \
  >> $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/opensipsctlrc

#install sysconfig file
install -D -p -m 644 %{SOURCE1} $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/%{name}

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
%{_sbindir}/osipsconsole

%attr(750,root,root) %dir %{_sysconfdir}/opensips
%attr(750,root,root) %dir %{_sysconfdir}/opensips/tls
%attr(750,root,root) %dir %{_sysconfdir}/opensips/tls/rootCA
%attr(750,root,root) %dir %{_sysconfdir}/opensips/tls/rootCA/certs
%attr(750,root,root) %dir %{_sysconfdir}/opensips/tls/rootCA/private
%attr(750,root,root) %dir %{_sysconfdir}/opensips/tls/user
%dir %{_libdir}/opensips/
%dir %{_libdir}/opensips/modules/
%dir %{_libdir}/opensips/opensipsctl/
%dir %{_libdir}/opensips/opensipsctl/dbtextdb

%attr(755,root,root) %{_initrddir}/opensips

%config(noreplace) %{_sysconfdir}/opensips/dictionary.opensips
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}
%attr(640,root,root) %config(noreplace) %{_sysconfdir}/opensips/opensips.cfg
%attr(640,root,root) %config(noreplace) %{_sysconfdir}/opensips/opensipsctlrc
%attr(640,root,root) %config(noreplace) %{_sysconfdir}/opensips/osipsconsolerc
# these files are just an example so no need to restrict access to them
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
%{_libdir}/opensips/opensipsctl/dbtextdb/dbtextdb.py*

%dir %{_datadir}/opensips
%dir %{_datadir}/opensips/dbtext
%dir %{_datadir}/opensips/dbtext/opensips
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
%doc COPYING

%{_libdir}/opensips/modules/acc.so
%{_libdir}/opensips/modules/alias_db.so
%{_libdir}/opensips/modules/auth.so
%{_libdir}/opensips/modules/auth_db.so
%{_libdir}/opensips/modules/avpops.so
%{_libdir}/opensips/modules/benchmark.so
%{_libdir}/opensips/modules/call_control.so
%{_libdir}/opensips/modules/closeddial.so
%{_libdir}/opensips/modules/cfgutils.so
%{_libdir}/opensips/modules/db_flatstore.so
%{_libdir}/opensips/modules/db_virtual.so
%{_libdir}/opensips/modules/db_text.so
%{_libdir}/opensips/modules/dialog.so
%{_libdir}/opensips/modules/dialplan.so
%{_libdir}/opensips/modules/dispatcher.so
%{_libdir}/opensips/modules/diversion.so
%{_libdir}/opensips/modules/domain.so
%{_libdir}/opensips/modules/domainpolicy.so
%{_libdir}/opensips/modules/drouting.so
%{_libdir}/opensips/modules/enum.so
%{_libdir}/opensips/modules/exec.so
%{_libdir}/opensips/modules/gflags.so
%{_libdir}/opensips/modules/group.so
%{_libdir}/opensips/modules/identity.so
%{_libdir}/opensips/modules/imc.so
%{_libdir}/opensips/modules/load_balancer.so
%{_libdir}/opensips/modules/localcache.so
%{_libdir}/opensips/modules/mangler.so
%{_libdir}/opensips/modules/maxfwd.so
%{_libdir}/opensips/modules/mediaproxy.so
%{_libdir}/opensips/modules/mi_fifo.so
%{_libdir}/opensips/modules/mi_datagram.so
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
%{_libdir}/opensips/modules/stun.so
%{_libdir}/opensips/modules/textops.so
%{_libdir}/opensips/modules/tm.so
%{_libdir}/opensips/modules/uac.so
%{_libdir}/opensips/modules/uac_redirect.so
%{_libdir}/opensips/modules/userblacklist.so
%{_libdir}/opensips/modules/uri.so
%{_libdir}/opensips/modules/usrloc.so
%{_libdir}/opensips/modules/xlog.so

%doc docdir/README.acc
%doc docdir/README.alias_db
%doc docdir/README.auth
%doc docdir/README.auth_db
%doc docdir/README.avpops
%doc docdir/README.benchmark
%doc docdir/README.cfgutils
%doc docdir/README.db_text
%doc docdir/README.dialog
%doc docdir/README.dialplan
%doc docdir/README.dispatcher
%doc docdir/README.diversion
%doc docdir/README.domain
%doc docdir/README.domainpolicy
%doc docdir/README.drouting
%doc docdir/README.enum
%doc docdir/README.exec
#%doc docdir/README.flatstore
%doc docdir/README.gflags
%doc docdir/README.group
%doc docdir/README.imc
%doc docdir/README.mangler
%doc docdir/README.maxfwd
%doc docdir/README.mediaproxy
%doc docdir/README.mi_fifo
%doc docdir/README.mi_datagram
%doc docdir/README.msilo
%doc docdir/README.nathelper
%doc docdir/README.options
%doc docdir/README.path
%doc docdir/README.pdt
%doc docdir/README.permissions
%doc docdir/README.pike
%doc docdir/README.registrar
%doc docdir/README.rr
%doc docdir/README.siptrace
%doc docdir/README.sl
%doc docdir/README.speeddial
%doc docdir/README.sst
%doc docdir/README.statistics
#%doc docdir/README.textops
%doc docdir/README.tm
%doc docdir/README.uac
%doc docdir/README.uac_redirect
%doc docdir/README.uri
%doc docdir/README.usrloc
%doc docdir/README.xlog

%files aaa_radius
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/aaa_radius.so
%doc docdir/README.aaa_radius

%files acc
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/acc.so
%doc docdir/README.acc

%files auth_aaa
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/auth_aaa.so
%doc docdir/README.auth_aaa

%files auth_diameter
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/auth_diameter.so
%doc docdir/README.auth_diameter

%files b2bua
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/b2b_entities.so
%{_libdir}/opensips/modules/b2b_logic.so
%doc docdir/README.b2b_entities
%doc docdir/README.b2b_logic

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
%dir %{_datadir}/opensips/db_berkeley
%dir %{_datadir}/opensips/db_berkeley/opensips
%{_datadir}/opensips/db_berkeley/opensips/*
%doc docdir/README.db_berkeley

%files db_http
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/db_http.so
%doc docdir/README.db_http

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

%files memcached
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/memcached.so
%doc docdir/README.memcached

%files mmgeoip
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/mmgeoip.so
%doc docdir/README.mmgeoip

%files mysql
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/db_mysql.so
%{_libdir}/opensips/opensipsctl/opensipsdbctl.mysql
%dir %{_datadir}/opensips/mysql
%{_datadir}/opensips/mysql/*.sql
%doc docdir/README.db_mysql

%if %{defined db_oracle}
%files oracle
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/db_oracle.db
%{_libdir}/opensips/opensipsctl/opensipsdbctl.oracle
%dir %{_datadir}/opensips/oracle
%{_datadir}/opensips/oracle/*
%doc docdir/README.db_oracle
%endif

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

%files peering
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/peering.so
%doc docdir/README.peering

%files postgresql
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/db_postgres.so
%{_libdir}/opensips/opensipsctl/opensipsdbctl.pgsql
%dir %{_datadir}/opensips/postgres
%{_datadir}/opensips/postgres/*.sql
%doc docdir/README.db_postgres

%files presence
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/presence.so
%doc docdir/README.presence

%files presence_dialoginfo
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/presence_dialoginfo.so
%doc docdir/README.presence_dialoginfo

%files presence_mwi
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/presence_mwi.so
%doc docdir/README.presence_mwi

%files presence_xcapdiff
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/presence_xcapdiff.so

%files presence_xml
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/presence_xml.so
%doc docdir/README.presence_xml

%files pua
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/pua.so
%doc docdir/README.pua

%files pua_dialoginfo
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/pua_dialoginfo.so
%doc docdir/README.pua_dialoginfo

%files pua_bla
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/pua_bla.so
%doc docdir/README.pua_bla

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

%files regex
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/regex.so
%doc docdir/README.regex

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

%if %{undefined disable_snmpstats}
%files snmpstats
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/snmpstats.so
%doc docdir/README.snmpstats
%dir %{_datadir}/snmp
%dir %{_datadir}/snmp/mibs
%{_datadir}/snmp/mibs/OPENSER-MIB
%{_datadir}/snmp/mibs/OPENSER-REG-MIB
%{_datadir}/snmp/mibs/OPENSER-SIP-COMMON-MIB
%{_datadir}/snmp/mibs/OPENSER-SIP-SERVER-MIB
%{_datadir}/snmp/mibs/OPENSER-TC
%endif

%files tlsops
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/tlsops.so
%doc docdir/README.tlsops

%files unixodbc
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/db_unixodbc.so
%doc docdir/README.db_unixodbc

%files xcap_client
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/xcap_client.so
%doc docdir/README.xcap_client

%files xmpp
%defattr(-,root,root,-)
%{_libdir}/opensips/modules/xmpp.so
%doc docdir/README.xmpp

%changelog
* Wed Nov 04 2009 John Khvatov <ivaxer@fedoraproject.org> - 1.6.0-4:
- Fixed typo: pia_mi to pua_mi in presence_xcapdiff dependencies

* Thu Nov 03 2009 John Khvatov <ivaxer@fedoraproject.org> - 1.6.0-3
- Added patch for compatibility with new openssl

* Thu Oct 29 2009 John Khvatov <ivaxer@fedoraproject.org> - 1.6.0-2
- Added patch for init script to fix malformed comment block
- Added COPYING file
- Fixed not-capitalized summory of memcached subpackage

* Mon Oct 19 2009 John Khvatov <ivaxer@fedoraproject.org> - 1.6.0-1
- Created new package from openser package
- Upgrade to OpenSIPS 1.6
- New modules
- Added osipconsole tool

* Tue Aug 25 2009 Tomas Mraz <tmraz@redhat.com> - 1.3.4-8
- rebuilt with new openssl

* Sat Jul 25 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.3.4-7
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Mon Mar 02 2009 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk> - 1.3.4-6
- allow build of this package on fedora<=10

* Sat Feb 28 2009 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk> - 1.3.4-5
- fix module path

* Sat Feb 28 2009 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk> - 1.3.4-3
- addedd subversion build dependency to avoid svnversion error messages
- fixed installation of perl modules in rawhide

* Fri Jan 23 2009 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk> 1.3.4-2
- Rebuild for new mysql.

* Mon Dec  8 2008 Peter Lemenkov <lemenkov@gmail.com> 1.3.4-1
- Ver. 1.3.4
- Added sysconfig-file

* Thu Aug 28 2008 Michael Schwendt <mschwendt@fedoraproject.org> - 1.3.3-3
- Include lots of unowned directories.

* Thu Aug 28 2008 Peter Lemenkov <lemenkov@gmail.com> 1.3.3-2
- Removed dialplan and drouting modules from upstream

* Thu Aug 28 2008 Peter Lemenkov <lemenkov@gmail.com> 1.3.3-1
- Ver. 1.3.3
- Dropped upstreamed patch

* Mon Aug 11 2008 Peter Lemenkov <lemenkov@gmail.com> 1.3.2-5
- Typo fix

* Mon Aug 11 2008 Peter Lemenkov <lemenkov@gmail.com> 1.3.2-4
- Fix build with --fuzz=0

* Mon Aug 11 2008 Peter Lemenkov <lemenkov@gmail.com> 1.3.2-3
- Fixed urls
- Restricted access to openser.cfg and openserctl.cfg
- Service won't start by default (BZ# 441297)

* Fri May 16 2008 Peter Lemenkov <lemenkov@gmail.com> 1.3.2-2
- New modules - dialplan and drouting (this one still has no README)

* Thu May 15 2008 Peter Lemenkov <lemenkov@gmail.com> 1.3.2-1
- Ver. 1.3.2

* Tue Mar 18 2008 Tom "spot" Callaway <tcallawa@redhat.com> - 1.3.1-3
- add Requires for versioned perl (libperl.so)
- drop silly file Requires

* Fri Mar 14 2008 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk> - 1.3.1-2
- removed perl patch, which is not necessary

* Thu Mar 13 2008 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk> - 1.3.1-1
- update to upstream
- removed obsolete patches

* Fri Mar  7 2008 Tom "spot" Callaway <tcallawa@redhat.com> - 1.3.0-12
- patch perl code to use PERL_SYS_INIT3_BODY

* Fri Mar  7 2008 Tom "spot" Callaway <tcallawa@redhat.com> - 1.3.0-11
- fix perl build requires

* Thu Mar 06 2008 Tom "spot" Callaway <tcallawa@redhat.com> - 1.3.0-10
- Rebuild for new perl

* Sat Feb 23 2008 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk> 1.3.0-9
- ia64 build fix

* Sat Feb  9 2008 Peter Lemenkov <lemenkov@gmail.com> 1.3.0-8.1
- typo fix

* Sat Feb  9 2008 Peter Lemenkov <lemenkov@gmail.com> 1.3.0-8
- Rebuild for GCC 4.3

* Sat Jan 26 2008 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk> 1.3.0-7
- Updated syntax error in default config

* Sat Jan 26 2008 Peter Lemenkov <lemenkov@gmail.com> 1.3.0-5
- Merge of acc module into main package

* Fri Jan 25 2008 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk> 1.3.0-4
- modify and apply forgotten patch4

* Thu Jan 17 2008 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk> 1.3.0-2
- removed openser.init and replaced by upstream version
- fixed configuration path for openserdbctl (#428799)

* Sun Jan 13 2008 Peter Lemenkov <lemenkov@gmail.com> 1.3.0-1.4
- 4th try to remove lm_sensors-devel from EL-[45] at ppc{64}

* Thu Dec 13 2007 Peter Lemenkov <lemenkov@gmail.com> 1.3.0-1
- Final ver. 1.3.0
- Removed some leftovers from spec-file

* Wed Dec 12 2007 Peter Lemenkov <lemenkov@gmail.com> 1.3.0-0.1.pre1
- Latest snapshot - 1.3.0pre1

* Mon Dec 10 2007 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk> 1.2.2-11
- added ETCDIR into openserctlrc (need openser-1.3 to work)

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
- changed attributes for openser.init to be rpmlint more silent

* Sun Aug 26 2007 Peter Lemenkov <lemenkov@gmail.com> 1.2.2-5
- fixed paths for openssl libs and includes

* Sun Aug 26 2007 Peter Lemenkov <lemenkov@gmail.com> 1.2.2-4
- Introduced acc and acc_radius modules (Jan Ondrej)
- Dropped radius_accounting condition

* Sat Aug 25 2007 Peter Lemenkov <lemenkov@gmail.com> 1.2.2-3
- Changed license according to Fedora's policy
- Make rpmlint more silent

* Fri Aug 24 2007 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk> 1.2.2-2
- added openser.init script
- removed Patch0: openser--Makefile.diff and updated build section
- spec file is 80 characters wide
- added radius_accounting condition

* Wed Aug 22 2007 Peter Lemenkov <lemenkov@gmail.com> 1.2.2-1
- Ver. 1.2.2

* Tue Jul 24 2007 Peter Lemenkov <lemenkov@gmail.com> 1.2.1-1
- Initial spec.
