---
title: "Modules"
description: ""
---

## SIP related modules

### SIP signaling modules

* [**DIALOG**](../../modules/dialog/README.md) - Dialog support module, 🟢 **stable**
* [**NAT_TRAVERSAL**](../../modules/nat_traversal/README.md) - NAT traversal module, 🔴 **alpha**
* [**NATHELPER**](../../modules/nathelper/README.md) - NAT traversal helper module, 🟢 **stable**
* [**OPTIONS**](../../modules/options/README.md) - OPTIONS server replier module, 🟢 **stable**
* [**REGISTRAR**](../../modules/registrar/README.md) - SIP Registrar implementation module, 🟢 **stable**
* [**SIGNALING**](../../modules/signaling/README.md) - SIP signaling module, 🔴 **alpha** / 🔵 **NEW**
* [**TM**](../../modules/tm/README.md) - Transaction (stateful) module, 🟢 **stable**
* [**SL**](../../modules/sl/README.md) - Stateless replier module, 🟢 **stable**
* [**SMS**](../../modules/sms/README.md) - SIP-to-SMS IM gateway module, 🟢 **stable**

### SIP Routing modules

* [**CARRIERROUTE**](../../modules/carrierroute/README.md) - routing extension suitable for carriers, 🔴 **alpha**
* [**DISPATCHER**](../../modules/dispatcher/README.md) - Dispatcher module, 🟢 **stable**
* [**DROUTING**](../../modules/drouting/README.md) - Dynamic Routing / LCR, 🟢 **stable** / 🔵 **NEW**
* [**ENUM**](../../modules/enum/README.md) - ENUM lookup module, 🟢 **stable**
* [**JABBER**](../../modules/jabber/README.md) - JABBER IM and PRESENCE interconnection module, 🟡 **beta**
* [**IMC**](../../modules/imc/README.md) - Instant Messaging Conferencing module, 🟡 **beta**
* [**LOAD_BALANCER**](../../modules/load_balancer/README.md) - Load Balancer (for calls) module, 🔴 **alpha** / 🔵 **NEW**
* [**MSILO**](../../modules/msilo/README.md) - SIP message silo module, 🟢 **stable**
* [**RR**](../../modules/rr/README.md) - Record-Route and Route module, 🟢 **stable**
* [**OSP**](../../modules/osp/README.md) - OSP peering module, 🟢 **stable**
* [**CPL-C**](../../modules/cpl-c/README.md) - CPL interpreter module, 🟢 **stable**
* [**LCR**](../../modules/lcr/README.md) - Least Cost Routing module, 🟢 **stable**
* [**PDT**](../../modules/pdt/README.md) - Prefix-to-Domain translator module, 🟢 **stable**

### SIP messaging operations

* [**DIVERSION**](../../modules/diversion/README.md) - Diversion header insertion module, 🟢 **stable**
* [**IDENTITY**](../../modules/identity/README.md) - SIP Identity implementation, 🔴 **alpha** / 🔵 **NEW**
* [**MAXFWD**](../../modules/maxfwd/README.md) - Max-Forward processor module, 🟢 **stable**
* [**MANGLER**](../../modules/mangler/README.md) - SIP mangler module, 🟢 **stable**
* [**PATH**](../../modules/path/README.md) - Path support for SIP frontending, 🟢 **stable**
* [**UAC**](../../modules/uac/README.md) - UAC functionalies (FROM mangling and UAC auth), 🟢 **stable**
* [**UAC_REDIRECT**](../../modules/uac_redirect/README.md) - UAC redirection functionality, 🟢 **stable**
* [**URI**](../../modules/uri/README.md) - Generic URI operation module, 🟢 **stable**
* [**SST**](../../modules/sst/README.md) - SIP Session Timer support, 🟢 **stable**

### SIP Presence Modules

* [**PRESENCE**](../../modules/presence/README.md) - Presence server module - common API, 🟢 **stable**
* [**PRESENCE_DIALOGINFO**](../../modules/presence_dialoginfo/README.md) - Extension to Presence server for Dialog Info, 🔴 **alpha** / 🔵 **NEW**
* [**PRESENCE_MWI**](../../modules/presence_mwi/README.md) - Extension to Presence server for Message Waiting Indication, 🟢 **stable**
* [**PRESENCE_XCAPDIFF**](../../modules/presence_xcapdiff/README.md) - Extension to Presence server for XCAP-DIFF event, 🔴 **alpha** / 🔵 **NEW**
* [**PRESENCE_XML**](../../modules/presence_xml/README.md) - Presence server module - presence & watcher info and XCAP, 🟢 **stable**
* [**PUA**](../../modules/pua/README.md) - Common API for presence user agent client, 🟢 **stable**
* [**PUA_BLA**](../../modules/pua_bla/README.md) - BLA extension for PUA, 🟢 **stable**
* [**PUA_DIALOGINFO**](../../modules/pua_dialoginfo/README.md) - Dialog-Info extension for PUA, 🔴 **alpha** / 🔵 **NEW**
* [**PUA_MI**](../../modules/pua_mi/README.md) - MI extension for PUA, 🟢 **stable**
* [**PUA_USRLOC**](../../modules/pua_usrloc/README.md) - USRLOC extension for PUA, 🟢 **stable**
* [**PUA_XMPP**](../../modules/pua_xmpp/README.md) - XMPP extension for PUA (SIMPLE-XMPP presence gateway), 🟢 **stable**
* [**RLS**](../../modules/rls/README.md) - Resource List Server implementation, 🟡 **beta**
* [**XCAP_CLIENT**](../../modules/xcap_client/README.md) - XCAP client implementation, 🟡 **beta**

---

## Scripting modules

### Script helper modules

* [**CFGUTILS**](../../modules/cfgutils/README.md) - Different config utilities, 🟢 **stable**
* [**EXEC**](../../modules/exec/README.md) - External exec module, 🟢 **stable**
* [**TEXTOPS**](../../modules/textops/README.md) - Text operations module, 🟢 **stable**
* [**AVPOPS**](../../modules/avpops/README.md) - AVP operation module, 🟢 **stable**
* [**REGEX**](../../modules/regex/README.md) - RegExp via PCRE library, 🔴 **alpha** / 🔵 **NEW**
* [**BENCHMARK**](../../modules/benchmark/README.md) - Config file benchmarking, 🟡 **beta**
* [**GFLAGS**](../../modules/gflags/README.md) - Global shared flags module, 🟢 **stable**
* [**PERL**](../../modules/perl/README.md) - embed execution of Perl function, 🟢 **stable**
* [**MMGEOIP**](../../modules/mmgeoip/README.md) - MaxMind GeoIP module, 🔴 **alpha** / 🔵 **NEW**
* [**AVP_RADIUS**](../../modules/avp_radius/README.md) - RADIUS-backend for AVP loading module, 🟢 **stable**
* [**XLOG**](../../modules/xlog/README.md) - Advanced logger module, 🟢 **stable**

### Auth modules

* [**AUTH**](../../modules/auth/README.md) - Authentication Framework module, 🟢 **stable**
* [**AUTH_DB**](../../modules/auth_db/README.md) - Database-backend authentication module, 🟢 **stable**
* [**PERMISSIONS**](../../modules/permissions/README.md) - Permissions control module, 🟢 **stable**
* [**AUTH_DIAMETER**](../../modules/auth_diameter/README.md) - DIAMETER-backend authentication module, ⚫ **unmaintained**
* [**AUTH_RADIUS**](../../modules/auth_radius/README.md) - RADIUS-backend authentication module, 🟢 **stable**
* [**GROUP_RADIUS**](../../modules/group_radius/README.md) - User-groups module with RADIUS-backend, 🟢 **stable**
* [**URI_DB**](../../modules/uri_db/README.md) - URI operation with database support module, 🟢 **stable**
* [**URI_RADIUS**](../../modules/uri_radius/README.md) - URI operation with RADIUS support module, 🟢 **stable**

### Accounting & Billing modules

* [**ACC**](../../modules/acc/README.md) - Accounting module, 🟢 **stable**
* [**CALL CONTROL**](../../modules/call_control/README.md) - Prepaid Application module, 🟢 **stable** / 🔵 **NEW**

### Dialplan Modules

* [**ALIAS_DB**](../../modules/alias_db/README.md) - Database SIP aliases module, 🟢 **stable**
* [**DIALPLAN**](../../modules/dialplan/README.md) - Dialplan management, 🟢 **stable**
* [**DOMAIN**](../../modules/domain/README.md) - Multi-domain support module, 🟢 **stable**
* [**DOMAINPOLICY**](../../modules/domainpolicy/README.md) - Policies to connect federations, 🟡 **beta**
* [**GROUP**](../../modules/group/README.md) - User-groups module with DB-backend, 🟢 **stable**
* [**USERBLACKLIST**](../../modules/userblacklist/README.md) - User black/white listing, 🔴 **alpha**
* [**SPEEDDIAL**](../../modules/speeddial/README.md) - Per-user speed-dial controller module, 🟢 **stable**
* [**PEERING**](../../modules/peering/README.md) - Radius peering module, 🔴 **alpha**
* [**CLOSEDDIAL**](../../modules/closeddial/README.md) - PBX-like dialling features, 🔴 **alpha** / 🔵 **NEW**

### Data caching

* [**USRLOC**](../../modules/usrloc/README.md) - User location implementation module, 🟢 **stable**

### Traffic shaping module

* [**PIKE**](../../modules/pike/README.md) - Flood detector module, 🟢 **stable**
* [**QOS**](../../modules/qos/README.md) - QOS (RTP) module, 🔴 **alpha** / 🔵 **NEW**
* [**RATELIMIT**](../../modules/ratelimit/README.md) - SIP traffic shaping module, 🔴 **alpha**

---

## Database modules

### SQL modules

* [**DB_BERKELEY**](../../modules/db_berkeley/README.md) - Berkeley DB driver for DB API, 🟡 **beta**
* [**DB_FLATSTORE**](../../modules/db_flatstore/README.md) - Fast writing-only text-backend for database module, 🟢 **stable**
* [**DB_MYSQL**](../../modules/db_mysql/README.md) - MYSQL-backend for database API module, 🟢 **stable**
* [**DB_ORACLE**](../../modules/db_oracle/README.md) - ORACLE-backend for database API module, 🔴 **alpha**
* [**DB_POSTGRES**](../../modules/db_postgres/README.md) - POSTGRES-backend for database API module, 🟢 **stable**
* [**DB_TEXT**](../../modules/db_text/README.md) - Text-backend for database API module, 🟢 **stable**
* [**DB_UNIXODBC**](../../modules/db_unixodbc/README.md) - unixODBC driver module, 🟢 **stable**
* [**PERLVDB**](../../modules/perlvdb/README.md) - Perl Virtual Database engine, 🟢 **stable**

### noSQL modules

* [**LOCALCACHE**](../../modules/localcache/README.md) - Local memory caching module, 🔴 **alpha** / 🔵 **NEW**

---

## External Integration modules

### OpenSIPS API modules

* [**MI_DATAGRAM**](../../modules/mi_datagram/README.md) - DATAGRAM (unix and network) support for Management Interface, 🟢 **stable**
* [**MI_FIFO**](../../modules/mi_fifo/README.md) - FIFO support for Management Interface, 🟢 **stable**
* [**STATISTICS**](../../modules/statistics/README.md) - Script statistics support, 🟢 **stable**
* [**MI_XMLRPC**](../../modules/mi_xmlrpc/README.md) - XMLRPC support for Management Interface, 🟢 **stable**

### Media Relays

* [**MEDIAPROXY**](../../modules/mediaproxy/README.md) - NAT traversal module, 🟢 **stable**

### External integration (non-SIP protocols)

* [**H350**](../../modules/h350/README.md) - H350 implementation, 🟢 **stable**
* [**LDAP**](../../modules/ldap/README.md) - LDAP connector, 🟢 **stable**
* [**SEAS**](../../modules/seas/README.md) - Sip Express Application Server (interface module), 🟢 **stable**
* [**SIPTRACE**](../../modules/siptrace/README.md) - SipTrace module, 🟢 **stable**
* [**SNMPStats**](../../modules/snmpstats/README.md) - SNMP interface for statistics module, 🟢 **stable**
* [**XMPP**](../../modules/xmpp/README.md) - SIP-to-XMPP Gateway (SIP to Jabber/Google Talk), 🟢 **stable**

---

## OpenSIPS protocols and infrastructure

* [**TLSOPS**](../../modules/tlsops/README.md) - TLS operations module, 🟢 **stable**
