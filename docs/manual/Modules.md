---
title: "Modules"
description: ""
---

## SIP related modules

### SIP signaling modules

* [**B2B_ENTITIES**](../../modules/b2b_entities/README.md) - Back-to-Back User Agent Entities, 🟢 **stable**
* [**B2B_LOGIC**](../../modules/b2b_logic/README.md) - Back-to-Back User Agent Logic, 🟢 **stable**
* [**DIALOG**](../../modules/dialog/README.md) - Dialog support module, 🟢 **stable**
* [**NAT_TRAVERSAL**](../../modules/nat_traversal/README.md) - NAT traversal module, 🟢 **stable**
* [**NATHELPER**](../../modules/nathelper/README.md) - NAT traversal helper module, 🟢 **stable**
* [**OPTIONS**](../../modules/options/README.md) - OPTIONS server replier module, 🟢 **stable**
* [**REGISTRAR**](../../modules/registrar/README.md) - SIP Registrar implementation module, 🟢 **stable**
* [**SIGNALING**](../../modules/signaling/README.md) - SIP signaling module, 🟢 **stable**
* [**UAC_REGISTRANT**](../../modules/uac_registrant/README.md) - SIP Registrant implementation module, 🟢 **stable**
* [**TM**](../../modules/tm/README.md) - Transaction (stateful) module, 🟢 **stable**
* [**SL**](../../modules/sl/README.md) - Stateless replier module, 🟢 **stable**
* [**SMS**](../../modules/sms/README.md) - SIP-to-SMS IM gateway module, 🟢 **stable**

### SIP Routing modules

* [**CARRIERROUTE**](../../modules/carrierroute/README.md) - routing extension suitable for carriers, 🔴 **alpha**
* [**DISPATCHER**](../../modules/dispatcher/README.md) - Dispatcher module, 🟢 **stable**
* [**DROUTING**](../../modules/drouting/README.md) - Dynamic Routing / LCR, 🟢 **stable**
* [**ENUM**](../../modules/enum/README.md) - ENUM lookup module, 🟢 **stable**
* [**JABBER**](../../modules/jabber/README.md) - JABBER IM and PRESENCE interconnection module, 🟡 **beta**
* [**IMC**](../../modules/imc/README.md) - Instant Messaging Conferencing module, 🟢 **stable**
* [**LOAD_BALANCER**](../../modules/load_balancer/README.md) - Load Balancer (for calls) module, 🟢 **stable**
* [**MSILO**](../../modules/msilo/README.md) - SIP message silo module, 🟢 **stable**
* [**RR**](../../modules/rr/README.md) - Record-Route and Route module, 🟢 **stable**
* [**OSP**](../../modules/osp/README.md) - OSP peering module, 🟢 **stable**
* [**CPL-C**](../../modules/cpl-c/README.md) - CPL interpreter module, 🟢 **stable**
* [**PDT**](../../modules/pdt/README.md) - Prefix-to-Domain translator module, 🟢 **stable**

### SIP messaging operations

* [**DIVERSION**](../../modules/diversion/README.md) - Diversion header insertion module, 🟢 **stable**
* [**IDENTITY**](../../modules/identity/README.md) - SIP Identity implementation, 🟢 **stable**
* [**MAXFWD**](../../modules/maxfwd/README.md) - Max-Forward processor module, 🟢 **stable**
* [**MANGLER**](../../modules/mangler/README.md) - SIP mangler module, 🟢 **stable**
* [**PATH**](../../modules/path/README.md) - Path support for SIP frontending, 🟢 **stable**
* [**SIPMSGOPS**](../../modules/sipmsgops/README.md) - SIP operations module, 🟢 **stable**
* [**UAC**](../../modules/uac/README.md) - UAC functionalies (FROM mangling and UAC auth), 🟢 **stable**
* [**UAC_AUTH**](../../modules/uac_auth/README.md) - UAC Authentication functionality, 🟢 **stable**
* [**UAC_REDIRECT**](../../modules/uac_redirect/README.md) - UAC redirection functionality, 🟢 **stable**
* [**URI**](../../modules/uri/README.md) - Generic URI operation module, 🟢 **stable**
* [**SST**](../../modules/sst/README.md) - SIP Session Timer support, 🟢 **stable**

### SIP Presence Modules

* [**PRESENCE**](../../modules/presence/README.md) - Presence server module - common API, 🟢 **stable**
* [**PRESENCE_CALLINFO**](../../modules/presence_callinfo/README.md) - Extension to Presence server for Call-Info, 🟢 **stable**
* [**PRESENCE_DIALOGINFO**](../../modules/presence_dialoginfo/README.md) - Extension to Presence server for Dialog Info, 🟢 **stable**
* [**PRESENCE_MWI**](../../modules/presence_mwi/README.md) - Extension to Presence server for Message Waiting Indication, 🟢 **stable**
* [**PRESENCE_XCAPDIFF**](../../modules/presence_xcapdiff/README.md) - Extension to Presence server for XCAP-DIFF event, 🟢 **stable**
* [**PRESENCE_XML**](../../modules/presence_xml/README.md) - Presence server module - presence & watcher info and XCAP, 🟢 **stable**
* [**PUA**](../../modules/pua/README.md) - Common API for presence user agent client, 🟢 **stable**
* [**PUA_BLA**](../../modules/pua_bla/README.md) - BLA extension for PUA, 🟢 **stable**
* [**PUA_DIALOGINFO**](../../modules/pua_dialoginfo/README.md) - Dialog-Info extension for PUA, 🟢 **stable**
* [**PUA_MI**](../../modules/pua_mi/README.md) - MI extension for PUA, 🟢 **stable**
* [**PUA_USRLOC**](../../modules/pua_usrloc/README.md) - USRLOC extension for PUA, 🟢 **stable**
* [**PUA_XMPP**](../../modules/pua_xmpp/README.md) - XMPP extension for PUA (SIMPLE-XMPP presence gateway), 🟢 **stable**
* [**RLS**](../../modules/rls/README.md) - Resource List Server implementation, 🟢 **stable**
* [**XCAP**](../../modules/xcap/README.md) - XCAP API provider, 🟡 **beta**
* [**XCAP_CLIENT**](../../modules/xcap_client/README.md) - XCAP client implementation, 🟢 **stable**

---

## Scripting modules

### Script helper modules

* [**JSON**](../../modules/json/README.md) - JSON packing function, 🟢 **stable**
* [**CFGUTILS**](../../modules/cfgutils/README.md) - Different config utilities, 🟢 **stable**
* [**EXEC**](../../modules/exec/README.md) - External exec module, 🟢 **stable**
* [**TEXTOPS**](../../modules/textops/README.md) - Text operations module, 🟢 **stable**
* [**AVPOPS**](../../modules/avpops/README.md) - AVP operation module, 🟢 **stable**
* [**REGEX**](../../modules/regex/README.md) - RegExp via PCRE library, 🟢 **stable**
* [**MATHOPS**](../../modules/mathops/README.md) - Math operations module, 🟡 **beta** / 🔵 **NEW**
* [**BENCHMARK**](../../modules/benchmark/README.md) - Config file benchmarking, 🟢 **stable**
* [**GFLAGS**](../../modules/gflags/README.md) - Global shared flags module, 🟢 **stable**
* [**PYTHON**](../../modules/python/README.md) - Python scripting support, 🟡 **beta**
* [**LUA**](../../modules/lua/README.md) - Call LUA scripts from OpenSIPS cfg, 🟡 **beta**
* [**PERL**](../../modules/perl/README.md) - embed execution of Perl function, 🟢 **stable**
* [**MMGEOIP**](../../modules/mmgeoip/README.md) - MaxMind GeoIP module, 🟢 **stable**

### Auth modules

* [**AUTH_AAA**](../../modules/auth_aaa/README.md) - AAA-backend authentication module, 🟢 **stable**
* [**AUTH**](../../modules/auth/README.md) - Authentication Framework module, 🟢 **stable**
* [**AUTH_DB**](../../modules/auth_db/README.md) - Database-backend authentication module, 🟢 **stable**
* [**PERMISSIONS**](../../modules/permissions/README.md) - Permissions control module, 🟢 **stable**
* [**AUTH_DIAMETER**](../../modules/auth_diameter/README.md) - DIAMETER-backend authentication module, ⚫ **unmaintained**

### Accounting & Billing modules

* [**ACC**](../../modules/acc/README.md) - Accounting module, 🟢 **stable**
* [**CALL CONTROL**](../../modules/call_control/README.md) - PrePaid application module, 🟡 **beta**

### Dialplan Modules

* [**ALIAS_DB**](../../modules/alias_db/README.md) - Database SIP aliases module, 🟢 **stable**
* [**DIALPLAN**](../../modules/dialplan/README.md) - Dialplan management, 🟢 **stable**
* [**DOMAIN**](../../modules/domain/README.md) - Multi-domain support module, 🟢 **stable**
* [**DOMAINPOLICY**](../../modules/domainpolicy/README.md) - Policies to connect federations, 🟡 **beta**
* [**GROUP**](../../modules/group/README.md) - User-groups module with DB-backend, 🟢 **stable**
* [**USERBLACKLIST**](../../modules/userblacklist/README.md) - User black/white listing, 🟢 **stable**
* [**SPEEDDIAL**](../../modules/speeddial/README.md) - Per-user speed-dial controller module, 🟢 **stable**
* [**PEERING**](../../modules/peering/README.md) - Radius peering module, 🔴 **alpha**
* [**CLOSEDDIAL**](../../modules/closeddial/README.md) - PBX-like dialling features, 🟢 **stable**

### Data caching

* [**DNS_CACHE**](../../modules/dns_cache/README.md) - Module for caching DNS records that can be used with any Key-Value back-end, 🟢 **stable**
* [**USRLOC**](../../modules/usrloc/README.md) - User location implementation module, 🟢 **stable**

### Traffic shaping module

* [**PIKE**](../../modules/pike/README.md) - Flood detector module, 🟢 **stable**
* [**QOS**](../../modules/qos/README.md) - QOS (RTP) module, 🟡 **beta**
* [**RATELIMIT**](../../modules/ratelimit/README.md) - SIP traffic shaping module, 🟢 **stable**

---

## Database modules

### SQL modules

* [**DB_BERKELEY**](../../modules/db_berkeley/README.md) - Berkeley DB driver for DB API, 🟢 **stable**
* [**DB_CACHEDB**](../../modules/db_cachedb/README.md) - SQL to CacheDB translator, 🟡 **beta** / 🔵 **NEW**
* [**DB_FLATSTORE**](../../modules/db_flatstore/README.md) - Fast writing-only text-backend for database module, 🟢 **stable**
* [**DB_HTTP**](../../modules/db_http/README.md) - HTTP-backend for DB API, 🟡 **beta**
* [**DB_MYSQL**](../../modules/db_mysql/README.md) - MYSQL-backend for database API module, 🟢 **stable**
* [**DB_ORACLE**](../../modules/db_oracle/README.md) - ORACLE-backend for database API module, 🟡 **beta**
* [**DB_PERLVDB**](../../modules/db_perlvdb/README.md) - Perl Virtual Database engine, 🟢 **stable**
* [**DB_POSTGRES**](../../modules/db_postgres/README.md) - POSTGRES-backend for database API module, 🟢 **stable**
* [**DB_TEXT**](../../modules/db_text/README.md) - Text-backend for database API module, 🟢 **stable**
* [**DB_UNIXODBC**](../../modules/db_unixodbc/README.md) - unixODBC driver module, 🟢 **stable**
* [**DB_VIRTUAL**](../../modules/db_virtual/README.md) - Middle-layer DB mixer, 🟢 **stable**

### noSQL modules

* [**CACHEDB_CASSANDRA**](../../modules/cachedb_cassandra/README.md) - Cassandra Implementation of CacheDB, 🟡 **beta**
* [**CACHEDB_COUCHBASE**](../../modules/cachedb_couchbase/README.md) - CouchBase Implementation of CacheDB, 🟡 **beta** / 🔵 **NEW**
* [**CACHEDB_LOCAL**](../../modules/cachedb_local/README.md) - Local Implementation of CacheDB, 🟢 **stable**
* [**CACHEDB_MEMCACHED**](../../modules/cachedb_memcached/README.md) - Memcached Implementation of CacheDB, 🟢 **stable**
* [**CACHEDB_MONGODB**](../../modules/cachedb_mongodb/README.md) - MongoDB Implementation of CacheDB, 🟡 **beta** / 🔵 **NEW**
* [**CACHEDB_REDIS**](../../modules/cachedb_redis/README.md) - Redis Implementation of CacheDB, 🟡 **beta**
* [**CACHEDB_SQL**](../../modules/cachedb_sql/README.md) - SQL-based Implementation of CacheDB, 🟡 **beta** / 🔵 **NEW**

---

## External Integration modules

### OpenSIPS API modules

* [**EVENT_DATAGRAM**](../../modules/event_datagram/README.md) - Event datagram module, 🟢 **stable**
* [**EVENT_ROUTE**](../../modules/event_route/README.md) - Route triggering based on events, 🟡 **beta** / 🔵 **NEW**
* [**EVENT_RABBITMQ**](../../modules/event_rabbitmq/README.md) - Event RabbitMQ client module, 🟢 **stable**
* [**EVENT_XMLRPC**](../../modules/event_xmlrpc/README.md) - Event XMLRPC client module, 🟡 **beta** / 🔵 **NEW**
* [**MI_DATAGRAM**](../../modules/mi_datagram/README.md) - DATAGRAM (unix and network) support for Management Interface, 🟢 **stable**
* [**MI_FIFO**](../../modules/mi_fifo/README.md) - FIFO support for Management Interface, 🟢 **stable**
* [**MI_HTTP**](../../modules/mi_http/README.md) - HTTP support for Management Interface, 🟢 **stable**
* [**MI_XMLRPC_NG**](../../modules/mi_xmlrpc_ng/README.md) - XMLRPC support for Management Interface, 🟡 **beta** / 🔵 **NEW**
* [**HTTPD**](../../modules/httpd/README.md) - Embedded HTTP server, 🟢 **stable**
* [**PI_HTTP**](../../modules/pi_http/README.md) - Provisioning Interface module, 🟢 **stable**
* [**STATISTICS**](../../modules/statistics/README.md) - Script statistics support, 🟢 **stable**
* [**MI_XMLRPC**](../../modules/mi_xmlrpc/README.md) - XMLRPC support for Management Interface, 🟢 **stable**

### Media Relays

* [**MEDIAPROXY**](../../modules/mediaproxy/README.md) - NAT traversal module, 🟢 **stable**
* [**RTPPROXY**](../../modules/rtpproxy/README.md) - NAT traversal using RTPProxy module, 🟢 **stable**

### External integration (non-SIP protocols)

* [**AAA_RADIUS**](../../modules/aaa_radius/README.md) - RADIUS backend for the AAA API, 🟢 **stable**
* [**H350**](../../modules/h350/README.md) - H350 implementation, 🟢 **stable**
* [**LDAP**](../../modules/ldap/README.md) - LDAP connector, 🟢 **stable**
* [**REST_CLIENT**](../../modules/rest_client/README.md) - Implementation of an HTTP client, 🟡 **beta** / 🔵 **NEW**
* [**SEAS**](../../modules/seas/README.md) - Sip Express Application Server (interface module), 🟢 **stable**
* [**SIPCAPTURE**](../../modules/sipcapture/README.md) - SipCapture module, 🟢 **stable**
* [**SIPTRACE**](../../modules/siptrace/README.md) - SipTrace module, 🟢 **stable**
* [**SNGTC**](../../modules/sngtc/README.md) - Voice Transcoding in OpenSIPS using Sangoma hardware, 🟡 **beta** / 🔵 **NEW**
* [**SNMPStats**](../../modules/snmpstats/README.md) - SNMP interface for statistics module, 🟢 **stable**
* [**STUN**](../../modules/stun/README.md) - Built-in STUN server, 🟢 **stable**
* [**XMPP**](../../modules/xmpp/README.md) - SIP-to-XMPP Gateway (SIP to Jabber/Google Talk), 🟢 **stable**

---

## OpenSIPS protocols and infrastructure

* [**TLSOPS**](../../modules/tlsops/README.md) - TLS operations module, 🟢 **stable**
