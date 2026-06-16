---
title: "Modules"
description: ""
---

## SIP related modules

### SIP signaling modules
* [**B2B_ENTITIES**](../../modules/b2b_entities/README.md) - Back-to-Back User Agent Entities, 🟢 **stable**
* [**B2B_LOGIC**](../../modules/b2b_logic/README.md) - Back-to-Back User Agent Logic, 🟢 **stable**
* [**CALL CENTER**](../../modules/call_center/README.md) - Inbound call center system , 🟢 **stable**
* [**DIALOG**](../../modules/dialog/README.md) - Dialog support module , 🟢 **stable**
* [**NAT_TRAVERSAL**](../../modules/nat_traversal/README.md) - NAT traversal module , 🟢 **stable**
* [**NATHELPER**](../../modules/nathelper/README.md) - NAT traversal helper module , 🟢 **stable**
* [**OPTIONS**](../../modules/options/README.md) - OPTIONS server replier module , 🟢 **stable**
* [**REGISTRAR**](../../modules/registrar/README.md) - SIP Registrar implementation module , 🟢 **stable**
* [**SIGNALING**](../../modules/signaling/README.md) - SIP signaling module , 🟢 **stable**
* [**UAC_REGISTRANT**](../../modules/uac_registrant/README.md) - SIP Registrant implementation module , 🟢 **stable**
* [**TM**](../../modules/tm/README.md) - Transaction (stateful) module , 🟢 **stable**
* [**SL**](../../modules/sl/README.md) - Stateless replier module , 🟢 **stable**
* [**MEDIA_EXCHANGE**](../../modules/media_exchange/README.md) - Module to exchange SDP bodies between different SIP calls, 🟢 **stable**
* [**CALLOPS**](../../modules/callops/README.md) - Module to trigger different call operations on ongoing SIP calls, 🟢 **stable**
* [**B2B_SDP_DEMUX**](../../modules/b2b_sdp_demux/README.md) - Module to de-multiplex calls with multiple media streams, 🟢 **stable**
* [**MSRP_UA**](../../modules/msrp_ua/README.md) - MSRP User Agent module, 🟢 **stable**

### SIP Routing modules
* [**CARRIERROUTE**](../../modules/carrierroute/README.md) - routing extension suitable for carriers , 🟢 **stable**
* [**CPL_C**](../../modules/cpl_c/README.md) - CPL interpreter module , 🟢 **stable**
* [**DISPATCHER**](../../modules/dispatcher/README.md) - Dispatcher module , 🟢 **stable**
* [**DROUTING**](../../modules/drouting/README.md) - Dynamic Routing / LCR , 🟢 **stable**
* [**QROUTING**](../../modules/qrouting/README.md) - Quality-based Routing , 🟢 **stable**
* [**EMERGENCY**](../../modules/emergency/README.md) - Emergency module, 🟢 **stable**
* [**ENUM**](../../modules/enum/README.md) - ENUM lookup module , 🟢 **stable**
* [**JABBER**](../../modules/jabber/README.md) - JABBER IM and PRESENCE interconnection module , beta
* [**IMC**](../../modules/imc/README.md) - Instant Messaging Conferencing module , 🟢 **stable**
* [**LOAD_BALANCER**](../../modules/load_balancer/README.md) - Load Balancer (for calls) module, 🟢 **stable**
* [**MID_REGISTRAR**](../../modules/mid_registrar/README.md) - SIP registration front-end with traffic throttling , 🟢 **stable**
* [**MSILO**](../../modules/msilo/README.md) - SIP message silo module , 🟢 **stable**
* [**MSRP_GATEWAY**](../../modules/msrp_gateway/README.md) - SIP MESSAGE / MSRP gateway module, 🟢 **stable**
* [**RR**](../../modules/rr/README.md) - Record-Route and Route module , 🟢 **stable**
* [**SCRIPT_HELPER**](../../modules/script_helper/README.md) - Embedded SIP routing logic and dialog management, 🟢 **stable**
* [**OSP**](../../modules/osp/README.md) - OSP peering module , 🟢 **stable**

### SIP messaging operations
* [**COMPRESSION**](../../modules/compression/README.md) - Message compression and compaction, 🟢 **stable**
* [**DIVERSION**](../../modules/diversion/README.md) - Diversion header insertion module , 🟢 **stable**
* [**IDENTITY**](../../modules/identity/README.md) - SIP Identity implementation, 🟢 **stable**
* [**MAXFWD**](../../modules/maxfwd/README.md) - Max-Forward processor module , 🟢 **stable**
* [**MANGLER**](../../modules/mangler/README.md) - SIP mangler module , 🟢 **stable**
* [**PATH**](../../modules/path/README.md) - Path support for SIP frontending , 🟢 **stable**
* [**SIP_I**](../../modules/sip_i/README.md) - ISUP manipulation module , 🟢 **stable**
* [**SIPMSGOPS**](../../modules/sipmsgops/README.md) - SIP operations module , 🟢 **stable**
* [**STIR_SHAKEN**](../../modules/stir_shaken/README.md) - STIR/SHAKEN support , 🟢 **stable**
* [**TOPOLOGY_HIDING**](../../modules/topology_hiding/README.md) - Provides Topology Hiding capabilities , 🟢 **stable**
* [**UAC**](../../modules/uac/README.md) - UAC functionalies (FROM mangling and UAC auth) , 🟢 **stable**
* [**UAC_AUTH**](../../modules/uac_auth/README.md) - UAC Authentication functionality, 🟢 **stable**
* [**UAC_REDIRECT**](../../modules/uac_redirect/README.md) - UAC redirection functionality , 🟢 **stable**
* [**SST**](../../modules/sst/README.md) - SIP Session Timer support , 🟢 **stable**

### SIP Presence Modules
* [**PRESENCE**](../../modules/presence/README.md) - Presence server module - common API , 🟢 **stable**
* [**PRESENCE_CALLINFO**](../../modules/presence_callinfo/README.md) - Extension to Presence server for Call-Info, 🟢 **stable**
* [**PRESENCE_DIALOGINFO**](../../modules/presence_dialoginfo/README.md) - Extension to Presence server for Dialog Info, 🟢 **stable**
* [**PRESENCE_DFKS**](../../modules/presence_dfks/README.md) - Extension to Presence server for Device Feature Key Synchronization, 🟢 **stable**
* [**PRESENCE_MWI**](../../modules/presence_mwi/README.md) - Extension to Presence server for Message Waiting Indication , 🟢 **stable**
* [**PRESENCE_REGINFO**](../../modules/presence_reginfo/README.md) - Extension to Presence server for "reg"-events according to RFC 3680 , 🟢 **stable**
* [**PRESENCE_XCAPDIFF**](../../modules/presence_xcapdiff/README.md) - Extension to Presence server for XCAP-DIFF event, 🟢 **stable**
* [**PRESENCE_XML**](../../modules/presence_xml/README.md) - Presence server module - presence & watcher info and XCAP , 🟢 **stable**
* [**PUA**](../../modules/pua/README.md) - Common API for presence user agent client , 🟢 **stable**
* [**PUA_BLA**](../../modules/pua_bla/README.md) - BLA extension for PUA , 🟢 **stable**
* [**PUA_DIALOGINFO**](../../modules/pua_dialoginfo/README.md) - Dialog-Info extension for PUA , 🟢 **stable**
* [**PUA_MI**](../../modules/pua_mi/README.md) - MI extension for PUA , 🟢 **stable**
* [**PUA_REGINFO**](../../modules/pua_reginfo/README.md) - Publisher for "reg"-events according to RFC 3680 , 🟢 **stable**
* [**PUA_USRLOC**](../../modules/pua_usrloc/README.md) - USRLOC extension for PUA , 🟢 **stable**
* [**PUA_XMPP**](../../modules/pua_xmpp/README.md) - XMPP extension for PUA (SIMPLE-XMPP presence gateway) , 🟢 **stable**
* [**B2B_SCA**](../../modules/b2b_sca/README.md) - Back-to-Back Shared Call Appearance, 🟢 **stable**
* [**RLS**](../../modules/rls/README.md) - Resource List Server implementation , 🟢 **stable**
* [**XCAP**](../../modules/xcap/README.md) - XCAP API provider , 🟢 **stable**
* [**XCAP_CLIENT**](../../modules/xcap_client/README.md) - XCAP client implementation , 🟢 **stable**

---

## Scripting modules

### Script helper modules
* [**JSON**](../../modules/json/README.md) - Manipulate JSON objects in OpenSIPS script, 🟢 **stable** 
* [**XML**](../../modules/xml/README.md) - Manipulate XML documents in OpenSIPS script, 🟢 **stable**
* [**CFGUTILS**](../../modules/cfgutils/README.md) - Various utility functions, 🟢 **stable**
* [**CONFIG**](../../modules/config/README.md) - DB backed runtime configuration, alpha / 🔵 **NEW**
* [**EXEC**](../../modules/exec/README.md) - External exec module , 🟢 **stable**
* [**TEXTOPS**](../../modules/textops/README.md) - Text operations module, 🟢 **stable**
* **AVPOPS** - renamed, see [SQLops module](../../modules/sqlops/README.md)
* [**SQLOPS**](../../modules/sqlops/README.md) - SQL DB operations module 🟢 **stable**
* [**REGEX**](../../modules/regex/README.md) - RegExp via PCRE library, 🟢 **stable**
* [**MATHOPS**](../../modules/mathops/README.md) - Floating point and rounding operations, 🟢 **stable**
* [**BENCHMARK**](../../modules/benchmark/README.md) - Script file benchmarking,  🟢 **stable**
* [**CARRIERROUTE**](../../modules/carrierroute/README.md) - routing extension suitable for carriers , 🟢 **stable**
* [**GFLAGS**](../../modules/gflags/README.md) - Global shared flags module, 🟢 **stable**
* [**PYTHON**](../../modules/python/README.md) - Python scripting support, 🟢 **stable**
* [**LUA**](../../modules/lua/README.md) - Call LUA scripts from OpenSIPS cfg, 🟢 **stable**
* [**PERL**](../../modules/perl/README.md) - embed execution of Perl function , 🟢 **stable**
* [**MMGEOIP**](../../modules/mmgeoip/README.md) - MaxMind GeoIP module, 🟢 **stable**
* [**UUID**](../../modules/uuid/README.md) - UUID generation, 🟢 **stable**
* [**MQUEUE**](../../modules/mqueue/README.md) - Message queue system inter-process communication using the config file, 🟢 **stable**

### Auth modules
* [**AUTH_AAA**](../../modules/auth_aaa/README.md) - AAA-backend authentication module, 🟢 **stable**
* [**AUTH**](../../modules/auth/README.md) - Authentication Framework module, 🟢 **stable**
* [**AUTH_DB**](../../modules/auth_db/README.md) -Database-backend authentication module, 🟢 **stable**
* [**AUTH_JWT**](../../modules/auth_jwt/README.md) -Authentication over JSON Web Tokens, 🟢 **stable**
* [**AUTH_AKA**](../../modules/auth_aka/README.md) - Authentication using RFC 3310 AKA mechanism, beta
* [**AUTH_WEB3**](../../modules/auth_web3/README.md) - Web3-based SIP authentication through blockchain and ENS, alpha / 🔵 **NEW**
* [**AKA_AV_DIAMETER**](../../modules/aka_av_diameter/README.md) - Fetches RFC 3310 AKA AVs using Cx/Dx Diameter interface, beta
* [**PERMISSIONS**](../../modules/permissions/README.md) - Permissions control module , 🟢 **stable**

### Accounting & Billing modules
* [**ACC**](../../modules/acc/README.md) - Accounting module, 🟢 **stable**
* [**CALL CONTROL**](../../modules/call_control/README.md) - PrePaid application module , 🟢 **stable**
* [**CGRATES**](../../modules/cgrates/README.md) - Connector to  the CGRateS billing engine, 🟢 **stable**

### Dialplan Modules
* [**ALIAS_DB**](../../modules/alias_db/README.md) - Database SIP aliases module, 🟢 **stable**
* [**DIALPLAN**](../../modules/dialplan/README.md) - Dialplan management , 🟢 **stable**
* [**DOMAIN**](../../modules/domain/README.md) - Multi-domain support module , 🟢 **stable**
* [**DOMAINPOLICY**](../../modules/domainpolicy/README.md) - Policies to connect federations , 🟢 **stable**
* [**GROUP**](../../modules/group/README.md) - User-groups module with DB-backend , 🟢 **stable**
* [**USERBLACKLIST**](../../modules/userblacklist/README.md) - User black/white listing , 🟢 **stable**
* [**SPEEDDIAL**](../../modules/speeddial/README.md) - Per-user speed-dial controller module , 🟢 **stable**
* [**PEERING**](../../modules/peering/README.md) - Radius peering module , 🟢 **stable**

### Data caching
* [**DNS_CACHE**](../../modules/dns_cache/README.md) - Module for caching DNS records that can be used with any Key-Value back-end , 🟢 **stable**
* [**RATE_CACHER**](../../modules/rate_cacher/README.md) - Cache, Query, Reload or Update rates via MI, 🟢 **stable**
* [**SQL_CACHER**](../../modules/sql_cacher/README.md) - SQL Caching module, 🟢 **stable**
* [**TRIE**](../../modules/trie/README.md) - Fast, low memory cache with trie search for number, alpha / 🔵 **NEW**
* [**USRLOC**](../../modules/usrloc/README.md) - User location implementation module , 🟢 **stable**

### Traffic shaping module
* [**PIKE**](../../modules/pike/README.md) - Flood detector module , 🟢 **stable**
* [**QOS**](../../modules/qos/README.md) - QOS (RTP) module , 🟢 **stable**
* [**RATELIMIT**](../../modules/ratelimit/README.md) - SIP traffic shaping module , 🟢 **stable**
* [**FRAUD_DETECTION**](../../modules/fraud_detection/README.md) - Detects fraudulent calls, 🟢 **stable**

---

## Database modules

### SQL modules
* [**DB_BERKELEY**](../../modules/db_berkeley/README.md) - Berkeley DB driver for DB API , 🟢 **stable**
* [**DB_CACHEDB**](../../modules/db_cachedb/README.md) - SQL to CacheDB translator , 🟢 **stable**
* [**DB_FLATSTORE**](../../modules/db_flatstore/README.md) - Fast writing-only text-backend for database module , 🟢 **stable**
* [**DB_HTTP**](../../modules/db_http/README.md) - HTTP-backend for DB API , 🟢 **stable**
* [**DB_MYSQL**](../../modules/db_mysql/README.md) - MYSQL-backend for database API module , 🟢 **stable**
* [**DB_ORACLE**](../../modules/db_oracle/README.md) - ORACLE-backend for database API module , 🟢 **stable**
* [**DB_PERLVDB**](../../modules/db_perlvdb/README.md) - Perl Virtual Database engine , 🟢 **stable**
* [**DB_POSTGRES**](../../modules/db_postgres/README.md) - POSTGRES-backend for database API module , 🟢 **stable**
* [**DB_SQLITE**](../../modules/db_sqlite/README.md) - SQLITE3-backend for database API module , 🟢 **stable**
* [**DB_TEXT**](../../modules/db_text/README.md) - Text-backend for database API module , 🟢 **stable**
* [**DB_UNIXODBC**](../../modules/db_unixodbc/README.md) - unixODBC driver module , 🟢 **stable**
* [**DB_VIRTUAL**](../../modules/db_virtual/README.md) - Middle-layer DB mixer, 🟢 **stable**

### noSQL modules
* [**CACHEDB_CASSANDRA**](../../modules/cachedb_cassandra/README.md) - Cassandra Implementation of CacheDB, 🟢 **stable**
* [**CACHEDB_COUCHBASE**](../../modules/cachedb_couchbase/README.md) - CouchBase Implementation of CacheDB, 🟢 **stable**
* [**CACHEDB_DYNAMODB**](../../modules/cachedb_dynamodb/README.md) - AWS DynamoDB Implementation of CacheDB, alpha / 🔵 **NEW**
* [**CACHEDB_LOCAL**](../../modules/cachedb_local/README.md) - Local Implementation of CacheDB, 🟢 **stable**
* [**CACHEDB_MEMCACHED**](../../modules/cachedb_memcached/README.md) - Memcached Implementation of CacheDB, 🟢 **stable**
* [**CACHEDB_MONGODB**](../../modules/cachedb_mongodb/README.md) - MongoDB Implementation of CacheDB, 🟢 **stable**
* [**CACHEDB_REDIS**](../../modules/cachedb_redis/README.md) - Redis Implementation of CacheDB, 🟢 **stable**
* [**CACHEDB_SQL**](../../modules/cachedb_sql/README.md) - SQL-based Implementation of CacheDB, 🟢 **stable**

---

## External Integration modules

### OpenSIPS API modules
* [**EVENT_DATAGRAM**](../../modules/event_datagram/README.md) - Publish JSON-RPC notifications using UDP, 🟢 **stable**
* [**EVENT_FLATSTORE**](../../modules/event_flatstore/README.md) - Text/File backend for events, 🟢 **stable**
* [**EVENT_KAFKA**](../../modules/event_kafka/README.md) - Publish JSON-RPC notifications/generic messages to Apache Kafka , 🟢 **stable**
* [**EVENT_ROUTE**](../../modules/event_route/README.md) - Route triggering based on events, 🟢 **stable**
* [**EVENT_ROUTING**](../../modules/event_routing/README.md) - Event-based routing, 🟢 **stable**
* [**EVENT_RABBITMQ**](../../modules/event_rabbitmq/README.md) - Publish JSON-RPC notifications using AMQP over TCP , 🟢 **stable**
* [**EVENT_STREAM**](../../modules/event_stream/README.md) - Publish JSON-RPC notifications using TCP, 🟢 **stable**
* [**EVENT_SQS**](../../modules/event_sqs/README.md) - An implementation of an Amazon SQS producer, alpha / 🔵 **NEW**
* [**EVENT_VIRTUAL**](../../modules/event_virtual/README.md) - Aggregator of event backends (failover & balancing), 🟢 **stable**
* [**EVENT_XMLRPC**](../../modules/event_xmlrpc/README.md) - Event XMLRPC client module , 🟢 **stable**
* [**MI_DATAGRAM**](../../modules/mi_datagram/README.md) - DATAGRAM (unix and network) support for Management Interface , 🟢 **stable**
* [**MI_FIFO**](../../modules/mi_fifo/README.md) - FIFO support for Management Interface , 🟢 **stable**
* [**MI_HTML**](../../modules/mi_html/README.md) - Minimal web GUI for Management Interface , 🟢 **stable**
* [**MI_HTTP**](../../modules/mi_http/README.md) - HTTP support for Management Interface , 🟢 **stable**
* [**MI_SCRIPT**](../../modules/mi_script/README.md) - support for running Management Interface commands in script , 🟢 **stable**
* [**MI_XMLRPC**](../../modules/mi_xmlrpc/README.md) - XMLRPC support for Management Interface , 🟢 **stable**
* [**HTTPD**](../../modules/httpd/README.md) - Embedded HTTP server , 🟢 **stable**
* [**PI_HTTP**](../../modules/pi_http/README.md) - Provisioning Interface module , 🟢 **stable**
* [**RABBITMQ**](../../modules/rabbitmq/README.md) - Connector to a RabbitMQ message broker, 🟢 **stable**
* [**RABBITMQ_CONSUMER**](../../modules/rabbitmq_consumer/README.md) - Connect to RabbitMQ and receive events, 🟢 **stable**
* [**STATISTICS**](../../modules/statistics/README.md) - Script statistics support , 🟢 **stable**
* [**STATUS_REPORT**](../../modules/status_report/README.md) - Script Status/Report identifiers support , 🟢 **stable**

### Media Relays
* [**MEDIAPROXY**](../../modules/mediaproxy/README.md) - NAT traversal module , 🟢 **stable**
* [**MSRP_RELAY**](../../modules/msrp_relay/README.md) - Implementation of a Relay for the MSRP protocol , 🟢 **stable**
* [**RTPENGINE**](../../modules/rtpengine/README.md) - Connector to RTPengine external RTP relay , 🟢 **stable**
* [**RTPPROXY**](../../modules/rtpproxy/README.md) - Connector to RTPproxy external RTP relay, 🟢 **stable**
* [**RTP.IO**](../../modules/rtp.io/README.md) - Builtin RTP relay module, alpha / 🔵 **NEW**
* [**RTP_RELAY**](../../modules/rtp_relay/README.md) - Interface for different RTP relay engines, 🟢 **stable**

### External integration (non-SIP protocols)
* [**AAA_DIAMETER**](../../modules/aaa_diameter/README.md) - Diameter backend for the AAA API, 🟢 **stable**
* [**AAA_RADIUS**](../../modules/aaa_radius/README.md) - RADIUS backend for the AAA API, 🟢 **stable**
* [**FREESWITCH**](../../modules/freeswitch/README.md) - FreeSWITCH ESL connection manager, 🟢 **stable**
* [**FREESWITCH_SCRIPTING**](../../modules/freeswitch_scripting/README.md) - FreeSWITCH events & commands at OpenSIPS script level, 🟢 **stable**
* [**H350**](../../modules/h350/README.md) - H350 implementation , 🟢 **stable**
* [**HTTP2D**](../../modules/http2d/README.md) - Programmable HTTP/2 Server, beta
* [**JANUS**](../../modules/janus/README.md) - WEB Socket connector to Janus (for running commands), alpha / 🔵 **NEW**
* [**JSONRPC**](../../modules/jsonrpc/README.md) - Execute JSON-RPC commands, 🟢 **stable**
* [**LAUNCH_DARKLY**](../../modules/launch_darkly/README.md) - Launch Darkly integration, beta
* [**LDAP**](../../modules/ldap/README.md) - LDAP connector , 🟢 **stable**
* [**OPENTELEMETRY**](../../modules/opentelemetry/README.md) - tracing the OpenSIPS routes execution and the logs they produce alpha / 🔵 **NEW**
* [**PROMETHEUS**](../../modules/prometheus/README.md) - export statistics to a [Prometheus](http://prometheus.io/) server, 🟢 **stable**
* [**REST_CLIENT**](../../modules/rest_client/README.md) - Implementation of an HTTP client , 🟢 **stable**
* [**SEAS**](../../modules/seas/README.md) - Sip Express Application Server (interface module) , 🟢 **stable**
* [**SIPCAPTURE**](../../modules/sipcapture/README.md) - SipCapture module , 🟢 **stable**
* [**SIPREC**](../../modules/siprec/README.md) - SIP Recording module , 🟢 **stable**
* [**TRACER**](../../modules/tracer/README.md) - Collects SIP, logs, DNS or REST queries and ships them to various backends , 🟢 **stable**
* [**SNGTC**](../../modules/sngtc/README.md) - Voice Transcoding in OpenSIPS using Sangoma hardware , 🟢 **stable**
* [**SNMPStats**](../../modules/snmpstats/README.md) - SNMP interface for statistics module , 🟢 **stable**
* [**STUN**](../../modules/stun/README.md) - Built-in STUN server , 🟢 **stable** - 
* [**XMPP**](../../modules/xmpp/README.md) - SIP-to-XMPP Gateway (SIP to Jabber/Google Talk) , 🟢 **stable**

---

## OpenSIPS protocols and infrastructure
* [**CLUSTERER**](../../modules/clusterer/README.md) - Define and configure an OpenSIPS cluster, 🟢 **stable**
* [**TLS_MGM**](../../modules/tls_mgm/README.md) - TLS management module , 🟢 **stable**
* [**TLS_OPENSSL**](../../modules/tls_openssl/README.md) - TLS operations implemented using the openSSL library , 🟢 **stable**
* [**TLS_WOLFSSL**](../../modules/tls_wolfssl/README.md) - TLS operations implemented using the wolfSSL library , 🟢 **stable**
* [**TCP_MGM**](../../modules/tcp_mgm/README.md) - TCP connections management module , 🟢 **stable**
* [**PROTO_BIN**](../../modules/proto_bin/README.md) - Binary INterface protocol module - implements inter-OPENSIPS communication , 🟢 **stable**
* [**PROTO_BINS**](../../modules/proto_bins/README.md) - Binary INterface over TLS protocol module - implements Secure inter-OPENSIPS communication , 🟢 **stable**
* [**PROTO_HEP**](../../modules/proto_hep/README.md) - HEP protocol module - implements HEP transport for SIP , 🟢 **stable**
* [**PROTO_IPSEC**](../../modules/proto_ipsec/README.md) - implements IMS IPSec protocol according to TS 33.203 specs, beta
* [**PROTO_MSRP**](../../modules/proto_msrp/README.md) - implements MSRP protocol stack, 🟢 **stable**
* [**PROTO_SCTP**](../../modules/proto_sctp/README.md) - SCTP protocol module - implements SCTP transport for SIP , 🟢 **stable**
* [**PROTO_TCP**](../../modules/proto_tcp/README.md) - TCP protocol module - implements TCP-plain transport for SIP , 🟢 **stable**
* [**PROTO_TLS**](../../modules/proto_tls/README.md) - TLS protocol module - implements TLS transport for SIP , 🟢 **stable**
* [**PROTO_UDP**](../../modules/proto_udp/README.md) - UDP protocol module - implements UDP-plain transport for SIP , 🟢 **stable**
* [**PROTO_WS**](../../modules/proto_ws/README.md) - WebSocket protocol module - implements WS transport for SIP , 🟢 **stable**
* [**PROTO_WSS**](../../modules/proto_wss/README.md) - WebSocket Secure protocol module - implements WSS transport for SIP , 🟢 **stable**
* [**PROTO_SMPP**](../../modules/proto_smpp/README.md) - SMPP (Short Message Peer-to-Peer) protocol module - implements transport for SMPP messages, 🟢 **stable**
* [**SOCKETS_MGM**](../../modules/sockets_mgm/README.md) - Dynamic SIP Sockets Management at runtime, alpha / 🔵 **NEW**
