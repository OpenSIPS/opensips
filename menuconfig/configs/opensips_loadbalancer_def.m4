divert(-1)
define(`ENABLE_TCP', `no') # OpenSIPS will listen on TCP for SIP requests
define(`ENABLE_TLS', `no') # OpenSIPS will listen on TLS for SIP requests
define(`USE_DBACC', `no') # OpenSIPS will save ACC entries in DB for all calls
define(`USE_DISPATCHER', `no') # OpenSIPS will use DISPATCHER instead of Load-Balancer for distributing the traffic
define(`DISABLE_PINGING', `yes') # OpenSIPS will not ping at all the destinations (otherwise it will ping when detected as failed)
define(`USE_HTTP_MANAGEMENT_INTERFACE', `no') # OpenSIPS will provide a WEB Management Interface on port 8888
divert