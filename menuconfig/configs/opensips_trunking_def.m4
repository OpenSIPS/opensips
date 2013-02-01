divert(-1)
define(`ENABLE_TCP', `no') # OpenSIPS will listen on TCP for SIP requests
define(`ENABLE_TLS', `no') # OpenSIPS will listen on TLS for SIP requests
define(`USE_DBACC', `no') # OpenSIPS will save ACC entries in DB for all calls
define(`USE_DIALPLAN', `no') # OpenSIPS will use dialplan for transformation of local numbers
define(`USE_DIALOG', `no') # OpenSIPS will keep track of active dialogs
define(`DO_CALL_LIMITATION', `no') # OpenSIPS will limit the number of parallel calls per trunk
define(`USE_HTTP_MANAGEMENT_INTERFACE', `no') # OpenSIPS will provide a WEB Management Interface on port 8888
divert