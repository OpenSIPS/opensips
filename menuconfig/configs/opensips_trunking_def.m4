divert(-1)
define(`ENABLE_TCP', `yes') # OpenSIPS will listen on TCP for SIP requests
define(`ENABLE_TLS', `no') # OpenSIPS will listen on TLS for SIP requests
define(`USE_DBACC', `yes') # OpenSIPS will save ACC entries in DB for all calls
define(`USE_DIALPLAN', `yes') # OpenSIPS will use dialplan for transformation of local numbers
define(`USE_DIALOG', `yes') # OpenSIPS will keep track of active dialogs
define(`DO_CALL_LIMITATION', `yes') # OpenSIPS will limit the number of parallel calls per trunk
divert