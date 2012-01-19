divert(-1)
define(`ENABLE_TCP', `yes') # OpenSIPS will listen on TCP for SIP requests
define(`ENABLE_TLS', `no') # OpenSIPS will listen on TLS for SIP requests
define(`USE_ALIASES', `yes') # OpenSIPS will allow the use of Aliases for SIP users
define(`USE_AUTH', `yes') # OpenSIPS will authenticate Register & Invite requests
define(`USE_DBACC', `yes') # OpenSIPS will save ACC entries in DB for all calls
define(`USE_DBUSRLOC', `yes') # OpenSIPS will store UsrLoc entries in the DB
define(`USE_DIALOG', `yes') # OpenSIPS will keep track of active dialogs
define(`USE_MULTIDOMAIN', `yes') # OpenSIPS will handle multiple domains for subscribers
define(`USE_NAT', `yes') # OpenSIPS will try to cope with NAT by fixing SIP msgs and engaging RTPProxy
define(`USE_PRESENCE', `yes') # OpenSIPS will act as a Presence server
define(`USE_DIALPLAN', `yes') # OpenSIPS will use dialplan for transformation of local numbers
define(`VM_DIVERSION', `yes') # OpenSIPS will redirect to VM calls not reaching the subscribers
define(`HAVE_INBOUND_PSTN', `yes') # OpenSIPS will accept calls from PSTN gateways (with static IP authentication)
define(`HAVE_OUTBOUND_PSTN', `yes') # OpenSIPS will send numerical dials to PSTN gateways (with static IP definition)
define(`USE_DR_PSTN', `yes') # OpenSIPS will use Dynamic Routing Support for PSTN interconnection
divert