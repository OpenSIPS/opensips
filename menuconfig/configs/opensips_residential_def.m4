divert(-1)
define(`ENABLE_TCP', `no') # OpenSIPS will listen on TCP for SIP requests
define(`ENABLE_TLS', `no') # OpenSIPS will listen on TLS for SIP requests
define(`USE_ALIASES', `no') # OpenSIPS will allow the use of Aliases for SIP users
define(`USE_AUTH', `no') # OpenSIPS will authenticate Register & Invite requests
define(`USE_DBACC', `no') # OpenSIPS will save ACC entries in DB for all calls
define(`USE_DBUSRLOC', `no') # OpenSIPS will store UsrLoc entries in the DB
define(`USE_DIALOG', `no') # OpenSIPS will keep track of active dialogs
define(`USE_MULTIDOMAIN', `no') # OpenSIPS will handle multiple domains for subscribers
define(`USE_NAT', `no') # OpenSIPS will try to cope with NAT by fixing SIP msgs and engaging RTPProxy
define(`USE_PRESENCE', `no') # OpenSIPS will act as a Presence server
define(`USE_DIALPLAN', `no') # OpenSIPS will use dialplan for transformation of local numbers
define(`VM_DIVERSION', `no') # OpenSIPS will redirect to VM calls not reaching the subscribers
define(`HAVE_INBOUND_PSTN', `no') # OpenSIPS will accept calls from PSTN gateways (with static IP authentication)
define(`HAVE_OUTBOUND_PSTN', `no') # OpenSIPS will send numerical dials to PSTN gateways (with static IP definition)
define(`USE_DR_PSTN', `no') # OpenSIPS will use Dynamic Routing Support for PSTN interconnection
define(`USE_HTTP_MANAGEMENT_INTERFACE', `no') # OpenSIPS will provide a WEB Management Interface on port 8888
divert