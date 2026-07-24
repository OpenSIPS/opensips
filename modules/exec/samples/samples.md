### Example of using the EXEC module

This config is based on the simple SIP-to-SIP scenario. In addition to that we have Push Notification support for the calls to users. For the incoming calls (to users) we are using the exec module to run (in async mode) an external script for PN triggering. For this purpose, for each local user, we may store (in subscriber table) an optional PN token - this will be passed to the PN triggering script.

[opensips-exec.cfg](./opensips-exec.cfg "include")

