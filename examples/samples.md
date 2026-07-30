### OpenSIPS Redirect Server - simple LCR

In this example, OpenSIPS, based on the received RURI, builds at script level a Contact header which is appended to the 302 Redirect reply.

[opensips-redirect-server-CT.cfg](./opensips-redirect-server-CT.cfg "include")


### OpenSIPS Redirect Server - Redirect to user's registrations

In this example, for the incoming calls, OpenSIPS does redirect to the user's registrations. The message branches ($msg.branch.uri) are used here to make OpenSIPS to automatically build the Contact header for the 302 Redirect reply

[opensips-redirect-server-BRANCH.cfg](./opensips-redirect-server-BRANCH.cfg "include")


### OpenSIPS Redirect Server - Simple LCR rediret, option 2

This example re-takes the simple LCR, but instead of building the redirect contact manually, at script level, we use the $msg.branch variable to make OpenSIPS to automatically build the Contact header for the 302 Redirect reply

[opensips-redirect-server-BRANCH_2.cfg](./opensips-redirect-server-BRANCH_2.cfg "include")

