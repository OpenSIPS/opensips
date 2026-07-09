---
title: "AUTH_DIAMETER Module"
description: "This module implements SIP authentication and authorization with DIAMETER server, namely DIameter Server Client (DISC)."
---

## Admin Guide


### Overview


This module implements SIP authentication and authorization with
DIAMETER server, namely DIameter Server Client (DISC).


NOTE: diameter support was developed for DISC (DIameter Server Client 
project at http://developer.berlios.de/projects/disc/). This project 
seems to be no longer maintained and DIAMETER specifications were updated
in the meantime. Thus, the module is obsolete and needs rework to be 
usable with opendiameter or other DIAMETER servers.


The digest authentication mechanism is presented in next figure.


```c title="Digest Authentication"
...
	a) First phase of Digest Authentication for SIP:


     +----+ SIP INVITE   +=====+  DIAMETER      +------+       +------+
     |    | no Auth hdr  #/////#  AA-Request    |      |       |      |
     |    |---------1--->#/////#-------2------->|      |---2-->|      |
     |UAC |              #UAS//#                |DClnt |       |DSrv  |
     |    |<-----4-------#(SER)#<------3--------|(DISC)|<--3---|(DISC)|
     |    |     401      #/////#  DIAMETER      |      |       |      |
     +----+ Unauthorized +=====+  AA-Answer     +------+       +------+
                                  Result-Code=4001


	b) Second phase of Digest Authentication for SIP:


     +----+ SIP INVITE   +=====+  DIAMETER     +------+       +----+
     |    | Auth hdr     #/////#  AA-Request   |      |       |    |
     |    |--------1---->#/////#-------2------>|      |---2-->|    |
     |UAC |              #UAS//#               |DClnt |       |DSrv|
     |    |<-------4-----#(SER)#<------3-------|      |<--3---|    |
     |    |      200 OK  #/////#  DIAMETER     |      |       |    |
     +----+              +=====+  AA-Answer    +------+       +----+
                                  Result-Code=2001

...
```


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *sl* - used to send stateless replies.


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### diameter_client_host (string)


Hostname of the machine where the DIAMETER Client is running.


*Default value is "localhost".*


```opensips title="Set diameter_client_host parameter"
...
modparam("auth_diameter", "diameter_client_host", "10.10.10.10")
...
```


#### diameter_client_port (int)


Port number where the DIAMETER Client is listening.


*Default value is "3000".*


```opensips title="Set diameter_client_port parameter"
...
modparam("auth_diameter", "diameter_client_port", 3000)
...
```


#### use_domain (int)


Specifies whether the domain name part of URI is used when checking the
user's privileges.


*Default value is "0 (0==false and 1==true )".*


```opensips title="Set use_domain parameter"
...
modparam("auth_diameter", "use_domain", 1)
...
```


### Exported Functions


#### diameter_www_authorize(realm)


SIP Server checks for authorization having a DIAMETER server in backend.
If no credentials are provided inside the SIP request then a challenge
is sent back to UAC. If the credentials don't match the ones computed by
DISC then "403 Forbidden" is sent back.


Negative codes may be interpreted as follows:


- *-5 (generic error)* - some generic error
occurred and no reply was sent out;
- *-3 (stale nonce)* - stale nonce;


Meaning of the parameters is as follows:


- *realm* - the realm to be use for
authentication and authorization. The string may contain 
pseudo variables.


This function can be used from REQUEST_ROUTE.


```opensips title="diameter_www_authorize usage"
...
if(!diameter_www_authorize("siphub.net"))
{ /* user is not authorized */
	exit;
};
...
```


#### diameter_proxy_authorize(realm)


SIP Proxy checks for authorization having a DIAMETER server in backend.
If no credentials are provided inside the SIP request then a challenge
is sent back to UAC. If the credentials don't match the ones computed by
DISC then "403 Forbidden" is sent back.  For more about 
the negative return codes, see the above function.


Meaning of the parameters is as follows:


- *realm* - the realm to be use for
authentication and authorization. The string may contain 
pseudo variables.


This function can be used from REQUEST_ROUTE.


```opensips title="diameter_proxy_authorize usage"
...
if(!diameter_proxy_authorize("siphub.net"))
{ /* user is not authorized */
	exit;
};
...
```


#### diameter_is_user_in(who, group)


The method performs group membership checking with DISC.


Meaning of the parameters is as follows:


- *who* - what header to be used to get the
SIP URI that is wanted to be checked being member in a certain group.
It can be: "Request-URI", "From",
"To" or "Credentials".
- *group* - the group name where to check if
the user is part of.


This function can be used from REQUEST_ROUTE.


```opensips title="diameter_is_user_in usage"
...
if(!diameter_is_user_in("From", "voicemail"))
{ /* user is not authorized */
	exit;
};
...
```


### Installation and Running


Notes about installation and running.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
