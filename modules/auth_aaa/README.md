---
title: "Auth_aaa Module"
description: "This module contains functions that are used to perform digest authentication and some URI checks against an AAA server. In order to perform the authentication, the proxy will pass along the credentials to the AAA server which will in turn send a reply containing result of the authenti..."
---

## Admin Guide


### Overview


This module contains functions that are used to perform digest 
		authentication and some URI checks against an AAA server.
		In order to perform the authentication, the proxy will pass along the 
		credentials to the AAA server which will in turn send a reply 
		containing result of the authentication. So basically the whole
		authentication is done in the AAA server. Before sending the request 
		to the AAA server we perform some sanity checks over the 
		credentials to make sure that only well formed credentials will get to 
		the server.


### Additional Credentials


When performing authentication, the AAA server may include in the
		response additional credentials. This scheme is very useful in fetching
		additional user information from the AAA server without making
		extra queries.


The additional credentials are embedded in the AAA reply as AVPs 
		"SIP-AVP". The syntax of the value is:


- *value = SIP_AVP_NAME SIP_AVP_VALUE*
- *SIP_AVP_NAME = STRING_NAME | '#'ID_NUMBER*
- *SIP_AVP_VALUE = ':'STRING_VALUE | '#'NUMBER_VALUE*


All additional credentials will be stored as OpenSIPS AVPs
		(SIP_AVP_NAME = SIP_AVP_VALUE).


The RPID value may be fetch via this mechanism.


```c title="'SIP-AVP' AAA AVP examples"
....
"email:joe@yahoo.com"
    - STRING NAME AVP (email) with STRING VALUE (joe@yahoo.com)
"#14:joe@yahoo.com"
    - ID AVP (14) with STRING VALUE (joe@yahoo.com)
"age#28"
    - STRING NAME AVP (age) with INTEGER VALUE (28)
"#14#28"
    - ID AVP (14) with INTEGER VALUE (28)
....
		
```


### Dependencies


#### OpenSIPS Modules


The module depends on the following modules (in the other words 
			the listed modules must be loaded before this module):


- *auth* -- Authentication framework,
				only if the auth functions are used from script
- *an aaa implementing module* -- for 
				example aaa_radius


#### External Libraries or Applications


This module does not depend on any external library.


### Exported Parameters


#### aaa_url (string)


This is the url representing the AAA protocol used and the location of the configuration file of this protocol.


The syntax for the url is the following: "name_of_the_aaa_protocol_used:path_of_the_configuration_file"


```c title="aaa_url parameter usage"
		
modparam("auth_aaa", "aaa_url", "radius:/etc/radiusclient-ng/radiusclient.conf")
		
```


#### auth_service_type (integer)


This is the value of the Service-Type aaa attribute to be used when
		performing an authentication operation.
		The default should be fine for most people. See your aaa client 
		include files for numbers to be put in this parameter if you need 
		to change it.


Default value is "15".


```c title="auth_service_type parameter usage"
		
modparam("auth_aaa", "auth_service_type", 15)
		
```


#### check_service_type (integer)


AAA service type used by `aaa_does_uri_exist` and
		`aaa_does_uri_user_exist` checks.


*Default value is 10 (Call-Check).*


```c title="Set check_service_type parameter"
...
modparam("auth_aaa", "check_service_type", 11)
...
```


#### use_ruri_flag (string)


When this parameter is set to the value other than "NULL" and the
		request being authenticated has flag with matching number set
		via setflag() function, use Request URI instead of uri parameter
		value from the Authorization / Proxy-Authorization header field
		to perform AAA authentication.  This is intended to provide
		workaround for misbehaving NAT / routers / ALGs that alter request
		in the transit, breaking authentication.  At the time of this
		writing, certain versions of Linksys WRT54GL are known to do that.


Default value is "NULL" (not set).


```c title="use_ruri_flag parameter usage"
		
modparam("auth_aaa", "use_ruri_flag", "USE_RURI_FLAG")
		
```


### Exported Functions


#### aaa_www_authorize(realm, [uri_user])


The function verifies credentials according to 
		[RFC2617](http://www.ietf.org/rfc/rfc2617.txt). If 
		the credentials are verified successfully then the function will 
		succeed and mark the credentials as authorized (marked credentials can 
		be later used by some other functions). If the function was unable to 
		verify the credentials for some reason then it will fail and
		the script should call
		`www_challenge`
		which will challenge the user again.


Negative codes may be interpreted as follows:


- *-5 (generic error)* - some generic error
			occurred and no reply was sent out;
- *-4 (no credentials)* - credentials were not
			found in request;
- *-3 (stale nonce)* - stale nonce;


This function will, in fact, perform sanity checks over the received 
		credentials and then pass them along to the aaa server which will 
		verify the credentials and return whether they are valid or not.


Meaning of the parameter is as follows:


- *realm (string)* - Realm is a opaque string that 
			the user agent should present to the user so he can decide what 
			username and password to use. Usually this is domain of the host 
			the server is running on.
If an empty string "" is used then the server will 
			generate it from the request. In case of REGISTER requests To 
			header field domain will be used (because this header field 
			represents a user being registered), for all other messages From 
			header field domain will be used.
The string may contain pseudo variables.
- *uri_user (string, optional)* -
			value passed to the Radius server as value of the SIP-URI-User
			check item.  If this parameter is not present, the server will
			generate the SIP-URI-User check item value from the username part
			of the To header field URI.


This function can be used from REQUEST_ROUTE.


```c title="aaa_www_authorize usage"
		
...
if (!aaa_www_authorize("siphub.net"))
	www_challenge("siphub.net", "auth");
...
```


#### aaa_proxy_authorize(realm, [uri_user])


The function verifies credentials according to 
		[RFC2617](http://www.ietf.org/rfc/rfc2617.txt). If 
		the credentials are verified successfully then the function will 
		succeed and mark the credentials as authorized (marked credentials can 
		be later used by some other functions). If the function was unable to 
		verify the credentials for some reason then it will fail and the script 
		should call `proxy_challenge` which 
		will challenge the user again. For more about the negative return 
		codes, see the above function.


This function will, in fact, perform sanity checks over the received 
		credentials and then pass them along to the aaa server which will 
		verify the credentials and return whether they are valid or not.


Meaning of the parameters is as follows:


- *realm (string)* - Realm is a opaque string that
			the user agent should present to the user so he can decide what 
			username and password to use.  This is usually
			one of the domains the proxy is responsible for.
			If an empty string "" is used then the server will 
			generate realm from host part of From header field URI.
The string may contain pseudo variables.
- *uri_user (string, optional)* -
			value passed to the Radius server as value of the SIP-URI-User
			check item.  If this parameter is not present, the server will
			generate the SIP-URI-User check item value from the username part
			of the To header field URI.


This function can be used from REQUEST_ROUTE.


```c title="proxy_authorize usage"
		
...
if (!aaa_proxy_authorize(""))    # Realm and URI user will be autogenerated
	proxy_challenge("", "auth");
...
if (!aaa_proxy_authorize($pd, $pU))    # Realm and URI user are taken
	proxy_challenge($pd, "auth");  # from P-Preferred-Identity
                                       # header field
...
```


#### aaa_does_uri_exist([sip_uri])


Checks from Radius if the SIP URI stored in the "sip_uri" parameter
		(or user@host part of the Request-URI if "sip_uri" is not given)
		belongs to a local user. Can be used to decide if 404 or 480 should
		be returned after lookup has failed.   If yes, loads AVP
		based on SIP-AVP reply items returned from Radius.  Each
		SIP-AVP reply item must have a string value of form:


- *value = SIP_AVP_NAME SIP_AVP_VALUE*
- *SIP_AVP_NAME = STRING_NAME | '#'ID_NUMBER*
- *SIP_AVP_VALUE = ':'STRING_VALUE | '#'NUMBER_VALUE*


Returns 1 if Radius returns Access-Accept, -1 if Radius
		returns Access-Reject, and -2 in case of internal
		error.


This function can be used from REQUEST_ROUTE.


```c title="aaa_does_uri_exist usage"
...
if (aaa_does_uri_exist()) {
	...
};
...
```


#### aaa_does_uri_user_exist([sip_uri])


Similar to aaa_does_uri_exist, but check is done
		based only on Request-URI user part or user stored in "sip_uri".
		The user should thus be unique among all users, such as an
		E.164 number.


This function can be used from REQUEST_ROUTE.


```c title="aaa_does_uri_user_exist usage"
...
if (aaa_does_uri_user_exist()) {
	...
};
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
