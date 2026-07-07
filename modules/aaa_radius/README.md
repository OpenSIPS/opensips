---
title: "AAA RADIUS MODULE"
description: "This module provides a Radius implementation for the AAA API from the core."
---

## Admin Guide


### Overview


This module provides a Radius implementation for the AAA API from the core.


It also provides two functions to be used from the script for generating custom Radius acct and auth requests.
		Detection and handling of SIP-AVPs from Radius replies is automatically and transparently done by the module.


Since version 2.2, aaa_radius module supports asynchronous operations. But in order to use them, one must apply
		the patch contained by the modules/aaa_radius folder, called *radius_async_support.patch*.In
		order to do this, you must have freeradius-client sources. In order to do this you can follow
		the tutorial in the end of the documentation.


Any module that wishes to use it has to do the following:


- *include aaa.h*
- *make a bind call with a proper radius specific url*


### Dependencies


#### OpenSIPS Modules


None.


#### External Libraries or Applications


One of the following libraries must be installed before running
		OpenSIPS with this module loaded:


- *radiusclient-ng* 0.5.0 or higher
				See [http://developer.berlios.de/projects/radiusclient-ng/](http://developer.berlios.de/projects/radiusclient-ng/).
- *freeradius-client*
				See [http://freeradius.org/](http://freeradius.org/).


One can force the radius library that is usedby setting RADIUSCLIENT env, before compiling the module, to one of the following values:


- *RADCLI  **** libradcli-dev library shall be used;
- *FREERADIUS  **** libfreeradius-client-dev library shall be used;
- *RADIUSCLIENT  **** libradiusclient-ng library shall be used;


IMPORTANT: If the selected library is not installed the module won't compile.
				NOTE: If RADIUSCLIENT env not set, the module will try to find one of the three radius libraries in
				the following order: radcli, freeradius, radiusclient-ng. That is if radcli library is installed
				it shall be used, else freeradius shall be looked for and so on.


### Exported Parameters


#### sets (string)


Sets of Radius AVPs to be used when building custom RADIUS requests (set of input RADIUS AVPs)
			or when fetching data from the RADIUS reply (set of output RADIUS AVPs).


The format for a set definition is the following:


- " set_name = ( attribute_name1 = var1 [, attribute_name2 = var2 ]* ) "


The left-hand side of the assignment must be an attribute name known by the RADIUS dictionary.


The right-hand side of the assignment must be a script pseudo variable or
			a script AVP. For more information about them see [CookBooks - Scripting Variables](https://opensips.org/Resources/DocsCoreVar15).


```opensips title="Set sets parameter"
...
modparam("aaa_radius","sets","set4  =  (  Sip-User-ID  =   $avp(10)
			,   Sip-From-Tag=$si,Sip-To-Tag=$tt      )      ")
...

...
modparam("aaa_radius","sets","set1 = (User-Name=$var(usr), Sip-Group = $var(grp),
			Service-Type = $var(type)) ")
...

...
modparam("aaa_radius","sets","set2 = (Sip-Group = $var(sipgrup)) ")
...
```


#### radius_config (string)


Radiusclient configuration file.


This parameter is optional. It must be set only if the radius_send_acct
			and radius_send_auth functions are used.


```opensips title="Set radius_config parameter"
...
modparam("aaa_radius", "radius_config", "/etc/radiusclient-ng/radiusclient.conf")
...
```


#### syslog_name (string)


Enable logging of the client library to syslog, using the given log name.


This parameter is optional. Radius client libraries will try to use syslog
		to report errors (such as problems with dictionaries) with the given ident
		string .If this parameter is set, then these errors are visible in syslog.
		Otherwise errors are hidden.


By default this parameter is not set (no logging).


```opensips title="Set syslog_name parameter"
...
modparam("aaa_radius", "syslog_name", "aaa-radius")
...
```


#### fetch_all_values (integer)


For the output sets, this parameter controls if all the values (for the same
		RADIUS AVP) should be returned (otherwise only the first value will be
		returned). When enabling this options, be sure that the variable you use
		to get the RADIUS output can store multiple values (like the AVP variables).


By default this parameter is disabled (set to 0) for backward compatibility
		reasons.


```opensips title="Set fetch_all_values parameter"
...
modparam("aaa_radius", "fetch_all_values", 1)
...
```


### Exported Functions


#### radius_send_auth(input_set_name, output_set_name)


This function can be used from the script to make custom
			radius authentication request. The function takes two parameters.


Parameters:


- *input_set_name* (string) - the name of the
				set that contains the list of attributes and pvars that will
				form the authentication request (see the "sets"
				module parameter).
- *output_set_name* (string) - the name of the
				set that contains the list of attributes and pvars that will be
				extracted form the authentication reply (see the "sets"
				module parameter).


The sets must be defined using the "sets" exported
			parameter.


The function return TRUE (retcode 1) if authentication was
			successful, FALSE (retcode -1) if an error (any kind of error)
			occurred during authentication processes or FALSE (retcode -2) if
			authentication was rejected or denied by RADIUS server.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, ONREPLY_ROUTE, BRANCH_ROUTE, ERROR_ROUTE and LOCAL_ROUTE.


```opensips title="radius_send_auth usage"
...
radius_send_auth("set1","set2");
switch ($rc) {
	case 1:
		xlog("authentication ok \n");
		break;
	case -1:
		xlog("error during authentication\n");
		break;
	case -2:
		xlog("authentication denied \n");
		break;
}
...

		
```


#### radius_send_acct(input_set_name)


This function can be used from the script to make custom
			radius authentication request. The function takes only one string parameter
			that represents the name of the set that contains the list of attributes
			and pvars that will form the accounting request.


Only one set is needed as a parameter because no AVPs can be extracted
			from the accounting replies.


The set must be defined using the "sets" exported parameter.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, ONREPLY_ROUTE, BRANCH_ROUTE, ERROR_ROUTE and LOCAL_ROUTE.


```opensips title="radius_send_acct usage"
...
radius_send_acct("set1");
...

		
```


### Exported Asynchronous Functions


#### radius_send_auth(input_set_name, output_set_name)


This function can be used from the script to make custom
			radius authentication request.


Parameters:


- *input_set_name* (string) - the name of the
				set that contains the list of attributes and pvars that will
				form the authentication request (see the "sets"
				module parameter).
- *output_set_name* (string) - the name of the
				set that contains the list of attributes and pvars that will be
				extracted form the authentication reply (see the "sets"
				module parameter).


The sets must be defined using the "sets" exported
			parameter.


The function return TRUE (retcode 1) if authentication was
			successful, FALSE (retcode -1) if an error (any kind of error)
			occurred during authentication processes or FALSE (retcode -2) if
			authentication was rejected or denied by RADIUS server.


```opensips title="radius_send_auth usage"
...
{
async( radius_send_auth("set1","set2"), resume);
}

route[resume] {
switch ($rc) {
	case 1:
		xlog("authentication ok \n");
		break;
	case -1:
		xlog("error during authentication\n");
		break;
	case -2:
		xlog("authentication denied \n");
		break;
}
...

		
```


#### radius_send_acct(input_set_name)


This function can be used from the script to make custom
			radius authentication request. The function takes only one string parameter
			that represents the name of the set that contains the list of attributes
			and pvars that will form the accounting request.


Only one set is needed as a parameter because no AVPs can be extracted
			from the accounting replies.


The set must be defined using the "sets" exported parameter.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, ONREPLY_ROUTE, BRANCH_ROUTE, ERROR_ROUTE and LOCAL_ROUTE.


```opensips title="radius_send_acct usage"
...
{
async( radius_send_acct("set1","set2"), resume);
}

route[resume] {
xlog(" accounting finished\n");
}

...

		
```


## Using radius async


### Downloading radius-client library


You can download the last freeRADIUS Client Library sources from
			[here](ftp://ftp.freeradius.org/pub/freeradius/freeradius-client-1.1.7.tar.gz).
			So the first step would be to download these sources in any folder you want.
			In this exaple we will consider this folder generically called
			*freeRADIUS-client*. After you download the sources,
			extract the contents of the archive.


```c title="downloading the library"
........
mkdir freeRADIUS-client; cd freeRADIUS-client
wget ftp://ftp.freeradius.org/pub/freeradius/freeradius-client-1.1.7.tar.gz
tar -xzvf freeradius-client-1.1.7.tar.gz
........
		
```


### Applying the patch


After you extracted the contents of the archive, you can apply the patch
			called *radius_async_support.patch* that you can find in
			*modules/aaa_radius/* inside OpenSIPS sources folder.
			You must apply this patch to the freeRADIUS-client library and after this
			you can install the radius library as usual using configure and make
			commands and free to use the library.


```c title="How to apply the patch"
........
cd freeRADIUS-client/freeradius-client-1.1.7.tar.gz
patch -p1 < /path/to/opensips/modules/aaa_radius/radius_async_support.patch
./configure --any-options-you-want
make
sudo make install
........
		
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
