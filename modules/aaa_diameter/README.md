---
title: "AAA_DIAMETER MODULE"
description: "This module provides an RFC 6733 Diameter peer implementation, being able to act as either **Diameter client** or **server**, or **both**."
---

## Admin Guide


### Overview


This module provides an RFC 6733 Diameter peer implementation, being
		able to act as either **Diameter client** or **server**, or **both**.


Any module that wishes to use it has to do the following:


- *include aaa.h*
- *make a bind call with a proper Diameter-specific URL, e.g. "diameter:freeDiameter-client.conf"*


### Diameter Client


The module implements the core AAA OpenSIPS interface, thus offering
		an alternative client implementation to the
		[aaa_radius](../aaa_radius) module which can be useful,
		for example, when performing billing and accounting for the live SIP calls.


In addition to the RADIUS client's auth and accounting features, the
		Diameter client includes support for sending *arbitrary*
		Diameter requests, further opening up the scope of applications which
		can be achieved through OpenSIPS scripting.  Such Diameter requests can
		be sent using the [dm send request](#func_dm_send_request) function.


### Diameter Server


Starting with OpenSIPS **3.5**, the Diameter
		module includes *server-side* support as well.


First, the [event_route](../event_route) module must be loaded in
		order to be able to process [dm request](#event_e_dm_request) events in
		the OpenSIPS configuration file.  These events will contain all necessary
		information on the incoming Diameter request.


Finally, once the request information is processed and the answer AVPs
		are prepared, script writers should use the [dm send answer](#func_dm_send_answer)
		function in order to reply with a Diameter answer message.


*Recommendation:* When possible, always load the
		**dict_sip.fdx** freeDiameter extension module
		inside your *freeDiameter.conf* configuration file,
		as it contains hundreds of well-known AVP definitions which may be good
		to have when inter-operating with other Diameter peer implementations.


### Dependencies


#### OpenSIPS Modules


None.


#### External Libraries or Applications


All Diameter message building and parsing, as well as the peer state
		machine and Diameter-related network communication are all powered by
		[the freeDiameter project](http://www.freediameter.net/trac/)
		and C libraries, dynamically linking with the "aaa_diameter" module.


The following libraries must be installed before running
		OpenSIPS with this module loaded:


- *libfdcore* v1.2.1 or higher
- *libfdproto* v1.2.1 or higher


### Exported Parameters


#### fd_log_level (integer)


This parameter measures the *quietness* of the logging
		done by the freeDiameter library. Possible values:


- 0 (ANNOYING)
- 1 (DEBUG)
- 3 (NOTICE, default)
- 5 (ERROR)
- 6 (FATAL)


NOTE: since freeDiameter logs to standard output, you must also enable
		the new core parameter, **log_stdout**,
		before getting any logs from the library.


```c title="Setting the fd_log_level parameter"
modparam("aaa_diameter", "fd_log_level", 0)
```


#### realm (string)


The unique realm to be used by all participating Diameter peers.


Default value is *"diameter.test"*.


```c title="Setting the realm parameter"
modparam("aaa_diameter", "realm", "opensips.org")
```


#### peer_identity (string)


The identity (realm subdomain) of the Diameter server peer, to which
		the OpenSIPS Diameter client peer will connect.


Default value is *"server"*
				(i.e. "server.diameter.test").


```c title="Setting the peer_identity parameter"
modparam("aaa_diameter", "peer_identity", "server")
```


#### aaa_url (string)


URL of the diameter client: the configuration file, with an optional
			extra-avps-file, where the Diameter client is configured.


By default, the connection is not created.


```c title="Setting the aaa_url parameter"
modparam("aaa_diameter", "aaa_url", "diameter:freeDiameter-client.conf")
```


```c title="Setting the aaa_url parameter"
modparam("aaa_diameter", "aaa_url", "diameter:freeDiameter-client.conf;extra-avps-file:dictionary.opensips")
```


#### answer_timeout (integer)


Time, in milliseconds, after which a [dm send request](#func_dm_send_request)
		function call with no received reply will time out and return a
		**-2** code.


Default value is *2000* ms.


```c title="Setting the answer_timeout parameter"
modparam("aaa_diameter", "answer_timeout", 5000)
```


#### max_json_log_size (integer)


When an error log is printed due to malformed JSON, this parameter indicates
			how many characters from the JSON should be printed at console. A higher value
			might overcrowd the logs, but can be useful for troubleshooting.


Default value is *512* characters.


```c title="Setting the max_json_log_size parameter"
modparam("aaa_diameter", "max_json_log_size", 4096)
```


### Exported Functions


#### dm_send_request(app_id, cmd_code, avps_json, [rpl_avps_pv])


Perform a blocking Diameter request over to the interconnected peer
		and return the Result-Code AVP value from the reply.


*Parameters*


- *app_id* (integer) - ID of the application.
				A custom application must be defined in the dictionary.opensips
				Diameter configuration file before it can be recognized.
- *cmd_code* (integer) - ID of the command.  A
				custom command code, name and AVP requirements must be defined
				in the dictionary.opensips Diameter configuration file beforehand.
				body of the HTTP response.
- *avps_json* (string) - A JSON Array containing
				the AVPs to include in the message.
- *rpl_avps_pv* (var, optional) - output variable which will
				hold all AVP names from the Diameter Answer along with their values, packed
				as a JSON Array string.  The "json" module and its *$json*
				variable could be used to iterate this array.


*Return Codes*


- **1** - Success
- **-1** - Internal Error
- **-2** - Request timeout
			(the [answer timeout](#param_answer_timeout) was exceeded
			before an Answer could be processed)


This function can be used from any route.


```c title="dictionary.opensips extended syntax"
# Example of defining custom Diameter AVPs, Application IDs,
# Requests and Replies in the "dictionary.opensips" file

ATTRIBUTE out_gw            232 string
ATTRIBUTE trunk_id          233 string

ATTRIBUTE rated_duration    234 integer
ATTRIBUTE call_cost         235 integer

ATTRIBUTE Exponent          429 integer32
ATTRIBUTE Value-Digits      447 integer64

ATTRIBUTE Cost-Unit 424 grouped
{
	Value-Digits | REQUIRED | 1
	Exponent | OPTIONAL | 1
}

ATTRIBUTE Currency-Code     425 unsigned32

ATTRIBUTE Unit-Value  445 grouped
{
	Value-Digits | REQUIRED | 1
	Exponent | OPTIONAL | 1
}

ATTRIBUTE Cost-Information  423 grouped
{
	Unit-Value | REQUIRED | 1
	Currency-Code | REQUIRED | 1
	Cost-Unit | OPTIONAL | 1
}

APPLICATION 42 My Diameter Application

REQUEST 92001 My-Custom-Request
{
	Origin-Host | REQUIRED | 1
	Origin-Realm | REQUIRED | 1
	Destination-Realm | REQUIRED | 1
	Sip-From-Tag | REQUIRED | 1
	Sip-To-Tag | REQUIRED | 1
	Sip-Call-Duration | REQUIRED | 1
	Sip-Call-Setuptime | REQUIRED | 1
	Sip-Call-Created | REQUIRED | 1
	Sip-Call-MSDuration | REQUIRED | 1
	out_gw | REQUIRED | 1
	call_cost | REQUIRED | 1
	Cost-Information | OPTIONAL | 1
}

ANSWER 92001 My-Custom-Answer
{
	Origin-Host | REQUIRED | 1
	Origin-Realm | REQUIRED | 1
	Destination-Realm | REQUIRED | 1
	Result-Code | REQUIRED | 1
}
```


```c title="dm_send_request usage"
# Building an sending an My-Custom-Request (92001) for the
# My Diameter Application (42)
$var(payload) = "[
	{ \"Origin-Host\": \"client.diameter.test\" },
	{ \"Origin-Realm\": \"diameter.test\" },
	{ \"Destination-Realm\": \"diameter.test\" },
	{ \"Sip-From-Tag\": \"dc93-4fba-91db\" },
	{ \"Sip-To-Tag\": \"ae12-47d6-816a\" },
	{ \"Session-Id\": \"a59c-dff0d9efd167\" },
	{ \"Sip-Call-Duration\": 6 },
	{ \"Sip-Call-Setuptime\": 1 },
	{ \"Sip-Call-Created\": 1652372541 },
	{ \"Sip-Call-MSDuration\": 5850 },
	{ \"out_gw\": \"GW-774\" },
	{ \"call_cost\": 10 },
	{ \"Cost-Information\": [
		{\"Unit-Value\": [{\"Value-Digits\": 1000}]},
		{\"Currency-Code\": 35}
		]}
]";

$var(rc) = dm_send_request(42, 92001, $var(payload), $var(rpl_avps));
xlog("rc: $var(rc), AVPs: $var(rpl_avps)\n");
$json(avps) := $var(rpl_avps);
```


#### dm_send_answer(avps_json, [is_error])


Send back a Diameter answer message to the interconnected peer in a
		*non-blocking* fashion, in response to its request.


The following fields will be automatically copied over from the Diameter
		request when building the answer message:


- Application ID
- Command Code
- Session-Id AVP, if any
- Transaction-Id AVP, if any (only applies when
					Session-Id is not present)


*Parameters*


- *avps_json* (string) - A JSON Array containing
				the AVPs to include in the answer message (example below).
- *is_error* (boolean, default: *false*)
				- Set to *true*
				in order to set the 'E' (error) bit in the answer message.


*Return Codes*


- **1** - Success
- **-1** - Internal Error


This function can only be used from an *EVENT_ROUTE*.


```c title="dm_send_answer() usage"
event_route [E_DM_REQUEST] {
  xlog("Req: $param(sess_id) / $param(app_id) / $param(cmd_code)\n");
  xlog("AVPs: $param(avps_json)\n");

  $json(avps) := $param(avps_json);

  /* ... process the data (AVPs) ... */

  /* ... and reply back with more AVPs! */
  $var(ans_avps) = "[
          { \"Vendor-Specific-Application-Id\": [{
                  \"Vendor-Id\": 0
                  }] },

          { \"Result-Code\": 2001 },
          { \"Auth-Session-State\": 0 },
          { \"Origin-Host\": \"opensips.diameter.test\" },
          { \"Origin-Realm\": \"diameter.test\" }
  ]";

  if (!dm_send_answer($var(ans_avps)))
    xlog("ERROR - failed to send Diameter answer\n");
}
```


### Exported Asynchronous Functions


#### dm_send_request(app_id, cmd_code, avps_json, [rpl_avps_pv])


Similar to [dm send request](#func_dm_send_request) but performs an asynchronous Diameter request.


Uses the same parameters and return codes as
            [dm send request](#func_dm_send_request).


```c title="dm_send_request asynchronous usage"
# Building an sending an My-Custom-Request (92001) for the
# My Diameter Application (42)
$var(payload) = "[
	{ \"Origin-Host\": \"client.diameter.test\" },
	{ \"Origin-Realm\": \"diameter.test\" },
	{ \"Destination-Realm\": \"diameter.test\" },
	{ \"Sip-From-Tag\": \"dc93-4fba-91db\" },
	{ \"Sip-To-Tag\": \"ae12-47d6-816a\" },
	{ \"Session-Id\": \"a59c-dff0d9efd167\" },
	{ \"Sip-Call-Duration\": 6 },
	{ \"Sip-Call-Setuptime\": 1 },
	{ \"Sip-Call-Created\": 1652372541 },
	{ \"Sip-Call-MSDuration\": 5850 },
	{ \"out_gw\": \"GW-774\" },
	{ \"call_cost\": 10 },
	{ \"Cost-Information\": [
		{\"Unit-Value\": [{\"Value-Digits\": 1000}]},
		{\"Currency-Code\": 35}
		]}
]";

async(dm_send_request(42, 92001, $var(payload), $var(rpl_avps), dm_reply);

route[dm_reply] {
	xlog("rc: $retcode, AVPs: $var(rpl_avps)\n");
	$json(avps) := $var(rpl_avps);
}
```


### Exported Events


#### E_DM_REQUEST


This event is raised whenever the *aaa_diameter*
		module is loaded and OpenSIPS receives a Diameter request on the configured
		Diameter listening interface.


Parameters:


- *app_id (integer)* - the Diameter Application Identifier
- *cmd_code (integer)* - the Diameter Command Code
- *sess_id (string)* - the value of either the
					*Session-Id* AVP, *Transaction-Id* AVP
						or a *NULL* value if neither of these
						transaction-identifying AVPs is present in the Diameter request.
- *avps_json (string)* - a JSON Array containing the
					AVPs of the request.  Use the [json](../json) module's
					**$json** variable
					to easily parse and work with it.


Note that this event is currently designed to be mainly consumed by an *event_route*,
		since that is the only way to gain access to the [dm send answer](#func_dm_send_answer)
		function in order to build custom answer messages.  On the other hand,
		if the application does not mind the answer being always a 3001 (DIAMETER_COMMAND_UNSUPPORTED) error,
		this event can be successfully consumed through any other EVI-compatible delivery channel ☺️
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
