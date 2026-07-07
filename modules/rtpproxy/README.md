---
title: "rtpproxy Module"
description: "This module is used by OpenSIPS to communicate with RTPProxy, a media relay proxy used to make the communication between user agents behind NAT possible."
---

## Admin Guide


### Overview


This module is used by OpenSIPS to communicate with RTPProxy, a media
		relay proxy used to make the communication between user agents behind
		NAT possible.


This module is also used along with RTPProxy to record media streams
		between user agents or to play media to either UAc or UAs.


### Multiple RTPProxy usage


Currently, the rtpproxy module can support multiple rtpproxies for
		balancing/distribution and control/selection purposes.


The module allows the definition of several sets of rtpproxies - 
		load-balancing will be performed over a set and the user has the
		ability to choose what set should be used. The set is selected via
		its id - the id being defined along with the set. Refer to the 
		"rtpproxy_sock" module parameter definition for syntax
		description.


The balancing inside a set is done automatically by the module based on
		the weight of each rtpproxy from the set. Note that if rtpproxy has weight
		0, it will be used only when no other rtpproxies  (with a different
		weight value than 0) respond. Default weight is 1.


Starting with OpenSIPS 1.11, the set_rtp_proxy_set() function has
		been removed. The set is now specified for each function. If
		absend, the default set 0 is used. Also, engage_rtp_proxy(),
		unforce_rtp_proxy() and start_recording() functions have been deprecated
		and replaced by rtpproxy_engage(), rtpproxy_unforce() and
		rtpproxy_start_recording() respectively.


IMPORTANT: if you use multiple sets, make sure you use the same set for
		both rtpproxy_offer()/rtpproxy_answer() and rtpproxy_unforce()!!


### RTPProxy timeout notifications


Nathelper module can also receive timeout notifications from multiple
		rtpproxies. RTPProxy can be configured to send notifications when
		a session doesn't receive any media for a configurable interval of
		time. The rtpproxy modules has implemented a listener for such
		notifications and when received it terminates the dialog at SIP
		level (send BYE to both ends), with the help of dialog module.


In our tests with RTPProxy we observed some limitations and also
		provide a patch for it against git commit
		"600c80493793bafd2d69427bc22fcb43faad98c5".
		It contains an addition and implements separate timeout parameters
		for the phases of session establishment and ongoing sessions.
		In the official code a single timeout parameter controls
		both session establishment and rtp timeout and the timeout
		notification is also sent in the call establishment phase.
		This is a problem since we want to detect rtp timeout fast, but also
		allow a longer period for call establishment.


Note that RTPProxy version
		[v2.0.0](http://www.rtpproxy.org/post/v2release/)
		has integrated this feature upstream, therefore this patch is no
		longer needed.


Starting with commit
		[21e5977](https://github.com/sippy/rtpproxy/commit/21e59778973c8aa85e26a7ef7a21a02695673656), the timeout notification sockets are handled a bit
		different by RTPProxy. This makes later RTPProxy releases
		incompatible with OpenSIPS.


To enable timeout notification there are several steps that you must follow:
		Start OpenSIPS timeout detection by setting the "rtpp_notify_socket"
			module parameter in your configuration script. This is the socket where further
			notification will be received from rtpproxies. This socket must be a TCP or 
			UNIX socket. Also, for all the calls that require notification, the
			rtpproxy_engage(), rtpproxy_offer() and rtpproxy_answer() functions must
			be called with the "n" flag.
		Configure RTPProxy to use timeout notification by adding
			the following command line parameters:
			
				
					" -n timeout_socket" - specifies
						where the notifications will be sent. This socket
						must be the same as "rtpp_notify_socket"
						OpenSIPS module parameter. This parameter is mandatory.
				
				
					" -T ttl" - limits the rtp session
						timeout to "ttl". This parameter
						is optional and the default value is 60 seconds.
				
				
					" -W ttl" - limits the session
						establishment timeout to "ttl".
						This parameter is optional and the default value 
						is 60 seconds.
			All of the previous parameters can be used with the offical
				RTPProxy release, except for the last one. It has been
				added, together with other modifications to RTPProxy in order
				to work properly. The patch is located in the
				*patches* directory in the module.
			To get the patched version from git you must follow theese steps:
				
					
						Get the latest source code: "git clone git://sippy.git.sourceforge.net/gitroot/sippy/rtpproxy"
					
					
						Make a branch from the commit: "git checkout
								-b branch_name 600c80493793bafd2d69427bc22fcb43faad98c5"
					
					
						Patch RTPProxy: "patch <
								path_to_rtpproxy_patch"
			The patched version can also be found at:
				http://opensips.org/pub/rtpproxy/


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *a database* module - only if you want
				to load use a database table from where to load the rtp proxies
				sets.
- *dialog* module - if using the rtpproxy_engage
				functions or RTPProxy timeout notifications.


#### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### rtpproxy_sock (string)


Definition of socket(s) used to connect to (a set) RTPProxy. It may 
		specify a UNIX socket or an IPv4/IPv6 UDP socket.


*Default value is "NONE" (disabled).*


```opensips title="Set rtpproxy_sock parameter"
...
# single rtproxy with specific weight
modparam("rtpproxy", "rtpproxy_sock", "udp:localhost:12221=2")
# multiple rtproxies for LB
modparam("rtpproxy", "rtpproxy_sock",
	"udp:localhost:12221 udp:localhost:12222")
# multiple sets of multiple rtproxies
modparam("rtpproxy", "rtpproxy_sock",
	"1 == udp:localhost:12221 udp:localhost:12222")
modparam("rtpproxy", "rtpproxy_sock",
	"2 == udp:localhost:12225")
...
```


#### rtpproxy_disable_tout (integer)


Once RTPProxy was found unreachable and marked as disable, rtpproxy
		will not attempt to establish communication to RTPProxy for 
		rtpproxy_disable_tout seconds.


*Default value is "60".*


```opensips title="Set rtpproxy_disable_tout parameter"
...
modparam("rtpproxy", "rtpproxy_disable_tout", 20)
...
```


#### rtpproxy_timeout (string)


Timeout value in waiting for reply from RTPProxy.


*Default value is "1".*


```opensips title="Set rtpproxy_timeout parameter to 200ms"
...
modparam("rtpproxy", "rtpproxy_timeout", "0.2")
...
```


#### rtpproxy_autobridge (integer)


Enable auto-bridging feature. Does not properly function when doing serial/parallel forking!


*Default value is "0".*


```opensips title="Enable auto-bridging feature"
...
modparam("rtpproxy", "rtpproxy_autobridge", 1)
...
```


#### rtpproxy_tout (integer)


Obsolete. see rtpproxy_timeout.


#### rtpproxy_retr (integer)


How many times rtpproxy should retry to send and receive after
		timeout was generated.


*Default value is "5".*


```opensips title="Set rtpproxy_retr parameter"
...
modparam("rtpproxy", "rtpproxy_retr", 2)
...
```


#### nortpproxy_str (string)


The parameter sets the SDP attribute used by rtpproxy to mark
		the packet SDP informations have already been mangled.


If empty string, no marker will be added or checked.


> [!NOTE]
> The string must be a complete SDP line, including the EOH (\r\n).


*Default value is "a=nortpproxy:yes\r\n".*


```opensips title="Set nortpproxy_str parameter"
...
modparam("rtpproxy", "nortpproxy_str", "a=sdpmangled:yes\r\n")
...
```


#### db_url (string)


The database url. This parameter should be set if you want to 
			use a database table from where to load or reload definitions of
			socket(s) used to connect to (a set) RTPProxy. The record from
			the database table will be read at start up (added to the ones
			defined with the rtpproxy_sock module parameter) and when the MI command
			rtpproxy_reload is issued(the definitions will be replaced with the
			ones from the database table).


*Default value is "NULL".*


```opensips title="Set db_url parameter"
...
modparam("rtpproxy", "db_url", 
		"mysql://opensips:opensipsrw@192.168.2.132/opensips")
...
```


#### db_table (string)


The name of the database table containing definitions of
			socket(s) used to connect to (a set) RTPProxy.


*Default value is "rtpproxy_sockets".*


```opensips title="Set db_table parameter"
...
modparam("rtpproxy", "db_table", "nh_sockets") 
...
```


#### rtpp_socket_col (string)


The name rtpp socket column in the database table.


*Default value is "rtpproxy_sock".*


```opensips title="Set rtpp_socket_col parameter"
...
modparam("rtpproxy", "rtpp_socket_col", "rtpp_socket") 
...
```


#### set_id_col (string)


The name set id column in the database table.


*Default value is "set_id".*


```opensips title="Set set_id parameter"
...
modparam("rtpproxy", "set_id_col", "rtpp_set_id") 
...
```


#### rtpp_notify_socket (string)


The socket used by OpenSIPS to receive timeout notifications.


*Default value is "NULL".*


```opensips title="Set rtpp_notify_socket parameter"
...
modparam("rtpproxy", "rtpp_notify_socket", "tcp:10.10.10.10:9999")
...
```


### Exported Functions


#### engage_rtp_proxy([[flags][, [ip_address][, [set_id][, sock_pvar]]]]) - deprecated, rtpproxy_engage([[flags][, [ip_address][, [set_id][, sock_pvar]]]])


Rewrites SDP body to ensure that media is passed through
		an RTP proxy. It uses the dialog module facilities to keep track
		when the rtpproxy session must be updated. Function must only be
		called for the initial INVITE
		and internally takes care of rewriting the body of 200 OKs and ACKs.
		Note that when used in bridge mode, this function might advertise wrong
		interfaces in SDP (due to the fact that OpenSIPS is not aware of the RTPProxy
		configuration), so you might face an undefined behavior.


Meaning of the parameters is as follows:


- *flags(optional)* - flags to turn on some features.

  - *a* - flags that UA from which message is
				received doesn't support symmetric RTP.
  - *l* - force "lookup", that is,
				only rewrite SDP when corresponding session is already exists 
				in the RTP proxy. By default is on when the session is to be
				completed (reply in non-swap or ACK in swap mode).
  - *i/e* - when RTPProxy is used in bridge mode,
				these flags are used to indicate the direction of the media flow
				for the current request/reply. 'i' refers to the LAN (internal
				network) and corresponds to the first interface of RTPProxy (as
				specified by the -l parameter). 'e' refers to the WAN (external
				network) and corresponds to the second interface of RTPProxy.
				These flags should always be used together. For example, an
				INVITE (offer) that comes from the Internet (WAN) to goes to a
				local media server (LAN) should use the 'ei' flags. The answer
				should use the 'ie' flags. Depending on the scenario, the 'ii'
				and 'ee' combination are also supported. Only makes sense when
				RTPProxy is running in the bridge mode.
*NOTE:* when using RTPProxy in bridge mode,
				all sessions are considered asymmetric (as oposed to symmetric
				if used in normal mode). If you have symmetric clients (this
				is the most common scenario), you'll have to force the
				*s*!
  - *f* - instructs rtpproxy to ignore marks 
				inserted by another rtpproxy in transit to indicate that the 
				session is already goes through another proxy. Allows creating 
				chain of proxies.
  - *r* - flags that IP address in SDP should 
				be trusted. Without this flag, rtpproxy ignores address in 
				the SDP and uses source address of the SIP message as media 
				address which is passed to the RTP proxy.
  - *o* - flags that IP from the origin 
				description (o=) should be also changed.
  - *c* - flags to change the session-level 
				SDP connection (c=) IP if media-description also includes 
				connection information.
  - *s/w* - flags that for the UA from which 
				message is received, support symmetric RTP must be forced.
  - *n* - flags that enables the notification
				timeout for the session.
  - *zNN* - requests the RTPproxy to perform
				re-packetization of RTP traffic coming from the UA which
				has sent the current message to increase or decrease payload
				size per each RTP packet forwarded if possible.  The NN is the
				target payload size in ms, for the most codecs its value should
				be in 10ms increments, however for some codecs the increment
				could differ (e.g. 30ms for GSM or 20ms for G.723).  The
				RTPproxy would select the closest value supported by the codec.
				This feature could be used for significantly reducing bandwith
				overhead for low bitrate codecs, for example with G.729 going
				from 10ms to 100ms saves two thirds of the network bandwith.
- *ip_address(optional)* - new SDP IP address.
- *set_id(optional)* - the set used for this call.
- *sock_pvar(optional)* - pvar used to store the RTPProxy
		socket chosen for this call. Note that the variable will only be populated in the
		initial request.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="rtpproxy_engage usage"
...
if (is_method("INVITE") && has_totag()) {
	if ($var(setid) != 0) {
		rtpproxy_engage(,,"$var(setid)", "$var(proxy)");
		xlog("SCRIPT: RTPProxy server used is $var(proxy)\n");
	} else {
		rtpproxy_engage();
		xlog("SCRIPT: using default RTPProxy set\n");
	}
}
...
		
```


#### rtpproxy_offer([[flags][, [ip_address][, [set_id][, sock_pvar]]])


Rewrites SDP body to ensure that media is passed through
                an RTP proxy. To be invoked
		on INVITE for the cases the SDPs are in INVITE and 200 OK and on 200 OK
		when SDPs are in 200 OK and ACK.


See rtpproxy_engage() function description above for the meaning of the
		parameters.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE,
		FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="rtpproxy_offer usage"
route {
...
    if (is_method("INVITE")) {
        if (has_body("application/sdp")) {
            if (rtpproxy_offer())
                t_on_reply("1");
        } else {
            t_on_reply("2");
        }
    }
    if (is_method("ACK") && has_body("application/sdp"))
        rtpproxy_answer();
...
}

onreply_route[1]
{
...
    if (has_body("application/sdp"))
        rtpproxy_answer();
...
}

onreply_route[2]
{
...
    if (has_body("application/sdp"))
        rtpproxy_offer();
...
}
```


#### rtpproxy_answer([[flags][, [ip_address][, [set_id][, sock_pvar]]]])


Rewrites SDP body to ensure that media is passed through
		an RTP proxy. To be invoked
		on 200 OK for the cases the SDPs are in INVITE and 200 OK and on ACK
		when SDPs are in 200 OK and ACK.


See rtpproxy_engage() function description above for the meaning of the
		parameters.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE,
		FAILURE_ROUTE, BRANCH_ROUTE.


See rtpproxy_offer() function example above for example.


#### unforce_rtp_proxy([[set_id][, sock_pvar]]) - deprecated, rtpproxy_unforce([[set_id][, sock_pvar]])


Tears down the RTPProxy session for the current call.


Meaning of the parameters is as follows:


- *set_id(optional)* - the set used for this call.
- *sock_pvar(optional)* - pvar used to store the RTPProxy
			socket chosen for this call.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="rtpproxy_unforce usage"
...
rtpproxy_unforce();
...
```


#### rtpproxy_stream2uac(prompt_name, count[, [set_id][, sock_pvar]]), rtpproxy_stream2uas(prompt_name, count[, [set_id][, sock_pvar]])


Instruct the RTPproxy to stream prompt/announcement pre-encoded with
	    the makeann command from the RTPproxy distribution. The uac/uas
	    suffix selects who will hear the announcement relatively to the current
	    transaction - UAC or UAS. For example invoking the
	    `rtpproxy_stream2uac` in the request processing
	    block on ACK transaction will play the prompt to the UA that has
	    generated original INVITE and ACK while
	    `rtpproxy_stop_stream2uas` on 183 in reply
	    processing block will play the prompt to the UA that has generated 183.


Apart from generating announcements, another possible application
	    of this function is implementing music on hold (MOH) functionality.
	    When count is -1, the streaming will be in loop indefinitely until
	    the appropriate `rtpproxy_stop_stream2xxx` is issued.


In order to work correctly, functions require that the session in the
	    RTPproxy already exists. Also those functions don't alted SDP, so that
	    they are not substitute for calling `rtpproxy_offer`
	    or `rtpproxy_answer`.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE.


Meaning of the parameters is as follows:


- *prompt_name* - name of the prompt to
		    stream.  Should be either absolute pathname or pathname
		    relative to the directory where RTPproxy runs.
- *count* - number of times the prompt
		    should be repeated.  The value of -1 means that it will
		    be streaming in loop indefinitely, until appropriate
		    `rtpproxy_stop_stream2xxx` is issued.
- *set_id(optional)* - the set used for this call.
- *sock_pvar(optional)* - pvar used to store the RTPProxy
			socket chosen for this call.


```opensips title="rtpproxy_stream2xxx usage"
...
    if (is_method("INVITE")) {
        rtpproxy_offer();
        if ($rb=~ "0\.0\.0\.0") {
            rtpproxy_stream2uas("/var/rtpproxy/prompts/music_on_hold", "-1");
        } else {
            rtpproxy_stop_stream2uas();
        };
    };
...
	    
```


#### rtpproxy_stop_stream2uac([[set_id][, sock_pvar]]), rtpproxy_stop_stream2uas([[set_id][, sock_pvar]])


Stop streaming of announcement/prompt/MOH started previously by the
	    respective `rtpproxy_stream2xxx`.  The uac/uas
	    suffix selects whose announcement relatively to tha current
	    transaction should be stopped - UAC or UAS.


Meaning of the parameters is as follows:


- *set_id(optional)* - the set used for this call.
- *sock_pvar(optional)* - pvar used to store the RTPProxy
			socket chosen for this call.


These functions can be used from REQUEST_ROUTE, ONREPLY_ROUTE.


#### start_recording([[set_id][, sock_pvar]]) - deprecated, rtpproxy_start_recording([[set_id][, sock_pvar]])


This command will send a signal to the RTP-Proxy to record 
		the RTP stream on the RTP-Proxy.


Meaning of the parameters is as follows:


- *set_id(optional)* - the set used for this call.
- *sock_pvar(optional)* - pvar used to store the RTPProxy
			socket chosen for this call.


This function can be used from REQUEST_ROUTE and ONREPLY_ROUTE.


```opensips title="rtpproxy_start_recording usage"
...
rtpproxy_start_recording();
...
		
```


### Exported MI Functions


#### rtpproxy_enable


Enables a rtp proxy if parameter value is greater than 0.
			Disables it if a zero value is given.


The first parameter is the rtp proxy url (exactly as defined in 
			the config file).


The next parameter (optional) is the rtpproxy set ID (used for better
			indentification of the rtpproxy instance to be enabled, for example
			when a rtpproxy is used in multiple sets).


The last parameter must be a number in decimal representing the new
			enabled/disabled state.


NOTE: if a rtpproxy is defined multiple times (in the same or
			diferente sete), all its instances will be enables/disabled IF
			no set ID provided (as second param).


```c title="rtpproxy_enable usage"
...
## disable a RTPProxy by URL only
$ opensipsctl fifo rtpproxy_enable udp:192.168.2.133:8081 0
## disable a RTPProxy by URL and set ID (3)
$ opensipsctl fifo rtpproxy_enable udp:192.168.2.133:8081 3 0
...
			
```


#### rtpproxy_show


Displays all the rtp proxies and their information: set and 
			status (disabled or not, weight and recheck_ticks).


No parameter.


```c title="rtpproxy_show usage"
...
$ opensipsctl fifo rtpproxy_show
...
			
```


#### rtpproxy_reload


Reload rtp proxies sets from database. The function will delete all
			previous records and populate the list with the entries from the
			database table. The db_url parameter must be set if you want to use
			this command.


No parameter.


```c title="rtpproxy_reload usage"
...
$ opensipsctl fifo rtpproxy_reload
...
			
```


### Exported Events


#### E_RTPPROXY_STATUS


This event is raised when a RTPProxy server changes it's status to
			enabled/disabled.


Parameters:


- *socket* - the socket that identifies the 
				RTPProxy instance.
- *status* - *active* if
				the RTPProxy instance responds to probing or
				*inactive* if the instance was deactivated.


## Frequently Asked Questions


**Q: What happened with "rtpproxy_disable" parameter?**


It was removed as it became obsolete - now 
			"rtpproxy_sock" can take empty value to disable the
			rtpproxy functionality.


**Q: Where can I find more about OpenSIPS?**


Take a look at [http://www.opensips.org/](http://www.opensips.org/).


**Q: Where can I post a question about this module?**


First at all check if your question was already answered on one of
			our mailing lists:

E-mails regarding any stable OpenSIPS release should be sent to 
			users@lists.opensips.org and e-mails regarding development versions
			should be sent to devel@lists.opensips.org.

If you want to keep the mail private, send it to 
			users@lists.opensips.org.


**Q: How can I report a bug?**


Please follow the guidelines provided at:
			[https://github.com/OpenSIPS/opensips/issues](https://github.com/OpenSIPS/opensips/issues).


*doc copyrights:*
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
