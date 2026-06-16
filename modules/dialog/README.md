---
title: "dialog Module"
description: "The dialog module provides dialog awareness to the OpenSIPS proxy. Its functionality is to keep trace of the current dialogs, to offer information about them (like how many dialogs are active)."
---

## Admin Guide


### Overview


The dialog module provides dialog awareness to the OpenSIPS proxy. Its
	functionality is to keep trace of the current dialogs, to offer information
	about them (like how many dialogs are active).


Aside tracking, the dialog module offers functionalities like flags and
	attributes per dialog (persistent data across dialog), dialog profiling
	and dialog termination (on timeout base or external triggered).


The module, via an internal API, also provide the foundation to build on
	top of it more complex dialog-based functionalities via other OpenSIPS
	modules.


### How it works


To create the dialog associated with an initial request, you must call
	the create_dialog() function, with or without parameter.


The dialog is automatically terminated when a "BYE" is
	received. In case of no "BYE", the dialog lifetime is
	controlled via the default timeout (see "default_timeout"
	- [default timeout](#param_default_timeout)) and custom timeout (see
	"$DLG_timeout" - [DLG timeout](#pv_DLG_timeout)).


Once terminated, the in-memory dialog may be destroyed right away or, 
	depending on the "delete_delay"
	- [delete delay](#param_delete_delay)) setting, it may be kept for a
	while in memory, in a read-only state (no action, no changes, nothing).
	This delaying may be used to help with the routing of late in-dialog
	request that may be received after the dialog terminted (like late BYE's
	due retransmissions, cross BYE requests, auth'ed BYE request, slow ACK on
	re-INVITEs, etc).


### Dialog profiling


Dialog profiling is a mechanism that helps in classifying, sorting and
	keeping trace of certain types of dialogs, using whatever properties of
	the dialog (like caller, destination, type of calls, etc).
	Dialogs can be dynamically added in different (and several) profile
	tables - logically, each profile table can have a special meaning (like
	dialogs outside the domain, dialogs terminated to PSTN, etc).


There are two types of profiles:


- *with no value* - a dialog simply belongs
			to a profile. (like outbound calls profile). There is no other
			additional information to describe the dialog's belonging to the
			profile;
- *with value* - a dialog belongs to a profile
			having a certain value (like in caller profile, where the value
			is the caller ID). The belonging of the dialog to the profile is
			strictly related to the value.


A dialog can be added to multiple profiles in the same time.


Profiles are visible (at the moment) in the request route (for initial
	and sequential requests) and in the branch, failure and reply routes of
	the original request.


Dialog profiles can also be used in distributed systems, using the OpenSIPS
	CacheDB Interface or the *clusterer* module. This feature
	allows you to share dialog profile information with multiple OpenSIPS instaces
	that use the same CacheDB backend or are part of an OpenSIPS cluster. In order
	to do that, the **cachedb_url** or
	**profile_replication_cluster** parameters must be defined.
	Also, the profile must be marked as shared, by adding one of the
	*'/s'* or *'/b'* suffixes to the name of
	the profile in the *profiles_with_value* or
	*profiles_no_value* parameters.


### Dialog clustering


**Dialog replication** is a mechanism used to
	mirror all dialog changes taking place in one OpenSIPS instance to one or
	multiple other instances. The process is simplified by using the
	*clusterer* module which facilitates the management of a
	cluster of OpenSIPS nodes and the sending of replication-related BIN packets
	(binary-encoded, using *proto_bin*). This feature
	is useful in achieving High Availability and/or Load Balancing for ongoing calls.


Configuring both receival and sending of dialog replication packets is trivial
	and can be done by using the
	**dialog_replication_cluster** parameter. But in
	addition to just sharing data, in order to properly cluster dialogs you will
	need to manage which node in the cluster is doing certain actions on certain
	dialogs using the **sharing tags** mechanism.
	For details and configuration examples on how this would work
	in different usage scenarios, see 
	[this article](https://blog.opensips.org/2018/03/23/clustering-ongoing-calls-with-opensips-2-4/).


The following actions will **not** be performed for a dialog
	marked with a sharing tag that is in the "**backup**" state:


- sending Re-Invite or OPTIONS pings to end-points
- generating BYE requests or any other actions(like producing CDRs)
			upon dialog expiration
- sending replication packets on dialog events(update, delete)
- counting the dialog in the profiles that it belongs; only if profile replication
			is also enabled


In addition to the event-driven replication, an OpenSIPS instance will first
	try to learn all the dialog information from antoher node in the cluster at startup.
	The data synchronization mechanism requires defining one of the nodes in the cluster
	as a "**seed**" node.
	See the [clusterer](../clusterer#capabilities) 
	module for details on how to do this and why is it needed.


In the context of dialog replication, using a database as a failsafe for obtaining
	restart persistency for dialog data is useful in case all nodes in the cluster are down.
	This approach makes the most sense if a separate, local DB is used for each node in the
	cluster. Dialogs loaded from the database at startup, which are not reconfirmed through
	syncing, are dropped and also deleted from the database once the sync from cluster is complete.


Also configuring profile replication via the *profile_replication_cluster*
	parameter is not necessary when dialog replication is already configured. The profile information
	is included in the dialog updates sent in the dialog replication cluster. The profiles must still
	be marked for sharing though in the *profiles_with_value* or
	*profiles_no_value* parameters.


A scenario were both profile and dialog replication should be configured is when a platform has
	multiple POPs, where separate dialog replication clusters are configured for HA purposes, and a
	cluster for globally shared profiles is also required. In this case, proper counting for dialogs
	is ensured by using the sharing tags mechanism(in order to avoid counting each dialog twice,
	both on the active and backup node for that dialog).


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *TM* - Transaction module
- *RR* - Record-Route module, optional, 
				if Dialog ID matching is used in non Topo Hiding cases
- *clusterer* - if *replication_cluster*
				parameter is set (contact replication via clusterer
				module)


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### enable_stats (integer)


If the statistics support should be enabled or not. Via statistic
		variables, the module provide information about the dialog processing.
		Set it to zero to disable or to non-zero to enable it.


*Default value is "1 (enabled)".*


```c title="Set enable_stats parameter"
...
modparam("dialog", "enable_stats", 0)
...
```


#### hash_size (integer)


The size of the hash table internally used to keep the dialogs. A
		larger table is much faster but consumes more memory. The hash size
		must be a power of 2 number.


IMPORTANT: If dialogs' information should be stored in a database,
		a constant hash_size should be used, otherwise the restored process
		will not take place. If you really want to modify the hash_size you
		must delete all table's rows before restarting OpenSIPS.


*Default value is "4096".*


```c title="Set hash_size parameter"
...
modparam("dialog", "hash_size", 1024)
...
```


#### log_profile_hash_size (integer)


The size of the hash table internally used to store  profile->dialog
		associations. A larger table can provide more
		parallel operations but consumes more memory. The hash size
		is provided as the base 2 logarithm(e.g. log_profile_hash_size =4
		means the table has 2^4 entries).


*Default value is "4".*


```c title="Set hash_size parameter"
...
modparam("dialog", "log_profile_hash_size", 5) #set a table size of 32
...
```


#### rr_param (string)


Name of the Record-Route parameter to be added with the dialog cookie.
		It is used for fast dialog matching of the sequential requests.


*Default value is "did".*


```c title="Set rr_param parameter"
...
modparam("dialog", "rr_param", "xyz")
...
```


#### default_timeout (integer)


The default dialog timeout (in seconds) if no custom one is set.


*Default value is "43200 (12 hours)".*


```c title="Set default_timeout parameter"
...
modparam("dialog", "default_timeout", 21600)
...
```


#### dlg_extra_hdrs (string)


A string containing the extra headers (full format, with EOH)
		to be added in the requests generated by the module (like BYEs).


*Default value is "NULL".*


```c title="Set dlf_extra_hdrs parameter"
...
modparam("dialog", "dlg_extra_hdrs", "Hint: credit expired\r\n")
...
```


#### dlg_match_mode (integer)


How the seqential requests should be matched against the known dialogs.
		The modes are a combination between matching based on a cookie (DID)
		stored as cookie in Record-Route header and the matching based on SIP
		elements (as in RFC3261).


The supported modes are:


- *0 - DID_ONLY* - the match is done
				exclusively based on DID;
- *1 - DID_FALLBACK* - the match is first
				tried based on DID and if not present, it will fallback to
				SIP matching;
- *2 - DID_NONE* - the match is done
				exclusively based on SIP elements; no DID information is added
				in RR.


*Default value is "1 (DID_FALLBACK)".*


NOTE that if you have call looping on your OpenSIPS server (passing
		more than once through the same OpenSIPS instance), it is strongly
		suggested to use only DID_ONLY mode, as the SIP based matching will
		have an undefined behavior - from SIP perspective, a sequential
		dialog will match all the loops of the call, as the Call-ID, To and 
		From TAGs are the same.


```c title="Set dlg_match_mode parameter"
...
modparam("dialog", "dlg_match_mode", 0)
...
```


#### delete_delay (integer)


The interval (seconds) to delay a dialog deletion / removal from
			memory AFTER its termination. Once terminated, the dialog will
			be kept in a read only state (no action, no changes), but it will
			still be able to match and route late in-dialog requests.


This global value may be per-call changed via the DLG_del_delay
			"$DLG_del_delay" ([DLG del delay](#pv_DLG_del_delay))
			script variable.


*Default value is "0" (disabled).*


```c title="Set delete_delay parameter"
...
modparam("dialog", "delete_delay", 10)
...
```


#### db_url (string)


If you want to store the information about the dialogs in a database
		a database url must be specified.


*Default value is "mysql://opensips:opensipsrw@localhost/opensips".*


```c title="Set db_url parameter"
...
modparam("dialog", "db_url", "dbdriver://username:password@dbhost/dbname")
...
```


#### db_mode (integer)


Describe how to push into the DB the dialogs' information from memory.


The supported modes are:


- *0 - NO_DB* - the memory content is not
				flushed into DB;
- *1 - REALTIME* - any dialog information
				changes will be reflected into the database immediately.
- *2 - DELAYED* - the dialog information
				changes will be flushed into the DB periodically, based on a
				timer routine.
- *3 - SHUTDOWN* - the dialog information
				will be flushed into DB only at shutdown - no runtime updates.


*Default value is "0".*


```c title="Set db_mode parameter"
...
modparam("dialog", "db_mode", 1)
...
```


#### db_update_period (integer)


The interval (seconds) at which to update dialogs' information if you chose to store the dialogs' info at a given interval.
			A too short interval will generate intensive database operations, a too large one will not notice short dialogs.


*Default value is "60".*


```c title="Set db_update_period parameter"
...
modparam("dialog", "db_update_period", 120)
...
```


#### options_ping_interval (integer)


The interval (seconds) at which OpenSIPS will generate in-dialog
		OPTIONS pings for one or both of the involved parties.


*Default value is "30".*


```c title="Set options_ping_interval parameter"
...
modparam("dialog", "options_ping_interval", 20)
...
```


#### reinvite_ping_interval (integer)


The interval (seconds) at which OpenSIPS will generate in-dialog
		Re-INVITE pings for one or both of the involved parties.


**Important:** the ping timeout detection
		is performed every time this interval ticks, not when the re-INVITE
		transaction times out! Consequently, please make sure that the
		timeouts for re-INVITE transactions (e.g. the "fr_timeout"
		modparam of the "tm" module or its $T_fr_timeout variable) are
		always **lower** than the value of this
		parameter! Failing to ensure this ordering of timeouts may possibly
		lead to re-INVITE pings never ending a disconnected dialog due to pings
		getting retried before getting a chance to properly time out.


*Default value is "300".*


```c title="Set reinvite_ping_interval parameter"
...
modparam("dialog", "reinvite_ping_interval", 600)
...
```


#### table_name (string)


If you want to store the information about the dialogs in a
		database a table name must be specified.


*Default value is "dialog".*


```c title="Set table_name parameter"
...
modparam("dialog", "table_name", "my_dialog")
...
```


#### call_id_column (string)


The column's name in the database to store the dialogs' callid.


*Default value is "callid".*


```c title="Set call_id_column parameter"
...
modparam("dialog", "call_id_column", "callid_c_name")
...
```


#### from_uri_column (string)


The column's name in the database to store the caller's
			sip address.


*Default value is "from_uri".*


```c title="Set from_uri_column parameter"
...
modparam("dialog", "from_uri_column", "from_uri_c_name")
...
```


#### from_tag_column (string)


The column's name in the database to store the From tag from
			the Invite request.


*Default value is "from_tag".*


```c title="Set from_tag_column parameter"
...
modparam("dialog", "from_tag_column", "from_tag_c_name")
...
```


#### to_uri_column (string)


The column's name in the database to store the calee's sip address.


*Default value is "to_uri".*


```c title="Set to_uri_column parameter"
...
modparam("dialog", "to_uri_column", "to_uri_c_name")
...
```


#### to_tag_column (string)


The column's name in the database to store the To tag from
			the 200 OK response to the Invite request, if present.


*Default value is "to_tag".*


```c title="Set to_tag_column parameter"
...
modparam("dialog", "to_tag_column", "to_tag_c_name")
...
```


#### from_cseq_column (string)


The column's name in the database to store the cseq from caller
			side.


*Default value is "caller_cseq".*


```c title="Set from_cseq_column parameter"
...
modparam("dialog", "from_cseq_column", "from_cseq_c_name")
...
```


#### to_cseq_column (string)


The column's name in the database to store the cseq from callee
			side.


*Default value is "callee_cseq".*


```c title="Set to_cseq_column parameter"
...
modparam("dialog", "to_cseq_column", "to_cseq_c_name")
...
```


#### from_route_column (string)


The column's name in the database to store the route records from
			caller side (proxy to caller).


*Default value is "caller_route_set".*


```c title="Set from_route_column parameter"
...
modparam("dialog", "from_route_column", "from_route_c_name")
...
```


#### to_route_column (string)


The column's name in the database to store the route records from
			callee side (proxy to callee).


*Default value is "callee_route_set".*


```c title="Set to_route_column parameter"
...
modparam("dialog", "to_route_column", "to_route_c_name")
...
```


#### from_contact_column (string)


The column's name in the database to store the caller's contact
			uri.


*Default value is "caller_contact".*


```c title="Set from_contact_column parameter"
...
modparam("dialog", "from_contact_column", "from_contact_c_name")
...
```


#### to_contact_column (string)


The column's name in the database to store the callee's contact
			uri.


*Default value is "callee_contact".*


```c title="Set to_contact_column parameter"
...
modparam("dialog", "to_contact_column", "to_contact_c_name")
...
```


#### from_sock_column (string)


The column's name in the database to store the information about
			the local interface receiving the traffic from caller.


*Default value is "caller_sock".*


```c title="Set from_sock_column parameter"
...
modparam("dialog", "from_sock_column", "from_sock_c_name")
...
```


#### to_sock_column (string)


The column's name in the database to store information about the
			local interface receiving the traffic from callee.


*Default value is "callee_sock".*


```c title="Set to_sock_column parameter"
...
modparam("dialog", "to_sock_column", "to_sock_c_name")
...
```


#### dlg_id_column (string)


The column's name in the database to store the dialogs'
			id information.


*Default value is "dlg_id".*


```c title="Set dlg_id_column parameter"
...
modparam("dialog", "dlg_id_column", "dlg_id_c_name")
...
```


#### state_column (string)


The column's name in the database to store the
			dialogs' state information.


*Default value is "state".*


```c title="Set state_column parameter"
...
modparam("dialog", "state_column", "state_c_name")
...
```


#### start_time_column (string)


The column's name in the database to store the
			dialogs' start time information.


*Default value is "start_time".*


```c title="Set start_time_column parameter"
...
modparam("dialog", "start_time_column", "start_time_c_name")
...
```


#### timeout_column (string)


The column's name in the database to store the dialogs' timeout.


*Default value is "timeout".*


```c title="Set timeout_column parameter"
...
modparam("dialog", "timeout_column", "timeout_c_name")
...
```


#### profiles_column (string)


The column's name in the database to store the dialogs' profiles.


*Default value is "profiles".*


```c title="Set profiles_column parameter"
...
modparam("dialog", "profiles_column", "profiles_c_name")
...
```


#### vars_column (string)


The column's name in the database to store the dialogs' vars.


*Default value is "vars".*


```c title="Set vars_column parameter"
...
modparam("dialog", "vars_column", "vars_c_name")
...
```


#### sflags_column (string)


The column's name in the database to store the dialogs' script flags.


*Default value is "script_flags".*


```c title="Set sflags_column parameter"
...
modparam("dialog", "sflags_column", "sflags_c_name")
...
```


#### mflags_column (string)


The column's name in the database to store the dialogs' module flags.


*Default value is "module_flags".*


```c title="Set mflags_column parameter"
...
modparam("dialog", "mflags_column", "mflags_c_name")
...
```


#### flags_column (string)


The column's name in the database to store the dialogs' flags.


*Default value is "flags".*


```c title="Set flags_column parameter"
...
modparam("dialog", "flags_column", "flags_c_name")
...
```


#### profiles_with_value (string)


List of names (alphanumerical/-/_) for profiles with values. Flags
			*/b* or */s* allow sharing
			profiles between OpenSIPS instances using the clusterer module or a
			CacheDB backend, respectively.


*Default value is "empty".*


```c title="Set profiles_with_value parameter"
...
modparam("dialog", "profiles_with_value", "callerCC; gatewayCC; clientChannels/s; codecUsed/b;")
...
```


#### profiles_no_value (string)


List of names (alphanumerical/-/_) for profiles without values. Flags
			*/b* or */s* allow sharing
			profiles between OpenSIPS instances using the clusterer module or a
			CacheDB backend, respectively.


*Default value is "empty".*


```c title="Set profiles_no_value parameter"
...
modparam("dialog", "profiles_no_value", "inbound ; outbound ; shared/s; repl/b;")
...
```


#### db_flush_vals_profiles (int)


Pushes dialog values, profiles and flags into the database
			along with other dialog state information (see db_mode 1 and 2).


*Default value is "empty".*


```c title="Set db_flush_vals_profiles parameter"
...
modparam("dialog", "db_flush_vals_profiles", 1)
...
```


#### timer_bulk_del_no (int)


The number of dialogs that should be attempted to be
			deleted at the same time ( a single query ) from the
			DB back-end.


*Default value is "1".*


```c title="Set timer_bulk_del_no parameter"
...
modparam("dialog", "timer_bulk_del_no", 10)
...
```


#### race_condition_timeout (int)


If dialog is created using the 'E' flag, and a SIP Race condition happens, then the dialog will be terminated after 'race_condition_timeout' seconds.
		Currently, the only supported race conditions are (200OK vs CANCEL) and (early BYE vs 200OK)


*Default value is "5" seconds.*


```c title="Set race_condition_timeout parameter"
...
modparam("dialog", "race_condition_timeout", 1)
...
```


#### cachedb_url (string)


Enables distributed dialog profiles and specifies the
			backend that should be used by the CacheDB interface.


*Default value is "empty".*


```c title="Set cachedb_url parameter"
...
modparam("dialog", "cachedb_url", "redis://127.0.0.1:6379")
...
```


#### profile_value_prefix (string)


Specifies what prefix should be added to the profiles with
			value when they are inserted into CacheDB backed. This is
			only used when distributed profiles are enabled.


*Default value is "dlg_val_".*


```c title="Set profile_value_prefix parameter"
...
modparam("dialog", "profile_value_prefix", "dlgv_")
...
```


#### profile_no_value_prefix (string)


Specifies what prefix should be added to the profiles without
			value when they are inserted into CacheDB backed. This is
			only used when distributed profiles are enabled.


*Default value is "dlg_noval_".*


```c title="Set profile_no_value_prefix parameter"
...
modparam("dialog", "profile_no_value_prefix", "dlgnv_")
...
```


#### profile_size_prefix (string)


Specifies what prefix should be added to the entity that holds
			the profiles with value size in CacheDB backed. This is
			only used when distributed profiles are enabled.


*Default value is "dlg_size_".*


```c title="Set profile_size_prefix parameter"
...
modparam("dialog", "profile_size_prefix", "dlgs_")
...
```


#### profile_timeout (int)


Specifies how long a dialog profile should be kept in the CacheDB
			until it expires. This is only used when distributed profiles are
			enabled.


*Default value is "86400".*


```c title="Set profile_timeout parameter"
...
modparam("dialog", "profile_timeout", "43200")
...
```


#### dialog_replication_cluster (int)


Specifies the cluster ID for dialog replication using the
			*clusterer* module. This enables sending
			and receiving all the dialog-related events (creation, update and
			deletion) in the cluster.


This OpenSIPS cluster exposes the **"dialog-dlg-repl"**
capability in order to mark nodes as eligible for becoming data donors during an
arbitrary sync request. Consequently, the cluster must have *at least
one node* marked with the **"seed"** value
as the *clusterer.flags* column/property in order to be fully functional.
Consult the [clusterer - Capabilities](../clusterer#capabilities)
chapter for more details.


*Default value is "0" (no replication).*


```c title="Set dialog_replication_cluster parameter"
...
modparam("dialog", "dialog_replication_cluster", 1)
...
```


#### profile_replication_cluster (int)


Specifies the cluster ID for profile replication using the
			*clusterer* module. This enables sending
			and receiving the profile information (value, dialog count)
			in the cluster.


*Default value is "0" (no replication).*


```c title="Set profile_replication_cluster parameter"
...
modparam("dialog", "profile_replication_cluster", 1)
...
```


#### replicate_profiles_buffer (string)


Used to specify the length of the buffer used by the binary
		replication, in bytes. Usually this should be big enough to hold
		as much data as possible, but small enough to avoid UDP
		fragmentation. The recommended value is the smallest MTU between
		all the replication instances.


*Default value is 1400 bytes.*


```c title="Set replicate_profiles_buffer parameter"
...
modparam("dialog", "replicate_profiles_buffer", 500)
...
```


#### replicate_profiles_check (string)


Timer in seconds, used to specify how often the module should check
		whether old, replicated profiles values are obsolete and should be removed.
		should replicate its profiles to the other instances.


*Default value is 10 s.*


```c title="Set replicate_profiles_check parameter"
...
modparam("dialog", "replicate_profiles_check", 100)
...
```


#### replicate_profiles_timer (string)


Timer in milliseconds, used to specify how often the module
		should replicate its profiles to the other instances.


*Default value is 200 ms.*


```c title="Set replicate_profiles_timer parameter"
...
modparam("dialog", "replicate_profiles_timer", 100)
...
```


#### replicate_profiles_expire (string)


Timer in seconds, used to specify when the profiles counters received
		from a different instance should no longer be taken into account.
		This is used to prevent obsolete values, in case an instance stops
		replicating its counters.


*Default value is 10 s.*


```c title="Set replicate_profiles_expire parameter"
...
modparam("dialog", "replicate_profiles_expire", 10)
...
```


#### cluster_auto_sync (string)


Specifies whether to automatically issue a sync request (for dialogs
		marked with a sharing tag in backup state) when a node becomes reachable.
		A value of *1* means enabled and *0*
		disabled.


*Default value is 1 (enabled).*


```c title="Set cluster_auto_sync parameter"
...
modparam("dialog", "cluster_auto_sync", 0)
...
```


#### auto_prack_hangup_on_failure (int)


Controls how dialogs created with the "auto-prack" flag react
		when the automatically generated PRACK transaction fails. A value of
		*1* causes OpenSIPS to generate a native
		*502 Bad Gateway* reply on the correlated INVITE
		transaction, while a value of *0* leaves the INVITE
		transaction untouched.


A failure means that the local PRACK transaction either completed with a
		final negative reply or hit TM failure handling.


*Default value is "0" (disabled).*


#### auto_prack_fr_timeout (int)


Specifies the TM FR timeout, in seconds, for PRACK transactions generated
		automatically for dialogs created with the "auto-prack" flag.
		This value is applied to the local PRACK transaction immediately after it
		is created.


*Default value is "3".*


### Exported Functions


#### create_dialog([flags])


The function creats the dialog for the currently processed request. The
		request must be an initial request.

		Optionally,the function also receives a string parameter, which specifies
		special behavior to be done for the current dialog.


Parameters:


- *flags (string, optional)*
				Possible values here are:
				
				"bye-on-timeout" - upon reaching dialog lifetime,
				BYEs will be triggered both ways
				"options-ping-caller" - ping caller side with
				OPTIONS messages, once every
				`options_ping_interval` seconds
				"options-ping-callee" - ping callee side with
				OPTIONS messages, once every
				`options_ping_interval` seconds
				"reinvite-ping-caller" - ping caller side with
				RE-INVITE messages, once every
				`reinvite_ping_interval` seconds
				"reinvite-ping-callee" - ping callee side with
				RE-INVITE messages, once every
				`reinvite_ping_interval` seconds
				"end-on-race-condition" - upon detecting a SIP
				Race condition (see RFC 5407), end the call after
				`race_condition_timeout` seconds
				"auto-prack" - automatically generate PRACK
				requests for reliable 101-199 provisional INVITE replies
				carrying an RSeq header
				
				Multiple string flags can be used at the same time as a CSV,
				i.e. passing
				"bye-on-timeout,options-ping-caller,options-ping-callee"
				will enable all 3 flags.


NOTE: both RE-INVITE and OPTIONS pinging cannot be enabled at the same time
		for a single dialog leg. If both flags for the same leg are provided
		(for example
		"options-ping-caller,reinvite-ping-caller" or
		"options-ping-callee,reinvite-ping-callee"),
		only RE-INVITE pinging will be used.


The function returns true if the dialog was successfully created or
		if the dialog was previously created.


This function can be used from REQUEST_ROUTE.


```c title="create_dialog() usage"
...
create_dialog();
...
#ping caller
create_dialog("options-ping-caller");
...
#ping caller and callee
create_dialog("options-ping-caller,options-ping-callee");

#bye on timeout
create_dialog("bye-on-timeout");

#auto-PRACK reliable provisional replies
create_dialog("auto-prack");
...
```


#### match_dialog([dlg_match_mode])


This function is to be used to match a sequential (in-dialog) request
		to an ongoing dialog.


By default, dialog matching is performed according to the
		[dlg match mode](#param_dlg_match_mode) module parameter. A specific
		matching mode may be enforced by specifying the optional
		"dlg_match_mode" parameter. Possible values for this parameter are
		"DID_ONLY", "DID_FALLBACK" and "DID_NONE".


As sequential requests are automatically matched to the dialog when
		doing "loose_route()" from script, this function is intended to:
		(A) control the place in your script where the dialog matching is done
		and (B) to cope with bogus sequential requests that do not have Route
		headers, so they are not handled by loose_route().


Parameters:


- *dlg_match_mode (string, optional)*


The function returns true if a dialog exists for the request.


This function can be used from REQUEST_ROUTE.


```c title="match_dialog() usage"
...
    if (has_totag()) {
        loose_route();

        # example 1: match according to 
```


#### validate_dialog()


The function checks the current received requests against the dialog
		(internal data) it belongs to.
		Performing several tests, the function will help to detect the bogus
		injected in-dialog requests (like malicious BYEs).


The performed tests are related to CSEQ sequence checking and routing
		information checking (contact and route set).


The function returns true if a dialog exists for the request and if
		the request is valid (according to dialog data). If the request is invalid,
		the following return codes are returned :


- *-1* - invalid cseq
- *-2* - invalid remote target
- *-3* - invalid route set
- *-4* - other errors ( parsing, no dlg, etc )


This function can be used from REQUEST_ROUTE.


```c title="validate_dialog() usage"
...
    if (has_totag()) {
        loose_route();
        if ($DLG_status!=NULL && !validate_dialog() ) {
            xlog(" in-dialog bogus request \n");
        } else {
            xlog(" in-dialog valid request - $DLG_dir !\n");
        }
    }
...
```


#### fix_route_dialog()


The function forces an in dialog SIP message to contain the ruri, route headers and
			dst_uri, as specified by the internal data of the dialog it belongs to.
			The function will prevent the existence of bogus injected in-dialog
			requests ( like malicious BYEs )


This function can be used from REQUEST_ROUTE.


```c title="fix_route_dialog() usage"
...
    if (has_totag()) {
        loose_route();
        if ($DLG_status!=NULL)
            if (!validate_dialog())
                fix_route_dialog();
    }
...
```


#### get_dialog_info(attr,avp,key,key_val,no_dlgs)


The function extracts a dialog value from another dialog. It first searches
		through all existing (ongoing) dialogs for all dialogs that have a dialog
		variable named "key" with the value "key_val"
		(so a dialog where $dlg_val(key)=="key_val"). If found, it returns
		the value of the dialog variable "attr" from all the
		founds dialog in the "avp" pseudo-variable, otherwise nothing is written
		in "avp", and a negative error code is returned.


NOTE: the function does not require to be called in the context of
		a dialog - you can use it whenever / whereever for searching for other
		dialogs.


Meaning of the parameters is as follows:


- *attr (string)* - the name of the dialog variable
			(from the found dialog) to be returned;
- *avp (var)* - an avp where to store the values of
			the "attr" dialog variable.
			Since the function checks through all dialogs, this needs to be an actual
			AVP in order to support pushing values from all matched dialogs.
- *key (string)* - name of a dialog variable to be
			used a search key (when looking after the target dialog)
- *key_val (var)* - the value of the dialog
			variable that is used as key in searching the target dialog.
- *no_dlgs (var)* - the total number of dialogs
			containing the key variable


This function can be used from ALL ROUTES.


```c title="get_dialog_info usage"
...
if ( get_dialog_info("callee",$avp(callee_array),"caller",$fu,$var(dlg_no)) ) {
	xlog("caller $fu has $var(dlg_no) other ongoing calls, talking with :");	
	$var(it) = 0;
	while ($var(it) < $var(dlg_no)) {
		$var(current_callee) = $(avp(callee_array)[$var(it)]);
		xlog(" $var(current_callee) ");
		$var(it) = $var(it) + 1;
	}

	xlog("\n");
}

# create dialog for current call and place the caller and callee attributes
create_dialog();
$dlg_val(caller) = $fu;
$dlg_val(callee) = $ru;
...
```


#### get_dialog_vals(names,vals,callid)


The function fetches all the dialog variables of another dialog.
		It first searches through all existing (ongoing) dialogs based on the 
		given SIP CallID. If found, it returns all the dialog variables as 
		two parallel arrays of names and values (using the given variables
		"names" and "vals"). As these variables have to hold arrays, they must
		be AVPs.


NOTE: the function does not require to be called in the context of
		a dialog - you can use it whenever / whereever for searching for other
		dialogs.


Meaning of the parameters is as follows:


- *names (var)* - an AVP variable to
			hold all the names of the variables from the found dialog.
- *vals (var)* - an AVP variable to
			hold all the values of the variables from the found dialog.
- *callid (string)* - the callid of a dialog
			to be searched (and have the variables fetched).


This function can be used from any type of route.


```c title="get_dialog_vals usage"
...
if ( get_dialog_vals($avp(d_names),$avp(d_vals),$var(callid)) ) {
	xlog("the call $var(callid) has the variables:\n);
	$var(i) = 0;
	while ( $(avp(d_names)[$var(i)])!=NULL ) {
		xlog("var $var(i) is $(avp(d_names)[$var(i)])='$(avp(d_vals)[$var(i)])'\n");
		$var(i) = $var(i) + 1;
	}
}
...
```


#### get_dialogs_by_val(name,value,out_avp,out_dlg_no)


The function looks up through the whole dialog table for dialogs containing a $dlg_val with the provided name and value, and returns all the $DLG_ctx_json variables for the matched dialogs, storing them in the provided out_avp. The total number of matched dialogs is returned in the out_dlgs_no variable


NOTE: the function does not require to be called in the context of
		a dialog - you can use it whenever / whereever for searching for other
		dialogs.


Meaning of the parameters is as follows:


- *name (string)* - the name of the dialog variable used for the lookup
- *value (var)* - the value of the above dialog val
- *out_avp (var)* - the AVP which will be populated will the dialog JSONs for all the matched calls
- *dlg_no (var)* - the out var which will contain the total number of matched dialogs


This function can be used from any type of route.


```c title="get_dialog_vals usage"
...
if ( get_dialogs_by_val("caller",$fU,$avp(dlg_jsons),$avp(dlg_no)) ) {
	xlog("Caller $fU has $avp(dlg_no) other calls \n);
	$var(i) = 0;
	while ( $(avp(dlg_jsons)[$var(i)])!=NULL ) {
		$json(dlg_info) := $(avp(dlg_jsons)[$var(i)]); 
		# fetch any info for the above call and process it
		$var(i) = $var(i) + 1;
	}
}
...
```


#### get_dialogs_by_profile(name,value,out_avp,out_dlg_no)


The function looks up through the whole dialog table for dialogs configured to be within the provided dialog profile name, and optionally with the provided profile value. The function returns all the $DLG_ctx_json variables for the matched dialogs, storing them in the provided out_avp. The total number of matched dialogs is returned in the out_dlgs_no variable


NOTE: the function does not require to be called in the context of
		a dialog - you can use it whenever / whereever for searching for other
		dialogs.


Meaning of the parameters is as follows:


- *name (string)* - the name of the dialog profile used for the lookup
- *value (string)* - the value of the above dialog profile ( optional )
- *out_avp (var)* - the AVP which will be populated will the dialog JSONs for all the matched calls
- *dlg_no (var)* - the out var which will contain the total number of matched dialogs


This function can be used from any type of route.


```c title="get_dialog_vals usage"
...
if ( get_dialogs_by_profile("caller",$fU,$avp(dlg_jsons),$avp(dlg_no)) ) {
	xlog("Caller $fU has $avp(dlg_no) other calls \n);
	$var(i) = 0;
	while ( $(avp(dlg_jsons)[$var(i)])!=NULL ) {
		$json(dlg_info) := $(avp(dlg_jsons)[$var(i)]); 
		# fetch any info for the above call and process it
		$var(i) = $var(i) + 1;
	}
}
...
```


#### load_dialog_ctx( dialog [, id_type] [, active_only])


The function loads and switches to the context of the given dialog.
		The context of a dialog is given by the dialog flags, variables,
		profiles and any other value/state related to the dialog. By 
		switching to the context of another dialog, you will see at the script
		level, by default, all the data from the new dialog.


NOTE: you cannot perform a new load until doing an unload - no nested
		loadings are possible.


Meaning of the parameters is as follows:


- *dialog (string)* - the identifier of the
			dialog to be loaded, it may be a SIP Call-ID or a Dialog ID.
- *id_type (string,optional)* - what kind of
			dialog identified was used in the first parameter. It can be
			*callid* (SIP Call-ID) or 
			*did* (internal Dialog ID). By default callid
			will be assumed.
- *active_only (integer,optional)* - if
			set to something different than *0*,
			it only considers active dialogs - dialogs that are not
			deleted.


This function can be used from any type of route.


```c title="load_dialog_ctx usage"
...
if (load_dialog_ctx("$var(callid)")) {
	xlog("The dialog '$var(callid)' already has a duration "
	     "of $DLG_lifetime seconds\n");
	if (is_in_profile("inboundCall"))
		xlog("this dialog is an inbound call\n");
	unload_dialog_ctx();
}
...
```


#### unload_dialog_ctx()


The function off-loads the loaded context of another dialog, exposing
		whatever dialog context was present before doing the load.


NOTE: you MUST perform from script an explicit unload for each load
		you did, otherwise the loaded dialog will remain hanged for ever.


This function can be used from any type of route.


For usage example, see the [load dialog ctx](#func_load_dialog_ctx)


#### set_dlg_profile(profile, [value], [clear_values])


Inserts the current dialog into a profile. Note that if the profile does
		not support values, this will be silently discarded. A dialog may be
		inserted in the same profile multiple times.


NOTE: the dialog must be created before using this function (use
		create_dialog() function before).


Meaning of the parameters is as follows:


- *profile (string)* - name of the profile to be
			added to.
- *value (string, optional)* - string value to
			define the belonging of the dialog to the profile - note that the
			profile must support values.
- *clear_values (boolean, optional)* - if set to
				*true* (1), all values of the profile will be cleared
				before setting the given value.  Default: *false*.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
			REPLY_ROUTE and FAILURE_ROUTE.


```c title="set_dlg_profile usage"
...
set_dlg_profile("inboundCall");

# Set a new value (all other values are kept intact)
set_dlg_profile("caller", $fu);

# Set a new value while removing all previous values
set_dlg_profile("caller", $fu, true);
...
```


#### unset_dlg_profile(profile, [value])


Removes the current dialog from a profile.


NOTE: the dialog must be created before using this function (use
		create_dialog() function before).


Meaning of the parameters is as follows:


- *profile (string)* - name of the profile to be
			removed from.
- *value (string, optional)* - string value to
			define the belonging of the dialog to the profile - note that the
			profile must support values.
NEW in 3.4: for profiles with value, by omitting this parameter
				you can now clear all values of the given profile.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
			REPLY_ROUTE and FAILURE_ROUTE.


```c title="unset_dlg_profile usage"
...
unset_dlg_profile("inboundCall");
unset_dlg_profile("caller", $fu);
...
# Remove all values in a profile
unset_dlg_profile("caller");
...
```


#### is_in_profile(profile,[value])


Checks if the current dialog belongs to a profile. If the profile
		supports values, the check can be reinforced to take into account a
		specific value - if the dialog was inserted into the profile for a
		specific value. If no value is passed, only simply belonging of the
		dialog to the profile is checked. Note that if the profile does not
		support values, this will be silently discarded.


NOTE: the dialog must be created before using this function (use
		create_dialog() function before).


Meaning of the parameters is as follows:


- *profile (string)* - name of the profile to be
			checked against.
- *value (string. optional)* - string value to
			toughen the check.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
			REPLY_ROUTE and FAILURE_ROUTE.


```c title="is_in_profile usage"
...
if (is_in_profile("inboundCall")) {
	log("this request belongs to a inbound call\n");
}
...
if (is_in_profile("caller","XX")) {
	log("this request belongs to a call of user XX\n");
}
...
```


#### get_profile_size(profile,[value],size)


Returns the number of dialogs belonging to a profile. If the profile
		supports values, the check can be reinforced to take into account a
		specific value - how many dialogs were inserted into the profile with
		a specific value. If not value is passed, only simply belonging of the
		dialog to the profile is checked. Note that the profile does not
		supports values, this will be silently discarded.


Meaning of the parameters is as follows:


- *profile (string)* - name of the profile to get
			the size for.
- *value (string, optional)* - string value to
			toughen the check.
- *size (var)* - an AVP or script variable to
			return the profile size in.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
			REPLY_ROUTE and FAILURE_ROUTE.


```c title="get_profile_size usage"
modparam("dialog", "profiles_no_value", "inboundCalls")
modparam("dialog", "profiles_with_value", "caller")
...
get_profile_size("inboundCalls",,$var(size));
xlog("inboundCalls: $var(size)\n");
...
get_profile_size("caller", $fu, $var(size));
xlog("currently, the user $fu has $var(size) active outgoing calls\n");
...
```


#### set_dlg_flag(flag)


Sets the dialog flag named *flag* to true. The dialog
		flags are dialog persistent and they can be accessed (set and test)
		for all requests belonging to the dialog.


Parameters:


- *flag (string, static)* - The flag name.


NOTE: the dialog must be created before using this function (use
		create_dialog() function before).


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
			REPLY_ROUTE and FAILURE_ROUTE.


```c title="set_dlg_flag usage"
...
set_dlg_flag("MY_DLG_FLAG");
...
```


#### test_and_set_dlg_flag(flag, value)


Atomically checks if the dialog flag named *flag* is
		equal to *value*. If true, changes the value with the
		opposite one. This operation is done under the dialog lock.


- *flag (string, static)* - The flag name.
- *value (int)* - The value should be 0 (false) or 1 (true).


NOTE: the dialog must be created before using this function (use
		create_dialog() function before).


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
			REPLY_ROUTE and FAILURE_ROUTE.


```c title="test_and_set_dlg_flag usage"
...
test_and_set_dlg_flag("MY_DLG_FLAG", 0);
...
```


#### reset_dlg_flag(flag)


Resets the dialog flag named *flag* to false.
		The dialog flags are dialog persistent and they can be accessed
		(set and test) for all requests belonging to the dialog.


Parameters:


- *flag (string, static)* - The flag name.


NOTE: the dialog must be created before using this function (use
		create_dialog() function before).


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
			REPLY_ROUTE and FAILURE_ROUTE.


```c title="reset_dlg_flag usage"
...
reset_dlg_flag("MY_DLG_FLAG");
...
```


#### is_dlg_flag_set(flag)


Returns true if the dialog flag named *flag* is set.
		The dialog flags are dialog persistent and they can be accessed
		(set and test) for all requests belonging to the dialog.


Parameters:


- *flag (string, static)* - The flag name.


NOTE: the dialog must be created before using this function (use
		create_dialog() function before).


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
			REPLY_ROUTE and FAILURE_ROUTE.


```c title="is_dlg_flag_set usage"
...
if (is_dlg_flag_set("MY_DLG_FLAG")) {
	xlog("dialog flag MY_DLG_FLAG is set\n");
}
...
```


#### store_dlg_value(name,val)


Attaches to the dialog the value from the variable *val*
		under the name *name*. The values attached to dialogs are
		dialog persistent and they can be accessed (read and write) for all
		requests belonging to the dialog.


Parameters:


- *name (string)*
- *val (var)*


NOTE: the dialog must be created before using this function (use
		create_dialog() function before).


Same functionality may be obtain by assigning a value to pseudo
		variable *$dlg_val(name)*.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
			REPLY_ROUTE and FAILURE_ROUTE.


```c title="store_dlg_value usage"
...
store_dlg_value("inv_src_ip",$si);
store_dlg_value("account type",$var(account));
# or
$dlg_val(account_type) = "prepaid";
...
```


#### fetch_dlg_value(name,val)


Fetches from the dialog the value of attribute named
		*name*. The values attached to dialogs are
		dialog persistent and they can be accessed (read and write) for all
		requests belonging to the dialog.


Parameters:


- *name (string)*
- *val (var)*


NOTE: the dialog must be created before using this function (use
		create_dialog() function before).


Same functionality may be obtain by reading the pseudo
		variable *$dlg_val(name)*.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
			REPLY_ROUTE and FAILURE_ROUTE.


```c title="fetch_dlg_value usage"
...
fetch_dlg_value("inv_src_ip",$avp(2));
fetch_dlg_value("account type",$var(account));
# or
$var(account) = $dlg_val(account_type);
...
```


#### set_dlg_sharing_tag(tag_name)


Marks the current dialog with the sharing tag *tag_name*.
		From this point on, actions like in-dialog pinging, BYEs on timeout etc.
		will depend on the tag state(no action in "backup" state, normal operation
		in "active" state).


For more details see the [dialog clustering](#dialog_clustering) chapter.


Parameters:


- *tag_name (string)*


NOTE: the dialog must be created before using this function (use
		create_dialog() function before).


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
			REPLY_ROUTE and FAILURE_ROUTE.


```c title="set_dlg_sharing_tag usage"
...
set_dlg_sharing_tag("vip1");
...
```


#### dlg_on_answer([route_name])


The function arms a script route to be executed when the current
		dialog will be later answered. When the route will be executed, the
		dialog context will be exposed, but with no valid SIP message (just
		a phony one).


You must use this function AFTER creating the dialog and before the
		dialog being answered.


If the parameter is missing, the function does a reset of any route
		previously set; there will be no triggering.


Parameters:


- *route_name (string,optional)* - the name
				of the script route to be executed.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
			REPLY_ROUTE and FAILURE_ROUTE.


```c title="dlg_on_answer usage"
...
create_dialog();
dlg_on_answer("dlg_answered");
...
route[dlg_answered] {
	xlog("The dialog $DLG_did was answered\n");
}
```


#### dlg_on_timeout([route_name])


The function arms a script route to be executed when (and if) the 
		current dialog will timeout (as duration). When the route will be 
		executed, the dialog context will be exposed, but with no valid SIP
		message (just a phony one)


When the route is executed, the dialog is not yet terminated, just its
		lifetime reached the set limit. In the timeout route you can increase 
		the dialog expiration timeout (and the dialog will continue) or you
		can let the dialog to be terminated (after the end of this route).


You must use this function AFTER creating the dialog and before the
		dialog being answered.


You must use this function AFTER creating the dialog and before the
		dialog being answered.


Parameters:


- *route_name (string,optional)* - the name
				of the script route to be executed.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
			REPLY_ROUTE and FAILURE_ROUTE.


```c title="dlg_on_timeout usage"
...
create_dialog();
$DLG_timeout=120;
dlg_on_timeout("dlg_timeout");
...
route[dlg_timeout] {
	xlog("The dialog $DLG_did timed out\n");
	if (_some_prolongation_condition)
		$DLG_timeout = 60; # give it 1 min more
}
```


#### dlg_on_hangup([route_name])


The function arms a script route to be executed when the current
		dialog will be terminated. When the route will be executed, the
		dialog context will be exposed, but with no valid SIP message (just
		a phony one). Note that the dialog will be already terminated and there
		is nothing you can do about it besides reading data from its context.


You must use this function AFTER creating the dialog and before the
		dialog being answered.
		
		If the parameter is missing, the function does a reset of any route
		previously set; there will be no triggering.


Parameters:


- *route_name (string,optional)* - the name
				of the script route to be executed.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
			REPLY_ROUTE and FAILURE_ROUTE.


```c title="dlg_on_hangup usage"
...
create_dialog();
dlg_on_hangup("dlg_hangup");
...
route[dlg_hangup] {
	xlog("The dialog $DLG_did terminated after $DLG_lifetime secs\n");
}
```


#### dlg_send_sequential(method, leg, [, body] [, content-type] [, headers])


Used to send an in-dialog request towards one if the dialog's legs.
		The function assumes that is runs inside a dialog context - if you
		are running it from a different context (such as an event_route),
		make sure you first load the dialog context using the
			[load dialog ctx](#func_load_dialog_ctx) function.


Parameters:


- *method (string)* -
				the method of the request sent.
- *leg (string)* - the leg
				where the request is sent. Must be either
				*caller* or *callee*.
- *body (string, optional)* - an
				optional body sent in the request. If missing, no body is sent.
- *content-type (string, optional)* -
				the content type of the body sent. Make sure you specify this
				every time you send a request with a body, otherwise there are high
				changes that your UAC will reject the request.
- *headers (string, optional)* -
				additional headers attached to the request sent.


This function can be used from ANY route.


```c title="dlg_send_sequential usage to convert DTMF codes"
...
event_route[E_RTPPROXY_DTMF] {
    if (load_dialog_ctx("$param(id)", "did")) {
        if ($param(stream) == 0) {
            $var(direction) = "callee";
        } else {
            $var(direction) = "caller";
        }
        dlg_send_sequential($var(direction), "INFO",
                "Signal=$param(digit)\nDuration=160",
                "application/dtmf-relay");
        unload_dialog_ctx();
    }
}
...
```


#### dlg_inc_cseq([tag, ][inc])


Increments the dialog's generated CSeq associated to the leg
		identified by the dialog's tag.


Parameters:


- *tag (string, optional)* -
			the tag to increment the CSeq value for. If missing, the
			message's *To* tag is used to identify
			the leg to increment the CSeq for.
- *inc (integer, optional)* - the
			value used to increment/decrement (if negative) the CSeq of
			the identified leg. If not used, the value is incremented with
			*1*.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			ONREPLY_ROUTE, BRANCH_ROUTE and LOCAL_ROUTE routes.


```c title="dlg_inc_cseq usage"
...
route {
	...
	if (has_totag()) {
		if (loose_route())
			dlg_inc_cseq(); # increment upstream CSeq after each in-dialog request
	}
}
...
```


### Exported Statistics


#### active_dialogs


Returns the number of current active dialogs (may be confirmed or
			not).


#### early_dialogs


Returns the number of early dialogs.


#### processed_dialogs


Returns the total number of processed dialogs (terminated,
			expired or active) from the startup.


#### expired_dialogs


Returns the total number of expired dialogs from the startup.


#### failed_dialogs


Returns the number of failed dialogs ( dialogs were
			never established due to whatever reasons - internal error,
			negative reply, cancelled, etc )


#### create_sent


Returns the number of replicated dialog
			**create** requests send to other OpenSIPS
			instances.


#### update_sent


Returns the number of replicated dialog
			**update** requests send to other OpenSIPS
			instances.


#### delete_sent


Returns the number of replicated dialog
			**delete** requests send to other OpenSIPS
			instances.


#### create_recv


Returns the number of dialog
			**create** events received from other
			OpenSIPS instances.


#### update_recv


Returns the number of dialog
			**update** events received from other
			OpenSIPS instances.


#### delete_recv


Returns the number of dialog
			**delete** events received from other
			OpenSIPS instances.


### Exported MI Functions


#### dialog:list


Replaces obsolete MI command: *dlg_list*.


Lists the description of the dialogs (calls). If no parameter is given,
		all dialogs will be listed. If a dialog identifier is passed
		as parameter (callid and fromtag), only that dialog will be listed. If
		a index and conter parameter is passed, it will list only a number of
		"counter" dialogs starting with index (as offset) - this is used to
		get only section of dialogs.


Name: *dialog:list*


Parameters (with dialog idetification):


- *callid* (optional) - callid if a single
				dialog to be listed.
- *from_tag* (optional, but cannot be present
				without the callid parameter) - fromtag (as per initial request)
				of the dialog to be listed.
				entry


Parameters (with dialog counting):


- *index* - offset where the dialog listing
				should start.
- *counter* - how many dialogs should be
				listed (starting from the offset)


MI FIFO Command Format:


```c
		## list all ongoing dialogs
		opensips-cli -x mi dialog:list
		## list the dialog by callid and From TAG
		opensips-cli -x mi dialog:list callid=abcdrssfrs122444@192.168.1.1 from_tag=AAdfeEFF33
		## list 10 dialogs, starting from the position 40
		## (in the list of all ongoing dialogs)
		opensips-cli -x mi dialog:list index=40 counter=10
		
```


#### dialog:list_ctx


Replaces obsolete MI command: *dlg_list_ctx*.


The same as the "dialog:list" but including in the
		dialog description
		the associated context from modules sitting on top of
		the dialog module.
		This function also prints the dialog's values. In case of
		binary values, the non-printable chars are represented in hex
		(e.g. \x00)


Name: *dialog:list_ctx*


Parameters: *see "dialog:list"*


MI FIFO Command Format:


```c
		opensips-cli -x mi dialog:list_ctx
		
```


#### dialog:end_dlg


Replaces obsolete MI command: *dlg_end_dlg*.


Terminates an ongoing dialog.
				If dialog is established, BYEs are sent in both directions.
				If dialog is in unconfirmed or early state, a CANCEL will be
				sent to the callee side, that will trigger a 487 from the
				callee, which, when relayed, will also end the dialog on 
				the caller's side.


Name: *dialog:end_dlg*


Parameters are:


- *dialog_id* - this is an identifier
				of the dialog - it can be either (1) the unique ID 
				of the dialog (as provided by dialog:list), either (2) the 
				SIP Call-ID of the dialog.
- *extra_hdrs* - (optional) string containg
				the extra headers (full format) to be added to the BYE
				requests.


The "dialog_id" value can be get via the "dialog:list" MI command.


MI FIFO Command Format:


```c
		# terminate the dialog via the internal Dialog-ID
		opensips-cli -x mi dialog:end_dlg 6ae.4b38d013
		# terminate the dialog via its SIP Call-ID
		opensips-cli -x mi dialog:end_dlg Y2IwYjQ2YmE2ZDg5MWVkNDNkZGIwZjAzNGM1ZDY
		
```


#### dialog:profile_get_size


Replaces obsolete MI command: *profile_get_size*.


Returns the number of dialogs belonging to a profile. If the profile
		supports values, the check can be reinforced to take into account a
		specific value - how many dialogs were inserted into the profile with
		a specific value. If not value is passed, only simply belonging of the
		dialog to the profile is checked. Note that the profile does not
		supports values, this will be silently discarded.


Name: *dialog:profile_get_size*


Parameters:


- *profile* - name of the profile to get the
				value for.
- *value* (optional)- string value to
				toughen the check;


MI FIFO Command Format:


```c
		opensips-cli -x mi dialog:profile_get_size inboundCalls
		
```


#### dialog:profile_list_dlgs


Replaces obsolete MI command: *profile_list_dlgs*.


Lists all the dialogs belonging to a profile. If the profile
		supports values, the check can be reinforced to take into account a
		specific value - list only the dialogs that were inserted into the
		profile with that specific value. If not value is passed, all dialogs
		belonging to the profile will be listed. Note that the profile does
		not supports values, this will be silently discarded. Also, when using
		shared profiles using the CacheDB interface, this command will only
		display the local dialogs.


Name: *dialog:profile_list_dlgs*


Parameters:


- *profile* - name of the profile to list the
				dialog for.
- *value* (optional)- string value to
				toughen the check;


MI FIFO Command Format:


```c
		opensips-cli -x mi dialog:profile_list_dlgs inboundCalls
		
```


#### dialog:profile_get_values


Replaces obsolete MI command: *profile_get_values*.


Lists all the values belonging to a profile along with their
		count. If the profile does not support values a total count
		will be returned. Note that this function does not work for shared
		profiles over the CacheDB interface.


Name: *dialog:profile_get_values*


Parameters:


- *profile* - name of the profile to list the
				dialog for.


MI FIFO Command Format:


```c
		opensips-cli -x mi dialog:profile_get_values inboundCalls
		
```


#### dialog:profile_end_dlgs


Replaces obsolete MI command: *profile_end_dlgs*.


Terminate all ongoing dialogs from a specified profile, on a single dialog it
		performs the same operations as the command **[mi end dlg](#mi_end_dlg)**


Name: *dialog:profile_end_dlgs*


Parameters:


- *profile* - name of the profile that will have its dialogs termianted
- *value* - (optional) if the profile supports values terminate only the dialogs
				with the specified value


MI FIFO Command Format:


```c
		opensips-cli -x mi dialog:profile_end_dlgs inboundCalls
		
```


#### dialog:db_sync


Replaces obsolete MI command: *dlg_db_sync*.


Will load all the information about the dialogs from the database
		in the OpenSIPS internal memory. If a dialog is already found in memory
		and has the same/an older state, it will be updated with the values from
		DB. Otherwise, the newer in-memory version will not be changed.


Name: *dialog:db_sync*


It takes no parameters


MI FIFO Command Format:


```c
		opensips-cli -x mi dialog:db_sync
		
```


#### dialog:cluster_sync


Replaces obsolete MI command: *dlg_cluster_sync*.


This command will only take effect if dialog replication is enabled.


Fully synchronize the dialog information in memory from a suitable donor
		node within the [dialog replication cluster](#param_dialog_replication_cluster). Dialogs
		that already exist in memory which are not reconfirmed through syncing will
		be discarded. A sharing tag can be specified in order to sync only dialogs
		marked with that sharing tag.


Name: *dialog:cluster_sync*


Parameters:


- *sharing_tag* - name of the sharing tag that
				dialogs have to be marked with in order to be synced


MI FIFO Command Format:


```c
		opensips-cli -x mi dialog:cluster_sync vip1
		
```


#### dialog:restore_db


Replaces obsolete MI command: *dlg_restore_db*.


Restores the dialog table after a potential desynchronization event.
		The table is truncated, then populated with CONFIRMED dialogs from memory.


Name: *dialog:restore_db*


It takes no parameters


MI FIFO Command Format:


```c
		opensips-cli -x mi dialog:restore_db
		
```


#### dialog:list_all_profiles


Replaces obsolete MI command: *list_all_profiles*.


Lists all the dialog profiles, along with 1 or 0 if
		the given profile has/does not have an associated value.


Name: *dialog:list_all_profiles*


Parameters: *It takes no parameters*


MI FIFO Command Format:


```c
		opensips-cli -x mi dialog:list_all_profiles
		
```


#### dialog:push_var


Replaces obsolete MI command: *dlg_push_var*.


Push or update a dialog value for the given list of dialog IDs / Call-IDs.


Name: *dialog:push_var*


Parameters: *It takes 3 or more parameters*


- *dlg_val_name* - name of the dialog value that needs to be inserted/updated
- *dlg_val_value* - value to be inserted/updated
- *DID* - dialog identifier. Can be either the $DLG_did or the actual Call-ID.


MI FIFO Command Format:


```c
		opensips-cli -x mi dialog:push_var var_name var_value DID1 [ DID2 DID3 ...  DIDN ]
		
```


#### dialog:send_sequential


Replaces obsolete MI command: *dlg_send_sequential*.


Sends a sequential request within an ongoing dialog.


Name: *dialog:send_sequential*


Parameters:


- *callid* - the callid of the dialog you need to trigger
					the sequential message for.
- *method* - (optional) the method used for the sequential
					message. Default value is *INVITE*.
- *mode* - (optional) can be used to tune the behavior of
					the sequential message. Possible values for the *mode* are:
				
					*caller* - (default) sends the sequential message
						to the caller. This mode can be useful in high availability scenarios
						when you want to update the upstream's routing set, specifically the contact.
					*callee* - same as caller, but sends the sequential
							message to the callee.
					*challenge* - sends a sequential INVITE (or UPDATE)
						to the caller to challenge it for its advertised SDP body. When the
						body is received, it is forwarded to the callee. This mode is useful
						when trying to change both endpoints (upstream and downstream) routing
						set. It can also be useful when trying to trigger a re-negotiation for
						SDP body.
					*challenge-caller* - same as *challenge*
					*challenge-callee* - same as
							*challenge-caller*, only that it first challenges
							the callee, instead of the caller.
- *body* - (optional) can be used to specify a body for
					the initial sequential message. Possible values for the *body*
					parameter are:
				
					*none* - (default) no body added to the sequential message.
					*inbound* - advertises in the body of the sequential
							message generated the last body received from its pair. For example,
							if the *mode=challenge-caller*, the message will
							contain the body sent to OpenSIPS by the callee. This is useful when
							you need to alter the body previously sent to the caller, because you
							want to re-negotiate a different media proxy for the call. This can
							be achieved by catching the generated request in
							*local_route*, and re-engage the Media proxy.
					*outbound* - advertises in the body of the sequential
							message generated the last body sent to that UAC. For example,
							if the *mode=challenge-caller*, the message will
							contain the last body sent by OpenSIPS to the caller. This is useful
							in a high availability scenario when trying to re-negotiate the
							contact of the server, but there is no need to alter the body sent
							earlier.
					*custom:CONTENT_TYPE:BODY* - this can be used to
								specify a specific Content-Type ehader and body for the
								sequential message generated.
- *headers* - (optional) can be used to specify some headers for
					the initial sequential message.


This functions runs asynchronously and returns the status code and reason
			of the last reply received for either the *challenge* or normal mode.


MI Command Format:


```c
			opensips-cli -x mi dialog:send_sequential \
				callid=5291231-testing@127.0.0.1
		
```


MI Command used to trigger media re-negotiation:


```c
			opensips-cli -x mi dialog:send_sequential \
				callid=5291231-testing@127.0.0.1 \
				mode=challenge \
				body=inbound
		
```


MI Command used to UPDATE the callee's remote Contact after a server failover:


```c
			opensips-cli -x mi dialog:send_sequential \
				callid=5291231-testing@127.0.0.1 \
				mode=challenge-callee \
				body=outbound \
				method=UPDATE
		
```


MI Command used to send REFER to the callee, and add Refer-To header:


```c
			opensips-cli -x mi dialog:send_sequential \
				callid=usR8FlGOSMfCTAIHebHCOQ.. \
				method=REFER \
				body=none \
				mode=callee \
				headers='Refer-To: sip:user@domain:50060'
		
```


#### dialog:set_profile


Replaces obsolete MI command: *set_dlg_profile*.


Set the dialog identified by dialog ID / Call-ID into the given profile ( with optional value and clearing of the old profile values )


Name: *dialog:set_profile*


Parameters: *It takes 2-4 parameters*


- *dlg_id* - dialog ID or Call-ID for the respective dialog
- *profile* - profile name to be set
- *value* - optional, the profile value to be set
- *clear_values* - optional, clear previous values in the profile before setting the new one


MI FIFO Command Format:


```c
		opensips-cli -x mi dialog:set_profile dlg_id=DID profile=my_profile value=my_value clear_values=1
		
```


#### dialog:unset_profile


Replaces obsolete MI command: *unset_dlg_profile*.


Unsets the dialog identified by dialog ID / Call-ID from the given profile (with optional value).


Name: *dialog:unset_profile*


Parameters: *It takes 2-3 parameters*


- *dlg_id* - dialog ID or Call-ID for the respective dialog
- *profile* - profile name to be unset
- *value* - optional, the profile value to be unset. for profiles with value, by omitting this parameter you can now clear all values of the given profile.


MI FIFO Command Format:


```c
		opensips-cli -x mi dialog:unset_profile dlg_id=DID profile=my_profile value=my_value
		
```


### Exported Pseudo-Variables


#### $DLG_count


Returns the number of current active dialogs (may be confirmed or
			not).


#### $DLG_status


Returns the status of the dialog corresponding to the processed
			sequential request. This PV will be available only for sequential
			requests, after doing loose_route().


Value may be:


- *NULL* - Dialog not found.
- *1* - Dialog unconfirmed (created
					but no reply received at all)
- *2* - Dialog in early state (created
					provisional reply received, but no final reply received
					yet)
- *3* - Confirmed by a final reply but
					no ACK received yet.
- *4* - Confirmed by a final reply and
					ACK received.
- *5* - Dialog ended.


#### $DLG_lifetime


Returns the duration (in seconds) of the dialog corresponding to
			the processed sequential request. The duration is calculated from
			the dialog confirmation and the current moment. This PV will be
			available only for sequential requests, after doing loose_route().


NULL will be returned if there is no dialog for the request.


#### $DLG_flags


Returns the dialog flags (as a list of flag names separted by space)
			of the dialog corresponding to the processed sequential request.
			This PV will be available only for sequential requests,
			after doing loose_route().


NULL will be returned if there is no dialog for the request.


#### $DLG_dir


Returns the direction of the request in dialog (as "upstream" string
			if the request is generated by callee or "downstream" string if the
			request is generated by caller) - to be used for sequential request.
			This PV will be available only for sequential requests (not for
			replies), after doing loose_route().


NULL will be returned if there is no dialog for the request.


#### $DLG_did


Returns the id of the dialog corresponding to
			the processed sequential request. The output format is a string
			identical to the one returned by the dialog:list MI function. This PV will be
			available only for sequential requests, after doing loose_route().


NULL will be returned if there is no dialog for the request.


#### $DLG_end_reason


Returns the reason for the dialog termination. It can be
				one of the following :


- *Upstream BYE* - Callee has sent a BYE
- *Downstream BYE* - Caller has sent a BYE
- *Lifetime Timeout* - Dialog lifetime expired
- *MI Termination* - Dialog ended via the MI interface
- *Ping Timeout* - Dialog ended because no reply to option pings
- *ReINVITE Ping Timeout* - Dialog ended because no reply to reinvite pings
- *RTPProxy Timeout* - Media timeout signaled by RTPProxy
- *SIP Race Condition* - SIP Race Condition occurred


NULL will be returned if there is no dialog for the request,
				or if the dialog is not ended in the current context.


#### $DLG_timeout


Used to set the dialog lifetime (in seconds). When read, the variable
				returns the number of seconds until the dialog expires and is destroyed.
				Note that reading the variable is only possible after the dialog is created
				(for initial requests) or after doing loose_route() (for sequential requests).
				Important notice: using this variable with a REALTIME db_mode is very inefficient,
				because every time the dialog value is changed, a database update is done.


NULL will be returned if there is no dialog for the request, otherwise the
				number of seconds until the dialog expiration.


#### $DLG_del_delay


Used to set the dialog deletion delay (in seconds) for the
				current dialog (in a per-call manner). When read, the variable
				returns the number of seconds that were set for the call or
				the default value ( see the
				"delete_delay" - [delete delay](#param_delete_delay))
				module param) for the delete delaying.


The variable must be used when the context of a dialog is
				available in script.


#### $DLG_json


The variable is read-only and exposes a JSON variable containing all the information that the dialog:list MI function contains


NULL will be returned if there is no dialog for the request, otherwise the JSON will be returned.


#### $DLG_ctx_json


The variable is read-only and exposes a JSON variable containing all the information that the dialog:list_ctx MI function contains ( on top of $DLG_json, this will expose the full list of dialog vars and profile links for the current dialog )


NULL will be returned if there is no dialog for the request, otherwise the JSON will be returned.


#### $dlg_val(name)


This is a read/write variable that allows access to the dialog
			attribute named *name*. It can hold a string or
			integer value.


Be sure and use this variable only when having a dialog context 
			(like after create_dialog() or match_dialog() or equivalent).


The variable accepts dynamic names, meaning the name may contain
			other variables.


NULL will be returned if there is no dialog for the request.


### Exported Events


#### E_DLG_STATE_CHANGED


This event is raised when the dialog state is changed.


Parameters:


- *id* - the hex representation of the dialog id.
- *db_id* - the integer representation of the dialog id,
					as it is stored in the database *dlg_id* field.
- *callid* - the callid.
- *from_tag* - the From tag.
- *to_tag* - the To tag.
- *old_state* - the old state of the dialog.
- *new_state* - the new state of the dialog.


## Developer Guide


### Available Functions


#### register_dlgcb (dialog, type, cb, param, free_param_cb)


Register a new callback to the dialog.


Meaning of the parameters is as follows:


- *struct dlg_cell* dlg* - dialog to 
			register callback to. If maybe NULL only for DLG_CREATED callback
			type, which is not a per dialog type.
- *int type* - types of callbacks; more
			types may be register for the same callback function; only 
			DLG_CREATED must be register alone. Possible types:
			
			
				*DLGCB_LOADED* - called when a dialog
				is loaded from the database, or received by a node using the
				cluster replication.
			
			
				*DLGCB_SAVED*
			
			
				*DLG_CREATED* - called when a new 
				dialog is created - it's a global type (not associated to 
				any dialog)
			
			
				*DLG_FAILED* - called when the dialog
				was negatively replied (non-2xx) - it's a per dialog type.
			
			
				*DLG_CONFIRMED* - called when the 
				dialog is confirmed (2xx replied) - it's a per dialog type.
			
			
				*DLG_REQ_WITHIN* - called when the 
				dialog matches a sequential request - it's a per dialog type.
			
			
				*DLG_TERMINATED* - called when the 
				dialog is terminated via BYE, or by the mi dlg_end_dlg command
				- it's a per dialog type.
			
			
				*DLG_EXPIRED* - called when the 
				dialog expires without receiving a BYE - it's a per dialog 
				type. Note that when using replication sharing tags, this
				callback is only executed by the node that has the Active tag.
			
			
				*DLGCB_EARLY* - called when the
				dialog is created in an early state (18x replied) - it's
				a per dialog type.
			
			
				*DLGCB_RESPONSE_FWDED* - called when
				the dialog matches a reply to the initial INVITE request - it's
				a per dialog type.
			
			
				*DLGCB_RESPONSE_WITHIN* - called when
				the dialog matches a reply to a subsequent in dialog request
				- it's a per dialog type.
			
			
				*DLGCB_MI_CONTEXT* - called when the
				mi dlg_list_ctx command is invoked - it's a per dialog type.
			
			
				*DLGCB_DESTROY*
- *dialog_cb cb* - callback function to be 
			called. Prototype is: "void (dialog_cb) 
			(struct dlg_cell* dlg, int type, struct dlg_cb_params * params);
			"
- *void *param* - parameter to be passed to
			the callback function.
- *param_free callback_param_free* - 
			callback function to be called to free the param.
			Prototype is: "void (param_free_cb) (void *param);"


## Frequently Asked Questions


**Q: What happened with "topology_hiding()" 
		function?**


The respective functionality was moved into the topology_hiding module.
			Function prototype has remained the same.


**Q: What happened with "use_tight_match" 
		parameter?**


The parameter was removed with version 1.3 as the option of tight
			matching became mandatory and not configurable. Now, the tight
			matching is done all the time (when using DID matching).


**Q: What happened with "bye_on_timeout_flag" 
		parameter?**


The parameter was removed in a dialog module parameter restructuring.
			To keep the bye on timeout behavior, you need to provide a "B" 
			string parameter to the create_dialog() function.


**Q: What happened with "dlg_flag" 
		parameter?**


The parameter is considered obsolete. The only way to
			create a dialog is to call the create_dialog() function


**Q: Where can I find more about OpenSIPS?**


Take a look at [https://opensips.org/](https://opensips.org/).


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
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
