---
title: "Acc Module"
description: "The ACC module is used to account transaction information to different backends such as syslog, SQL, AAA."
---

## Admin Guide


### Overview


The ACC module is used to account transaction information to different
		backends such as syslog, SQL,
		AAA.


To account a transaction and to choose which set of backends to be
		used, the script writer only has to mark the transaction for
		accounting by using the [do accounting](#func_do_accounting) script function.
		Note that the function is not actually doing the accounting at that
		very time, it is just setting a marker - the actual accounting
		will be done later when the transaction or dialog will be
		completed.


Even so, the module allows the script writer to force accounting on the
		spot in special cases via some other script functions.


The accounting module will log by default a fixed set of attributes
		for the transaction - if you customize your accounting by adding more
		information to be logged, please see the next chapter about extra
		accounting - [ACC extra id](#extra_accounting).


The fixed minimal accounting information is:


- Request Method name
- From header TAG parameter
- To header TAG parameter
- Call-Id
- 3-digit Status code from final reply
- Reason phrase from final reply
- Timestamp when transaction was completed


If a value is not present in the request, the empty string is accounted
		instead.


Note that:


- A single INVITE may produce multiple accounting reports -- that's
			most likely due to the SIP forking feature.
- Since version 2.2, all flags used for accounting have been replaced
			with the do_accounting() function. No need to worry anymore whether
			you have set the flags or not, or be confused by various flag names,
			now you only have to call the function and it will do all the work
			for you.
- OpenSIPS now supports session/dialog accounting. It can
			automatically correlate INVITEs with BYEs for generating proper CDRs,
			for example for billing purposes.
- If a UA fails in the middle of a conversation, a proxy will never
			find out about it. In general, a better practice is to account from an
			end-device (such as PSTN gateway), which best knows about call
			status (including media status and PSTN status in case of the
			gateway).


The SQL, Event Interface and AAA backend support are compiled in the
		module.


A very comprehensive description of how the accounting module works in
	terms accounting scope, accounting events and accounting backends can
	be found in this online [Advanced Accounting Tutorial](https://docs.opensips.org/tutorials-advanced-accounting).


#### General Example


```c
loadmodule "modules/acc/acc.so"

if ($ru=~"sip:+40") /* calls to Romania */ {
    if (!proxy_authorize("sip_domain.net" /* realm */,
    "subscriber" /* table name */))  {
        proxy_challenge("sip_domain.net" /* realm */, "0" /* no qop */ );
        exit;
    }

    if (is_method("INVITE") && $au!=$fU) {
        xlog("FROM URI != digest username\n");
        sl_send_reply(403,"Forbidden");
    }

    do_accounting("log"); /* set for accounting via syslog */
    t_relay(); /* enter stateful mode now */
};
```


### Extra accounting


#### Overview


Along the static default information, the ACC module
			allows dynamic selection of extra information to be logged using
			the acc_extra pseudovariable. This allows you to log any
			pseudo-variable (AVPs, parts of the request, parts of the reply, etc).


#### Definitions and syntax


Selection of extra information is done via
			*extra_field* parameter by specifying tags
			and log_names for the additional information. This information is
			defined via acc_extra pseudovariable, referenced with the define
			tag. If the tag is not specified, its value will be considered
			to be the same as the log_value. Accounting backend(log, db, aaa, evi)
			is specified at the beginning of the definition, separated by ':' from
			the rest. The syntax of the parameter is:


- *backend : tag -> log_name (';'tag -> log_name)**
- *backend : tag (';' tag)**


Extra values are consistent during the whole call. Setting a
			value during a request, will cause it to remain visible during all replies. Also,
			concerning CDR logging, setting a value on the initial INVITE will
			result in having that value throughout the dialog.


Via *log_name* you define how/where the
			*data* will be logged. Its meaning depends
			of the accounting support which is used:


- *LOG accounting* - log_name
				will be just printed along with the data in *log_name=data* format;
- *DB accounting* - log_name
				will be the name of the DB column where the data will be
				stored.*IMPORTANT*: add in db
				*acc* table the columns corresponding to
				each extra data;
- *AAA accounting* -
				log_name will be the AVP name used for packing the data into
				AAA message. The log_name will be translated to AVP number
				via the dictionary. *IMPORTANT*: add in
				AAA dictionary the *log_name* attribute.
- *Events accounting* -
				log_name will be the name of the parameter in the event raised.


#### How it works


Declaring an extra in the format of


```c
modparam("acc", "extra_fields", "log: a -> test_a")
```


will enable you to set the value for *test_a* field
				of the log only by setting *$acc_extra(a)* variable.
				Otherwise, the field shall be logged with no value(null).


#### Radius accounting dependencies


If radius accounting is used, except from a radius client library which is mandatory,
				**dictionary.rfc2866** must be included for the module
				to work properly.


### Multi Call-Legs accounting


#### Overview


A SIP call can have multiple legs due forwarding actions. For
			example user A calls user B which forwards the call to user C.
			There is only one SIP call but with 2 legs ( A to B and B to C).
			Accounting the legs of a call is required for proper billing of
			the calls (if C is a PSTN number and the call is billed, user B
			must pay for the call - as last party modifing the call
			destination-, and not A - as initiator of the call. Call
			forwarding on server is only one example which shows the
			necessity of the having an accounting engine with multiple legs
			support.


#### Configuration


First how it works: The idea is to have a variable to store
			a set of values for each leg. The meaning of
			the variable content is strictly decided by the script writer - it can
			be the origin and source of the leg, its status or any other
			related information. By default there is defined only one leg. Script
			writer has to decide when is the time to create a new leg, by using
			*acc_new_leg()* script function. When creating a new
			leg, all the values for that leg will be set to NULL by default.


When the accounting information for the call will be written/sent,
			all the call-leg pairs will be added.


By default, the multiple call-leg support is disabled - it can be
			enabled just by setting *acc_leg* variable
			`leg_fields` module parameter. Note that
			the last one only makes sense only for CDRs that are generated
			automatically by OpenSIPS.


#### Logged data


For each call, all the values from the *acc_leg*
				variable will be logged. How the information will be actually
			logged, depends of the data backend:


- *syslog* -- all leg-sets will be added
				to one record string as acc_leg(leg1)=xxx, acc_leg(leg2)=xxxx ,... sets.
- *database* -- each pair will be
				separately logged (due DB data structure constraints); several
				records will be written, the difference between them being
				only the fields corresponding to the call-leg info.

  > **Note:** You will need to add in your DB (all acc related
				tables) the colums for call-leg info (a column for each leg value
				of the set).
- *AAA* -- all sets will be added
				to the same AAA accounting message as AAA AVPs - for each
				call-leg a set of AAA AVPs will be added (corresponding
				to the per-leg set)

  > **Note:** You will need to add in your dictionary the
				AAA AVPs used in call-leg set definition.
- *events* -- each pair will appear as a
				different parameter-value pair in the event. Similar to the
				database behavior, multiple events will be raised, and the only
				difference between them is the leg information.


*Important!!!* In order to use *RADIUS*,
				one must include the AVPs which are located in
				$(opensips_install_dir)/etc/dictionary.opensips, both in opensips radius config
				script dictionary and radius server dictionary. Most important are the last three
				AVPs (IDs : 227, 228, 229) which you won't find in any SIP dictionary
				(at least at this moment) because they are only used in openSips.


### CDRs accounting


#### Overview


ACC module can now also maintain session/dialog accounting. This
			allows you to log useful information like call duration, call
			start time and setup time.


#### Configuration


In order to have CDRs accounting, first you need to set the
			*cdr* flag when calling
			[do accounting](#func_do_accounting) script function for the
			initial INVITE of the dialog.


#### How it works


This type of accounting is based on the dialog module. When
			an initial INVITE is received, if the *cdr*
			flag is set, then the dialog creation time is saved. Once the call is
			answered and the ACK is received, other information like extra values
			or leg values are saved. When the corresponding BYE is received,
			the call duration is computed and all information is stored to
			the desired backend.


### Dependencies


#### OpenSIPS Modules


The module depends on the following modules (in the other words
			the listed modules must be loaded before this module):


- *tm* -- Transaction Manager
- *a database module* -- If SQL
				support is used.
- *rr* -- Record Route, if
				"detect_direction" module parameter is enabled.
- *an aaa module*
- *dialog* -- Dialog, if
				"cdr" option is used


#### External Libraries or Applications


The following libraries or applications must be installed
			before running OpenSIPS with this module loaded:


- none.


### Exported Parameters


#### early_media (integer)


Should be early media (any provisional reply with body) accounted too ?


Default value is 0 (no).


```c title="early_media example"
modparam("acc", "early_media", 1)
```


#### report_cancels (integer)


By default, CANCEL reporting is disabled -- most accounting
		applications wants to see INVITE's cancellation status.
		Turn on if you explicitly want to account CANCEL transactions.


Default value is 0 (no).


```c title="report_cancels example"
modparam("acc", "report_cancels", 1)
```


#### detect_direction (integer)


Controls the direction detection for sequential requests. If
		enabled (non zero value), for sequential requests with upstream
		direction (from callee to caller), the FROM and TO will be swapped
		(the direction will be preserved as in the original request).


It affects all values related to TO and FROM headers (body, URI,
		username, domain, TAG).


Default value is 0 (disabled).


```c title="detect_direction example"
modparam("acc", "detect_direction", 1)
```


#### extra_fields (string)


Defines the tag-log_value set to be used in extra fields accounting.
		See [ACC extra id](#extra_accounting) for a
		detailed description of the Extra accounting.


If empty, extra accounting support will be disabled.


Default value is 0 (disabled).


```c title="Setting *extra_fields* example:"
# for syslog-based accounting, use any text you want to be printed
# if setting $acc_extra(a) you will see "My_a_Field=<value> in logs
# if setting $acc_extra(b) you will see "b=<value> in logs
modparam("acc", "extra_fields", "log: a->My_a_Field; b")
# for mysql-based accounting, use the names of the columns
# $acc_extra(a) = <value>  results in setting col_a with <value> in db
modparam("acc", "extra_fields", "db: a->col_a; col_b")
# for AAA-based accounting, use the names of the AAA AVPs
modparam("acc", "extra_fields","aaa:a->AAA_SRC;b->AAA_DST")
# evi definition example
modparam("acc", "extra_fields","a->2345;b->2346")
```


#### leg_fields (string)


Defines the tag-log_value set to be used in multi-leg accounting.
		See [multi call legs](#multi_call_legs_accounting) for a
		detailed description of the Multi Call-Legs accounting.


If empty, multi-leg accounting support will be disabled.


Default value is 0 (disabled).


```c title="Setting *leg_fields* example:"
# for syslog-based accounting, use any text you want to be printed
# if setting $(acc_leg(a)[0]) you will see "My_a_Field=<value> in logs
# if setting $(acc_leg(b)[0]) you will see "b=<value> in logs
modparam("acc", "leg_fields", "log: a->My_a_Field; b")
# for mysql-based accounting, use the names of the columns
# $acc_leg(a) = <value>  results in setting col_a with <value> in db
modparam("acc", "leg_fields", "db: a->col_a; col_b")
# for AAA-based accounting, use the names of the AAA AVPs
modparam("acc", "leg_fields","aaa:a->AAA_LEG_SRC;b->AAA_LEG_DST")
# evi definition example
modparam("acc", "leg_fields","a->2345;b->2346")
```


#### log_level (integer)


Log level at which accounting messages are issued to syslog.


Default value is L_NOTICE.


```c title="log_level example"
modparam("acc", "log_level", 2)   # Set log_level to 2
```


#### log_facility (string)


Log facility to which accounting messages are issued to syslog.
		This allows to easily seperate the accounting specific logging
		from the other log messages.


Default value is LOG_DAEMON.


```c title="log_facility example"
modparam("acc", "log_facility", "LOG_DAEMON")
```


#### aaa_url (string)


This is the url representing the AAA protocol used and the location of the configuration file of this protocol.


If the parameter is set to empty string, the AAA accounting support
		will be disabled.


Default value is "NULL".


```c title="Set aaa_url parameter"
...
modparam("acc", "aaa_url", "radius:/etc/radiusclient-ng/radiusclient.conf")
...
```


#### service_type (integer)


AAA service type used for accounting.


Default value is not-set.


```c title="service_type example"
# Default value of service type for SIP is 15
modparam("acc", "service_type", 15)
```


#### db_table_acc (string)


Table name of accounting successful calls -- database specific.


Default value is "acc"


```c title="db_table_acc example"
modparam("acc", "db_table_acc", "myacc_table")
```


#### db_table_missed_calls (string)


Table name for accounting missed calls -- database specific.


Default value is "missed_calls"


```c title="db_table_missed_calls example"
modparam("acc", "db_table_missed_calls", "myMC_table")
```


#### db_url (string)


SQL address -- database specific. If is set to NULL or empty string,
		the SQL support is disabled.


Default value is "NULL" (SQL disabled).


```c title="db_url example"
modparam("acc", "db_url", "mysql://user:password@localhost/opensips")
```


#### acc_method_column (string)


Column name in accounting table to store the request's method name as
		string.


Default value is "method".


```c title="acc_method_column example"
modparam("acc", "acc_method_column", "method")
```


#### acc_from_tag_column (string)


Column name in accounting table to store the From header TAG parameter.


Default value is "from_tag".


```c title="acc_from_tag_column example"
modparam("acc", "acc_from_tag_column", "from_tag")
```


#### acc_to_tag_column (string)


Column name in accounting table to store the To header TAG parameter.


Default value is "to_tag".


```c title="acc_to_tag_column example"
modparam("acc", "acc_to_tag_column", "to_tag")
```


#### acc_callid_column (string)


Column name in accounting table to store the request's Callid value.


Default value is "callid".


```c title="acc_callid_column example"
modparam("acc", "acc_callid_column", "callid")
```


#### acc_sip_code_column (string)


Column name in accounting table to store the final reply's numeric code
		value in string format.


Default value is "sip_code".


```c title="acc_sip_code_column example"
modparam("acc", "acc_sip_code_column", "sip_code")
```


#### acc_sip_reason_column (string)


Column name in accounting table to store the final reply's reason
		phrase value.


Default value is "sip_reason".


```c title="acc_sip_reason_column example"
modparam("acc", "acc_sip_reason_column", "sip_reason")
```


#### acc_time_column (string)


Column name in accounting table to store the time stamp of the
		transaction completion in date-time format.


Default value is "time".


```c title="acc_time_column example"
modparam("acc", "acc_time_column", "time")
```


### Exported Pseudo-Variables


#### $acc_extra(tag_name)


This variable can addresed with the tag names defined
			using [extra fields](#param_extra_fields). If
			[do accounting](#func_do_accounting) isn't called, this
			variable is visible during the whole processing of one message,
			enabling calling *acc_XXX_request()*.
			If [do accounting](#func_do_accounting) is called, the variable
			will be visible from the first call of this function until the
			actual accounting is being made.


#### $(acc_leg(tag_name)[leg_index])


This variable can be addressed with the tag names defined
			using [leg fields](#param_leg_fields) and  a valid leg index
			(<= [acc current leg](#pv_acc_current_leg)). This variable cannot
			be used unless [do accounting](#func_do_accounting) is used. The
			variable also accepts negative indexes, which start from -1
			(the lastly added leg).


```c
# the "caller" value of the current leg
$acc_leg(caller)

# the "caller" value of the lastly added leg
$(acc_leg(caller)[-1]) # equivalent to $acc_leg(caller)
                       # equivalent to $(acc_leg(caller)[$acc_current_leg])

# the "caller" value of the next-to-last leg
$(acc_leg(caller)[-2])
```


#### $acc_current_leg (read-only)


Holds the index of the current leg, starting from 0.  Calling
			[acc new leg](#func_acc_new_leg) will increment this index.


### Exported Functions


#### do_accounting(type, [flags], [table])


`do_accounting()` replaces all the
			*_flag and, *_missed_flag, cdr_flag, failed transaction_flag and the
			db_table_avp modparams. Just call do_accounting(), select where and how you want
			the accounting to take place, and the function will do all the work for you.


When called multiple times, the function behaves *additively*.


Meaning of the parameters is as follows:


- *type (string)* - the type of accounting you want to do.
			All types have to be separated by '|'. The following parameters can
			be used:

  - *log* - syslog accounting;
  - *db* - database accounting;
  - *aaa* - aaa specific accounting;
  - *evi* - Event Interface accounting;
- *flags (string, optional)* - flags for the accounting type you have
			selected. All the types have to be separated by '|'. The following
			parameters can be used:

  - *cdr* - enables dialog-level accounting.
						OpenSIPS will internally detect dialog termination (generation/receipt
						of a BYE request), and store the CDR as soon as the BYE request
						is replied to. By enabling the "cdr" flag, the following additional
						fields will be populated: duration, ms_duration, setuptime, created.
						 (requires dialog module support)
  - *missed* - log missed calls; take care
						that this flag will be deactivated after the first missed call;
						you will have to reactivate it in the
						*failure_route* if you want to account
						each destination that did not respond to the call;
  - *failed* -  flag which indicates if the
						transaction should also be accounted in case
						of failure (status>=300);
- *table (string, optional)* - table where to do the accounting;
			it replaces old table_avp parameter;


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE and LOCAL_ROUTE.


```c title="do_accounting usage"
		...
		if (!has_totag()) {
			if (is_method("INVITE")) {
			/* enable cdr and missed calls accounting in the database
			 * and to syslog; db accounting shall be done in "my_acc" table */
				do_accounting("db|log", "cdr|missed", "my_acc");
			}
		}
		...
		if (is_method("BYE")) {
			/* do normal accounting via aaa */
			do_accounting("aaa");
		}
		...
		
```


#### drop_accounting([type], [flags])


`drop_accounting()` resets flags
			and types of accounting set with do_accounting(). If called with no
			arguments all accounting will be stopped. If called with only one argument
			all accounting for that type will be stopped. If called with two arguments
			normal accounting will still be enabled.


When called multiple times, the function behaves *additively*.


Meaning of the parameters is as follows:


- *type (string, optional)* - the type of accounting you want to stop.
			All the types have to be separated by '|'. The following parameters can
			be used:

  - *log* - stop syslog accounting;
  - *db* - stop database accounting;
  - *aaa* - stop aaa specific accounting;
  - *evi* - stop Event Interface accounting;
- *flags (string, optional)* - flags to be reset for the accouting type you have
			selected. All the types have to be separated by '|'. The following
			parameters can be used:

  - *cdr* - stop CDR accounting;
  - *missed* - stop logging missed calls;
  - *failed* -  stop failed transaction accounting;


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE and LOCAL_ROUTE.


```c title="drop_accounting usage"
		...
		acc_log_request("403 Destination not allowed");
		if (!has_totag()) {
			if (is_method("INVITE")) {
			/* enable cdr and missed calls accounting in the database
			 * and to syslog; db accounting shall be done in "my_acc" table */
				do_accounting("db|log", "cdr|missed", "my_acc");
			}
		}
		...
		/* later in your script */
		if (...) { /* you don't want accounting anymore */
			/* stop all syslog accounting */
			drop_accounting("log");
			/* or stop missed calls and cdr accounting for syslog;
			 * normal accounting will still be enabled */
			drop_accounting("log", "missed|cdr");
			/* or stop all types of accounting  */
			drop_accounting();
		}
		...
		
```


#### acc_log_request(comment)


`acc_request` reports on a request,
		for example, it can be used to report on missed calls to off-line users
		who are replied 404 - Not Found. To avoid multiple reports on UDP
		request retransmission, you would need to embed the
		action in stateful processing.


Meaning of the parameters is as follows:


- *comment (string)* - Comment describing how the
			request completed - this string has to contain a reply code
			followed by a reply reason phrase (ex: "480 Nobody Home"). Variables
			are accepted in this string.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE and LOCAL_ROUTE.


```c title="acc_log_request usage"
...
acc_log_request("403 Destination not allowed");
...
```


#### acc_db_request(comment, table)


Like `acc_log_request`,
		`acc_db_request` reports on a
		request. The report is sent to database at "db_url", in
		the table referred to in the second action parameter.


Meaning of the parameters is as follows:


- *comment (string)* - Comment describing how the
			request completed - this string has to contain a reply code
			followed by a reply reason phrase (ex: "480 Nobody Home"). Variables
			are accepted in this string.
- *table (string)* - Database table to be used.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE and LOCAL_ROUTE.


```c title="acc_db_request usage"
...
acc_db_request("Some comment", "Some table");
acc_db_request("$T_reply_code $(<reply>rr)", "acc");
...
```


#### acc_aaa_request(comment)


Like `acc_log_request`,
		`acc_aaa_request` reports on
		a request. It reports to aaa server as configured in
		"aaa_url".


Meaning of the parameters is as follows:


- *comment (string)* - Comment describing how the
			request completed - this string has to contain a reply code
			followed by a reply reason phrase (ex: "404 Nobody home"). Variables
			are accepted in this string.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE and LOCAL_ROUTE.


```c title="acc_aaa_request usage"
...
acc_aaa_request("403 Destination not allowed");
...
```


#### acc_evi_request(comment)


Like `acc_log_request`,
		`acc_evi_request` reports on a
		request. The report is packed as an event sent through the OpenSIPS Event
		Interface as *E_ACC_EVENT* if the reply code is a
		positive one (lower than 300), or *E_ACC_MISSED_EVENT*
		for negative or no codes. More information on this in
		[exported events](#exported_events).


Meaning of the parameters is as follows:


- *comment (string)* - Comment describing how the
			request completed - this string has to contain a reply code
			followed by a reply reason phrase (ex: "404 Nobody home")


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE and LOCAL_ROUTE.


```c title="acc_evi_request usage"
...
acc_evi_request("403 Destination not allowed");
...
```


#### acc_new_leg()


Creates a new leg and increments [acc current leg](#pv_acc_current_leg)
			only if multi-leg accounting is used.  All values of the new leg
			will be initialized to null.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE and LOCAL_ROUTE.


```c title="acc_new_leg usage"
...
	acc_new_leg();
...
```


#### acc_load_ctx_from_dlg()


The function loads and exposes the accounting context of the
			currently in-use dialog. By dialog context, it means, from script
			level, you will read/write the accounting variables from the
			other dialog. The current accounting context is
			stashed until an unload operation is done.


Note that this functions makes sense only when used together with
			the *load_dialog_ctx()* function from the
			dialog module. After loading the context of another dialog, by
			using the *acc_load_ctx_from_dlg()* function,
			you can also access the accounting context of the loaded dialog.


NOTE: you cannot perform a new load until doing an unload - no nested
		loadings are allowed.


This function can be used from any type of route.


```c title="acc_load_ctx_from_dlg usage"
...
if ( load_dialog_ctx("$var(callid)") ) {
	# we now have the dialog context of the new dialog
	acc_load_ctx_from_dlg();
	# we have now also the accouting context of that dialog
	xlog("The accounting caller of call '$var(callid)' "
		"is '$acc_extra(caller)'\n");
	acc_unload_ctx_from_dlg();
	unload_dialog_ctx();
}

...
```


#### acc_unload_ctx_from_dlg()


The function off-loads a previosuly loaded accounting context, exposing
		whatever accounting context was present before doing the load.


NOTE: you MUST perform from script an explicit unload for each load
		you did!


This function can be used from any type of route.


For usage example, see the [acc load ctx from dlg](#func_acc_load_ctx_from_dlg).


### Exported Events


#### E_ACC_CDR


The event raised when a CDR is generated. Note that this event will
			only be triggered if the auto CDR accounting is used.


Parameters:


- *method* - Request method name
- *from_tag* - From header tag parameter
- *to_tag* - To header tag parameter
- *callid* - Message Call-id
- *sip_code* - The status code from the final reply
- *sip_reason* - The status reason from the final reply
- *time* - The timestamp when the call was established
- *evi_extra** - Extra parameters added by
				the *evi_extra* parameter.
- *evi_extra_bye** - Extra parameters added by
				the *evi_extra_bye* parameter
- *multi_leg_info** - Extra parameters added by
				the *multi_leg_info* parameter
- *multi_leg_bye_info** - Extra parameters added by
				the *multi_leg_bye_info* parameter
- *duration* - The call duration in seconds
- *ms_duration* - The call duration in milliseconds
- *setuptime* - The call setup time in seconds
- *created* - The timestamp when the call was
				created (the initial Invite was received)


#### E_ACC_EVENT


This event is triggered when old-style accounting is used. It is
			generated when the requests (INVITE and BYE) transaction have
			positive final replies, or by the `acc_evi_request()`
			function that has a positive reply code in comment.


Parameters:


- *method* - Request method name
- *from_tag* - From header tag parameter
- *to_tag* - To header tag parameter
- *callid* - Message Call-id
- *sip_code* - The status code from the final reply
- *sip_reason* - The status reason from the final reply
- *time* - The timestamp when the transaction was created
- *evi_extra** - Extra parameters added by
				the *evi_extra* parameter
- *multi_leg_info** - Extra parameters added by
				the *multi_leg_info* parameter


#### E_ACC_MISSED_EVENT


This event is triggered when old-style accounting is used. It is
			generated when the requests (INVITE and BYE) transaction have
			negative final replies, or by the `acc_evi_request()`
			function that has a negative reply code in comment.


Parameters:


- *method* - Request method name
- *from_tag* - From header tag parameter
- *to_tag* - To header tag parameter
- *callid* - Message Call-id
- *sip_code* - The status code from the final reply
- *sip_reason* - The status reason from the final reply
- *time* - The timestamp when the transaction was created
- *evi_extra** - Extra parameters added by
				the *evi_extra* parameter
- *multi_leg_info** - Extra parameters added by
				the *multi_leg_info* parameter
- *created* - Timestamp when the call was created
- *setuptime* - The call setup time in seconds


## Frequently Asked Questions


**Q: What happened with old report_ack parameter**


The parameter is considered obsolete. It was removed as acc
			module is doing SIP transaction based accouting and according
			to SIP RFC, end2end ACKs are a different transaction (still part
			of the same dialog). ACKs can be individually accouted as any
			other sequential (in-dialog) request.


**Q: What happened with old log_fmt parameter**


The parameter became obsolete with the restructure of the data
			logged by ACC module (refer to the Overview chapter). For similar
			behaviour you can use the extra accouting (see the corresponding
			chapter).


**Q: What happened with old multi_leg_enabled parameter**


The parameter became obsolete by the addition of the new
			multi_leg_info parameter. The multi-leg accouting is automatically
			enabled when multi_leg_info is defined.


**Q: What happened with old src_leg_avp_id and dst_leg_avp_id
				parameters**


The parameter was replaced by the more generic new parameter
			multi_leg_info. This allows logging (per-leg) of more information
			than just dst and src.


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
