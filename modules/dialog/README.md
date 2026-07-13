---
title: "dialog Module"
description: "The dialog module provides dialog awareness to the OpenSIPS proxy."
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


To create the dialog associated to an initial request, you must call
the create_dialog() function, with or without parameter..


The dialog is automatically destroyed when a "BYE" is 
received. In case of no "BYE", the dialog lifetime is 
controlled via the default timeout (see "default_timeout"
	- [default timeout id](#param_default_timeout)) and custom timeout (see 
"timeout_avp" - [timeout avp id](#param_timeout_avp)). The 
dialog timeout is reset each time a sequential (except ACKs) request 
passes.


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
CacheDB Interface. This feature allows you to share dialog profile
information with multiple OpenSIPS instaces that use the same CacheDB
backend. In order to do that, the *cachedb_url* parameter
must be defined. Also, the profile must be marked as shared, by adding the
*'/s'* suffix to the name of the profile in the
*profiles_with_value* or
*profiles_no_value* parameters.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *TM* - Transaction module
- *RR* - Record-Route module


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


```opensips title="Set enable_stats parameter"
...
modparam("dialog", "enable_stats", 0)
...
```


#### hash_size (integer)


The size of the hash table internally used to keep the dialogs. A 
larger table is much faster but consumes more memory. The hash size
must be a power of 2 number.


> [!IMPORTANT]
> If dialogs' information should be stored in a database, 
> a constant hash_size should be used, otherwise the restored process 
> will not take place. If you really want to modify the hash_size you 
> must delete all table's rows before restarting OpenSIPS.


*Default value is "4096".*


```opensips title="Set hash_size parameter"
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


```opensips title="Set hash_size parameter"
...
modparam("dialog", "log_profile_hash_size", 5) #set a table size of 32
...
```


#### rr_param (string)


Name of the Record-Route parameter to be added with the dialog cookie.
It is used for fast dialog matching of the sequential requests.


*Default value is "did".*


```opensips title="Set rr_param parameter"
...
modparam("dialog", "rr_param", "xyz")
...
```


#### timeout_avp (string)


The specification of an AVP to contain a custom timeout (in seconds)
for the dialog. It may be used only in a request 
(initial or sequential) context.


*Default value is "none".*


```opensips title="Set timeout_avp parameter"
...
modparam("dialog", "timeout_avp", "$avp(10)")
...
```


*Make sure you call this before `loose_route()`.*


#### default_timeout (integer)


The default dialog timeout (in seconds) if no custom one is set.


*Default value is "43200 (12 hours)".*


```opensips title="Set default_timeout parameter"
...
modparam("dialog", "default_timeout", 21600)
...
```


#### dlg_extra_hdrs (string)


A string containing the extra headers (full format, with EOH)
to be added in the requests generated by the module (like BYEs).


*Default value is "NULL".*


```opensips title="Set dlf_extra_hdrs parameter"
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


*Default value is "0 (DID_ONLY)".*


```opensips title="Set dlg_match_mode parameter"
...
modparam("dialog", "dlg_match_mode", 1)
...
```


#### db_url (string)


If you want to store the information about the dialogs in a database 
a database url must be specified.


*Default value is "mysql://opensips:opensipsrw@localhost/opensips".*


```opensips title="Set db_url parameter"
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
changes will be reflected into the database immediatly.
- *2 - DELAYED* - the dialog information 
changes will be flushed into DB periodically, based on a
timre routine.
- *3 - SHUTDOWN* - the dialog information 
will be flushed into DB only at shutdown - no runtime updates.


*Default value is "0".*


```opensips title="Set db_mode parameter"
...
modparam("dialog", "db_mode", 1)
...
```


#### db_update_period (integer)


The interval (seconds) at which to update dialogs' information if you chose to store the dialogs' info at a given interval.
A too short interval will generate intensiv database operations, a too large one will not notice short dialogs.


*Default value is "60".*


```opensips title="Set db_update_period parameter"
...
modparam("dialog", "db_update_period", 120)
...
```


#### ping_interval (integer)


The interval (seconds) at which OpenSIPS will generate in-dialog pings for dialogs.


*Default value is "30".*


```opensips title="Set ping_interval parameter"
...
modparam("dialog", "ping_interval", 20)
...
```


#### table_name (string)


If you want to store the information about the dialogs in a 
database a table name must be specified.


*Default value is "dialog".*


```opensips title="Set table_name parameter"
...
modparam("dialog", "table_name", "my_dialog")
...
```


#### call_id_column (string)


The column's name in the database to store the dialogs' callid.


*Default value is "callid".*


```opensips title="Set call_id_column parameter"
...
modparam("dialog", "call_id_column", "callid_c_name")
...
```


#### from_uri_column (string)


The column's name in the database to store the caller's 
sip address.


*Default value is "from_uri".*


```opensips title="Set from_uri_column parameter"
...
modparam("dialog", "from_uri_column", "from_uri_c_name")
...
```


#### from_tag_column (string)


The column's name in the database to store the From tag from 
the Invite request.


*Default value is "from_tag".*


```opensips title="Set from_tag_column parameter"
...
modparam("dialog", "from_tag_column", "from_tag_c_name")
...
```


#### to_uri_column (string)


The column's name in the database to store the calee's sip address.


*Default value is "to_uri".*


```opensips title="Set to_uri_column parameter"
...
modparam("dialog", "to_uri_column", "to_uri_c_name")
...
```


#### to_tag_column (string)


The column's name in the database to store the To tag from 
the 200 OK response to the Invite request, if present.


*Default value is "to_tag".*


```opensips title="Set to_tag_column parameter"
...
modparam("dialog", "to_tag_column", "to_tag_c_name")
...
```


#### from_cseq_column (string)


The column's name in the database to store the cseq from caller
side.


*Default value is "caller_cseq".*


```opensips title="Set from_cseq_column parameter"
...
modparam("dialog", "from_cseq_column", "from_cseq_c_name")
...
```


#### to_cseq_column (string)


The column's name in the database to store the cseq from callee
side.


*Default value is "callee_cseq".*


```opensips title="Set to_cseq_column parameter"
...
modparam("dialog", "to_cseq_column", "to_cseq_c_name")
...
```


#### from_route_column (string)


The column's name in the database to store the route records from
caller side (proxy to caller).


*Default value is "caller_route_set".*


```opensips title="Set from_route_column parameter"
...
modparam("dialog", "from_route_column", "from_route_c_name")
...
```


#### to_route_column (string)


The column's name in the database to store the route records from
callee side (proxy to callee).


*Default value is "callee_route_set".*


```opensips title="Set to_route_column parameter"
...
modparam("dialog", "to_route_column", "to_route_c_name")
...
```


#### from_contact_column (string)


The column's name in the database to store the caller's contact 
uri.


*Default value is "caller_contact".*


```opensips title="Set from_contact_column parameter"
...
modparam("dialog", "from_contact_column", "from_contact_c_name")
...
```


#### to_contact_column (string)


The column's name in the database to store the callee's contact 
uri.


*Default value is "callee_contact".*


```opensips title="Set to_contact_column parameter"
...
modparam("dialog", "to_contact_column", "to_contact_c_name")
...
```


#### from_sock_column (string)


The column's name in the database to store the information about 
the local interface receiving the traffic from caller.


*Default value is "caller_sock".*


```opensips title="Set from_sock_column parameter"
...
modparam("dialog", "from_sock_column", "from_sock_c_name")
...
```


#### to_sock_column (string)


The column's name in the database to store information about the 
local interface receiving the traffic from callee.


*Default value is "callee_sock".*


```opensips title="Set to_sock_column parameter"
...
modparam("dialog", "to_sock_column", "to_sock_c_name")
...
```


#### dlg_id_column (string)


The column's name in the database to store the dialogs' 
id information.


*Default value is "hash_id".*


```opensips title="Set dlg_id_column parameter"
...
modparam("dialog", "dlg_id_column", "dlg_id_c_name")
...
```


#### state_column (string)


The column's name in the database to store the 
dialogs' state information.


*Default value is "state".*


```opensips title="Set state_column parameter"
...
modparam("dialog", "state_column", "state_c_name")
...
```


#### start_time_column (string)


The column's name in the database to store the 
dialogs' start time information.


*Default value is "start_time".*


```opensips title="Set start_time_column parameter"
...
modparam("dialog", "start_time_column", "start_time_c_name")
...
```


#### timeout_column (string)


The column's name in the database to store the dialogs' timeout.


*Default value is "timeout".*


```opensips title="Set timeout_column parameter"
...
modparam("dialog", "timeout_column", "timeout_c_name")
...
```


#### profiles_column (string)


The column's name in the database to store the dialogs' profiles.


*Default value is "profiles".*


```opensips title="Set profiles_column parameter"
...
modparam("dialog", "profiles_column", "profiles_c_name")
...
```


#### vars_column (string)


The column's name in the database to store the dialogs' vars.


*Default value is "vars".*


```opensips title="Set vars_column parameter"
...
modparam("dialog", "vars_column", "vars_c_name")
...
```


#### sflags_column (string)


The column's name in the database to store the dialogs' script flags.


*Default value is "script_flags".*


```opensips title="Set sflags_column parameter"
...
modparam("dialog", "sflags_column", "sflags_c_name")
...
```


#### flags_column (string)


The column's name in the database to store the dialogs' flags.


*Default value is "flags".*


```opensips title="Set flags_column parameter"
...
modparam("dialog", "flags_column", "flags_c_name")
...
```


#### profiles_with_value (string)


List of names for profiles with values.


*Default value is "empty".*


```opensips title="Set profiles_with_value parameter"
...
modparam("dialog", "profiles_with_value", "caller ; my_profile; share/s")
...
```


#### profiles_no_value (string)


List of names for profiles without values.


*Default value is "empty".*


```opensips title="Set profiles_no_value parameter"
...
modparam("dialog", "profiles_no_value", "inbound ; outbound ; shared/s")
...
```


#### db_flush_vals_profiles (int)


Pushes dialog values, profiles and flags into the database
along with other dialog state information (see db_mode 1 and 2).


*Default value is "empty".*


```opensips title="Set db_flush_vals_profiles parameter"
...
modparam("dialog", "db_flush_vals_profiles", 1)
...
```


#### own_timer_proc (int)


Whether the dialog timer should be a 
separate process or if the tasks should be done in the
global timer process.


*Default value is "0", run the timer in the
global process.*


```opensips title="Set own_timer_proc parameter"
...
modparam("dialog", "own_timer_proc", 1)
...
```


#### timer_bulk_del_no (int)


The number of dialogs that should be attempted to be
deleted at the same time ( a single query ) from the 
DB back-end.


*Default value is "1".*


```opensips title="Set timer_bulk_del_no parameter"
...
modparam("dialog", "timer_bulk_del_no", 10)
...
```


#### cachedb_url (string)


Enables distributed dialog profiles and specifies the
backend that should be used by the CacheDB interface.


*Default value is "empty".*


```opensips title="Set cachedb_url parameter"
...
modparam("dialog", "cachedb_url", "redis://127.0.0.1:6379")
...
```


#### profile_value_prefix (string)


Specifies what prefix should be added to the profiles with 
value when they are inserted into CacheDB backed. This is
only used when distributed profiles are enabled.


*Default value is "dlg_val_".*


```opensips title="Set profile_value_prefix parameter"
...
modparam("dialog", "profile_value_prefix", "dlgv_")
...
```


#### profile_no_value_prefix (string)


Specifies what prefix should be added to the profiles without
value when they are inserted into CacheDB backed. This is
only used when distributed profiles are enabled.


*Default value is "dlg_noval_".*


```opensips title="Set profile_no_value_prefix parameter"
...
modparam("dialog", "profile_no_value_prefix", "dlgnv_")
...
```


#### profile_size_prefix (string)


Specifies what prefix should be added to the entity that holds
the profiles with value size in CacheDB backed. This is
only used when distributed profiles are enabled.


*Default value is "dlg_size_".*


```opensips title="Set profile_size_prefix parameter"
...
modparam("dialog", "profile_size_prefix", "dlgs_")
...
```


#### profile_timeout (int)


Specifies ho long a dialog profile should be kept in the CacheDB
until it expires. This is only used when distributed profiles are
enabled.


*Default value is "86400".*


```opensips title="Set profile_timeout parameter"
...
modparam("dialog", "profile_timeout", "43200")
...
```


### Exported Functions


#### create_dialog()


The function creats the dialog for the currently processed request. The
request must be an initial request.

Optionally,the function also receives a string parameter, which specifies
whether the dialog end-points should be pinged via SIP options
messages. The parameter can be "P" to specify to only ping the
caller, "p" to only ping the callee or "Pp" to ping both dialog
sides. If the extra string parameter is provided and one
end-point fails to respond to a options ping, OpenSIPS will
terminate the dialog from the middle.

The string parameter can also contain "B" to activate the bye on
timeout behavior.


The function returns true if the dialog was successfully created or 
if the dialog was previously created.


This function can be used from REQUEST_ROUTE.


```opensips title="create_dialog() usage"
...
create_dialog();
...
#ping caller
create_dialog("P");
...
#ping caller and callee
create_dialog("Pp");

#bye on timeout
create_dialog("B");
...
```


#### match_dialog()


This function is to be used to match a sequential (in-dialog) request
to an existing dialog. In other words, the function will try to match 
the current request to an known ongoing dialog.


The function tries to use (for dialog matching) the DID (Dialog ID)
from Route header and also falls back to SIP-wise matching.


As sequential requests are automatically matched to the dialog when 
doing "loose_route()" from script, this function is intended to:
(A) control the place in your script where the dialog matching is done
and (B) to cope with bogus sequential requests that do not have Route 
headers, so they are not handled by loose_route().


The function returns true if a dialog exists for the request.


This function can be used from REQUEST_ROUTE.


```opensips title="match_dialog() usage"
...
    if (has_totag()) {
        loose_route();
        if ($DLG_status==NULL && !match_dialog() ) {
            xlog(" cannot match request to a dialog \n");
        }
    }
...
```


#### validate_dialog()


The function checks the current received requests against the dialog 
(internal data) it belongs to.
Performing several tests, the function will help to detect the bogus
injected in-dialog requests (like malicious BYEs).


The performed tests are related to CSEQ sequance checking and routing
information checking (contact and route set).


The function returns true if a dialog exists for the request and if 
the request is valid (according to dialog data). If the request is invalid,
the following return codes are returned :


- *-1* - invalid cseq
- *-2* - invalid remote target
- *-3* - invalid route set
- *-4* - other errors ( parsing, no dlg, etc )


This function can be used from REQUEST_ROUTE.


```opensips title="validate_dialog() usage"
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


```opensips title="fix_route_dialog() usage"
...
    if (has_totag()) {
        loose_route();
        if ($DLG_status!=NULL)
            if (!validate_dialog())
                fix_route_dialog();
    }
...
```


#### get_dialog_info(attr,var,key,key_val)


The function extracts a dialog value from another dialog - it search 
through all existing (ongoing) dialogs for a dialog
that has a dialog variable named "key" with the value "key_val" 
(so a dialog where $dlg_val(key)=="key_val") - once found, it return
in pvar "var" the value of the the dialog variable "attr" from the 
found dialog.


> [!NOTE]
> The function does not require to be called in the context of
> a dialog - you can use it whenever / whereever for searching for other
> dialogs.


Meaning of the parameters is as follows:


- *attr* - the name of the dialog variable
(from the found dialog) to be returned;
- *var* - a pvar where to store the value of
the "attr" dialog variable
- *key* - name of a dialog variable to be
used a search key (when looking after the target dialog)
- *key_val* - the value of the dialog 
variable that is used as key in searching the target dialog.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
REPLY_ROUTE, FAILURE_ROUTE and LOCAL_ROUTE.


```opensips title="get_dialog_info usage"
...
if ( get_dialog_info("callee","$var(x)","caller","$fu") ) {
	xlog("caller $fU has another ongoing, talking to callee $var(x)\n")
}

# create dialog for current call and place the caller and callee attributes
create_dialog();
$dlg_val(caller) = $fu;
$dlg_val(callee) = $ru;
...
```


#### set_dlg_profile(profile,[value])


Inserts the current dialog into a profile. Note that if the profile does
not support values, this will be silently discarded. A dialog may be
inserted in the same profile multiple times.


> [!NOTE]
> The dialog must be created before using this function (use
> create_dialog() function before).


Meaning of the parameters is as follows:


- *profile* - name of the profile to be 
added to;
- *value* (optional) - string value to 
define the belonging of the dialog to the profile - note that the
profile must support values.
Pseudo-variables are supported.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
REPLY_ROUTE and FAILURE_ROUTE.


```opensips title="set_dlg_profile usage"
...
set_dlg_profile("inbound_call");
set_dlg_profile("caller","$fu");
...
```


#### unset_dlg_profile(profile,[value])


Removes the current dialog from a profile.


> [!NOTE] 
> The dialog must be created before using this function (use
> create_dialog() function before).


Meaning of the parameters is as follows:


- *profile* - name of the profile to be 
removed from;
- *value* (optional) - string value to 
define the belonging of the dialog to the profile - note that the
profile must support values.
Pseudo-variables are supported.


This function can be used from BRANCH_ROUTE,
REPLY_ROUTE and FAILURE_ROUTE.


```opensips title="unset_dlg_profile usage"
...
unset_dlg_profile("inbound_call");
unset_dlg_profile("caller","$fu");
...
```


#### is_in_profile(profile,[value])


Checks if the current dialog belongs to a profile. If the profile 
supports values, the check can be reinforced to take into account a 
specific value - if the dialog was inserted into the profile for a 
specific value. If no value is passed, only simply belonging of the 
dialog to the profile is checked. Note that if the profile does not 
support values, this will be silently discarded.


> [!NOTE]
> The dialog must be created before using this function (use
> create_dialog() function before).


Meaning of the parameters is as follows:


- *profile* - name of the profile to be 
checked against;
- *value* (optional) - string value to 
toughen  the check. Pseudo-variables are supported.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
REPLY_ROUTE and FAILURE_ROUTE.


```opensips title="is_in_profile usage"
...
if (is_in_profile("inbound_call")) {
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


- *profile* - name of the profile to get 
the size for;
- *value* (optional) - string value to 
toughen  the check. Pseudo-variables are supported;
- *size* - an AVP or script variable to
return the profile size in.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
REPLY_ROUTE and FAILURE_ROUTE.


```opensips title="get_profile_size usage"
...
get_profile_size("inbound_call","$avp(size)");
xlog("currently there are $avp(size) inbound calls\n");
...
get_profile_size("caller","$fu");
xlog("currently, the user %fu has $avp(size) active outgoing calls\n");
...
```


#### set_dlg_flag(idx)


Sets the dialog flag index *idx* to true. The dialog
flags are dialog persistent and they can be accessed (set and test)
for all requests belonging to the dialog.


The flag index can be between 0 and 31.


> [!NOTE]
> The dialog must be created before using this function (use
> create_dialog() function before).


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
REPLY_ROUTE and FAILURE_ROUTE.


```opensips title="set_dlg_flag usage"
...
set_dlg_flag("3");
...
```


#### test_and_set_dlg_flag(idx, value)


Atomically checks if the dialog flag index *idx* is
equal to *value*. If true, changes the value with the
oppsosite one. This operation is done under the dialog lock.


The flag index can be between 0 and 31.


The value should be 0 (false) or 1 (true).


> [!NOTE]
> The dialog must be created before using this function (use
> create_dialog() function before).


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
REPLY_ROUTE and FAILURE_ROUTE.


```opensips title="test_and_set_dlg_flag usage"
...
test_and_set_dlg_flag("3", "0");
...
```


#### reset_dlg_flag(idx)


Resets the dialog flag index *idx* to false.
The dialog flags are dialog persistent and they can be accessed 
(set and test) for all requests belonging to the dialog.


The flag index can be between 0 and 31.


> [!NOTE]
> The dialog must be created before using this function (use
> create_dialog() function before).


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
REPLY_ROUTE and FAILURE_ROUTE.


```opensips title="reset_dlg_flag usage"
...
reset_dlg_flag("16");
...
```


#### is_dlg_flag_set(idx)


Returns true if the dialog flag index *idx* is set.
The dialog flags are dialog persistent and they can be accessed 
(set and test) for all requests belonging to the dialog.


The flag index can be between 0 and 31.


> [!NOTE]
> The dialog must be created before using this function (use
> create_dialog() function before).


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
REPLY_ROUTE and FAILURE_ROUTE.


```opensips title="is_dlg_flag_set usage"
...
if (is_dlg_flag_set("16")) {
	xlog("dialog flag 16 is set\n");
}
...
```


#### store_dlg_value(name,val)


Attaches to the dialog the value *val* under the 
name *name*. The values attached to dialogs are 
dialog persistent and they can be accessed (read and write) for all 
requests belonging to the dialog.


Parameter *val* may contain pseudo-variables.


> [!NOTE]
> The dialog must be created before using this function (use
> create_dialog() function before).


Same functionality may be obtain by assigning a value to pseudo
variable *$dlg_val(name)*.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
REPLY_ROUTE and FAILURE_ROUTE.


```opensips title="store_dlg_value usage"
...
store_dlg_value("inv_src_ip","$si");
store_dlg_value("account type","prepaid");
# or
$dlg_val("account_type") = "prepaid";
...
```


#### fetch_dlg_value(name,pvar)


Fetches from the dialog the value of attribute named 
*name*. The values attached to dialogs are 
dialog persistent and they can be accessed (read and write) for all 
requests belonging to the dialog.


Parameter *pvar* may be a script var ($var) or
and avp ($avp).


> [!NOTE]
> The dialog must be created before using this function (use
> create_dialog() function before).


Same functionality may be obtain by reading the pseudo
variable *$dlg_val(name)*.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
REPLY_ROUTE and FAILURE_ROUTE.


```opensips title="fetch_dlg_value usage"
...
fetch_dlg_value("inv_src_ip","$avp(2)");
fetch_dlg_value("account type","$var(account)");
# or
$var(account) = $dlg_val("account_type");
...
```


#### topology_hiding()


Dialog module can also do a small overhead topology hiding. By calling this
function on an initial Invite, for the current dialog, the modules will
hide the topology, meaning that it will strip and restore all the Via,
Record-Route and Route headers and it will replace the contact with the
IP address of the interface where the request was received.


You must note however, that the detection of the future in-dialog requests(BYE, reInvite, etc.)
for these dialogs on which topology hiding is applied, is not done automatically.
Without topology hiding and only normal dialog, the detection was
done when loose_route was called. But now, for this dialogs where topology
hiding is applied, the in dialog requests reaching OpenSIPS won't have any Route headers
and the RURI will point to OpenSIPS machine.
So, to be able to match the in-dialog requests to the corresponding dialog, a script
function must be called. It's name is *match_dialog* and you can read
it's description above.
The in-dialog topology requests are requests with a to tag,
RURI pointing to opensips and with a method specific to a
Invite dialog. For this kind of requests you should call
match_dialog() function. If a dialog is found the function
returns success.


The great advantage of using the topology hiding functionality built inside
dialog module is that you can use all the dialog modules functionalities:
profiles, dialog variables, dialog timeouts, etc..


```opensips title="topology_hiding usage"
...
if(!has_totag() && is_method("INVITE")) {
	topology_hiding();
}
...
```


```opensips title="calling match_dialog() function for topology hiding sequential requests"
...
if (has_totag()  && (uri == myself)  && is_method("INVITE|ACK|BYE|UPDATE")
        if(match_dialog())
        {
                xlog(" in-dialog topology hiding request - $DLG_dir\n");
                route(1);
                exit;
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


### Exported MI Functions


#### dlg_list


Lists the description of the dialogs (calls). If no paramter is given,
all dialogs will be listed. If a dialog identifier is passed
as paramter (callid and fromtag), only that dialog will be listed. If
a index and conter parameter is passed, it will list only a number of
"counter" dialogs starting with index (as offset) - this is used to
get only section of dialogs.


Name: *dlg_list*


Parameters (with dialog idetification):


- *callid* (optional) - callid if a single
dialog to be listed.
- *from_tag* (optional, but cannot be present
without the callid paramter) - fromtag (as per initial request)
of the dialog to be listed.
entry


Parameters (with dialog counting):


- *index* - offset where the dialog listing
should start.
- *counter* - how many dialogs should be 
listed (starting from the offset)


MI FIFO Command Format:


```bash
:dlg_list:_reply_fifo_file_
_empty_line_
```


```bash
:dlg_list:_reply_fifo_file_
abcdrssfrs122444@192.168.1.1
AAdfeEFF33
```


```bash
:dlg_list:_reply_fifo_file_
40
10
```


#### dlg_list_ctx


The same as the "dlg_list" but including in the 
dialog description
the associated context from modules sitting on top of
the dialog module.


Name: *dlg_list_ctx*


Parameters: *see "dlg_list"*


MI FIFO Command Format:


```bash
:dlg_list_ctx:_reply_fifo_file_
_empty_line_
```


#### dlg_end_dlg


Terminates an ongoing dialog.
If dialog is established, BYEs are sent in both directions.
If dialog is in unconfirmed or early state, a CANCEL will be sent
to the callee side, that will trigger a 487 from the callee,
which, when relayed, will also end the dialog on the caller's side.


Name: *dlg_end_dlg*


Parameters:


- *h_entry* - hash entry of the dialog in the
internal dialog table
- *h_id* - hash id of the dialog on the hash
entry
- *extra_hdrs* - (optional) string containg 
extra headers (full format) to be added to the BYE requests.


The values for the h_entry and h_id can be get via the dlg_list
MI command.


MI FIFO Command Format:


```bash
:dlg_end_dlg:_reply_fifo_file_
342
56
_empty_line_
```


#### profile_get_size


Returns the number of dialogs belonging to a profile. If the profile 
supports values, the check can be reinforced to take into account a 
specific value - how many dialogs were inserted into the profile with 
a specific value. If not value is passed, only simply belonging of the 
dialog to the profile is checked. Note that the profile does not 
supports values, this will be silently discarded.


Name: *profile_get_size*


Parameters:


- *profile* - name of the profile to get the
value for.
- *value* (optional)- string value to 
toughen the check;


MI FIFO Command Format:


```bash
:profile_get_size:_reply_fifo_file_
inbound_calls
_empty_line_
```


#### profile_list_dlgs


Lists all the dialogs belonging to a profile. If the profile 
supports values, the check can be reinforced to take into account a 
specific value - list only the dialogs that were inserted into the 
profile with that specific value. If not value is passed, all dialogs 
belonging to the profile will be listed. Note that the profile does 
not supports values, this will be silently discarded. Also, when using
shared profiles using the CacheDB interface, this command will only
display the local dialogs.


Name: *profile_list_dlgs*


Parameters:


- *profile* - name of the profile to list the
dialog for.
- *value* (optional)- string value to 
toughen the check;


MI FIFO Command Format:


```bash
:profile_list_dlgs:_reply_fifo_file_
inbound_calls
_empty_line_
```


#### profile_get_values


Lists all the values belonging to a profile along with their
count. If the profile does not support values a total count
will be returned. Note that this function does not work for shared
profiles over the CacheDB interface.


Name: *profile_get_values*


Parameters:


- *profile* - name of the profile to list the
dialog for.


MI FIFO Command Format:


```bash
:profile_get_values:_reply_fifo_file_
inbound_calls
_empty_line_
```


#### dlg_db_sync


Will synchronize the information about the dialogs from the database
with the OpenSIPS internal memory. To be used mainly for transfering
OpenSIPS dialog information from one server to another.


Name: *dlg_db_sync*


It takes no parameters


MI FIFO Command Format:


```bash
:dlg_db_sync:_reply_fifo_file_
_empty_line_
```


#### list_all_profiles


Lists all the dialog profiles, along with 1 or 0 if
the given profile has/does not have an associated value.


Name: *list_all_profiles*


Parameters: *It takes no parameters*


MI FIFO Command Format:


```bash
:list_all_profiles:_reply_fifo_file_
_empty_line_
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


Returns the dialog flags array (as a single interger value)
of the dialog corresponding to the processed sequential request.
This PV will be available only for sequential requests, 
after doing loose_route().


NULL will be returned if there is no dialog for the request.


#### $DLG_dir


Returns the direction of the request in dialog (as "UPSTREAM" or
"DOWNSTREAM" string) - to be used for sequential request.
This PV will be available only for sequential requests (on 
replies), after doing loose_route().


NULL will be returned if there is no dialog for the request.


#### $DLG_did


Returns the id of the dialog corresponding to 
the processed sequential request. The output format is 
entry ':' id (as returned by the dlg_list MI function). This PV will be 
available only for sequential requests, after doing loose_route().


NULL will be returned if there is no dialog for the request.


#### $dlg_val(name)


This is a read/write variable that allows access to the dialog 
attribute named *name*.
This PV will be available only for sequential requests,
after doing loose_route().


NULL will be returned if there is no dialog for the request.


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
	- *DLGCB_LOADED*
	- *DLGCB_SAVED*
	- *DLG_CREATED* - called when a new 
	dialog is created - it's a global type (not associated to 
	any dialog)
	- *DLG_FAILED* - called when the dialog
	was negatively replied (non-2xx) - it's a per dialog type.
	- *DLG_CONFIRMED* - called when the 
	dialog is confirmed (2xx replied) - it's a per dialog type.
	- *DLG_REQ_WITHIN* - called when the 
	dialog matches a sequential request - it's a per dialog type.
	- *DLG_TERMINATED* - called when the 
	dialog is terminated via BYE - it's a per dialog type.
	- *DLG_EXPIRED* - called when the 
	dialog expires without receiving a BYE - it's a per dialog 
	type.
	- *DLGCB_EARLY* - called when the
	dialog is created in an early state (18x replied) - it's
	a per dialog type.
	- *DLGCB_RESPONSE_FWDED* - called when
	the dialog matches a reply to the initial INVITE request - it's
	a per dialog type.
	- *DLGCB_RESPONSE_WITHIN* - called when
	the dialog matches a reply to a subsequent in dialog request - it's a per dialog type.
	- *DLGCB_MI_CONTEXT* - called when the
	mi dlg_list_ctx command is invoked - it's a per dialog type.
	- *DLGCB_DESTROY*
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


**Q: What happend with "use_tight_match" 
parameter?**


The parameter was removed with version 1.3 as the option of tight
matching became mandatory and not configurable. Now, the tight
matching is done all the time (when using DID matching).


**Q: What happend with "bye_on_timeout_flag" 
parameter?**


The parameter was removed in a dialog module parameter restructuring.
To keep the bye on timeout behavior, you need to provide a "B" 
string parameter to the create_dialog() function.


**Q: What happend with "dlg_flag" 
parameter?**


The parameter is considered obsolete. The only way to
create a dialog is to call the create_dialog() function


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
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
