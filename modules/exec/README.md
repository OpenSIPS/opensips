---
title: "exec Module"
description: "The Exec module enables the execution of external commands from the OpenSIPS script."
---

## Admin Guide


### Overview


The Exec module enables the execution of external commands from the
OpenSIPS script. Any valid shell commands are accepted. The final input
string is evaluated and executed using the "/bin/sh" symlink/binary.
OpenSIPS may additionally pass a lot more information about the request
using environment variables:


- SIP_HF_<hf_name> contains value of each header field in 
request. If a header field occurred multiple times, values are 
concatenated and comma-separated. <hf_name> is in capital 
letters. Ff a header-field name occurred in compact form, 
<hf_name> is canonical.
- SIP_TID is transaction identifier. All request retransmissions or 
CANCELs/ACKs associated with a previous INVITE result in the same 
value.
- SIP_DID is dialog identifier, which is the same as to-tag. 
Initially, it is empty.
- SIP_SRCIP is source IP address from which request came.
- SIP_ORURI is original request URI.
- SIP_RURI is *current* request URI (if 
unchanged, equal to original).
- SIP_USER is userpart of *current* request URI.
- SIP_OUSER is userpart of original request URI.
- SIP_REPLY_CODE is the code of the *current* reply.
- SIP_REPLY_REASON is the reason of the *current* reply.


> [!NOTE]
> Any environment variables which are given to the exec module
> functions must be specified using the '$$' delimiter (e.g., $$SIP_OUSER),
> otherwise they will be evaluated as OpenSIPS pseudo-variables,
> throwing scripting errors.


### Dependencies


#### OpenSIPS Modules


The following  modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### setvars (integer)


Set to 1 to enable setting all above-mentioned environment variables
for all executed commands.


> [!WARNING]
> Before enabling this parameter, make sure
> your "/bin/sh" is safe from the Shellshock bash vulnerability!


*Default value is 0 (disabled).*


```opensips title="Set 'setvars' parameter"
...
modparam("exec", "setvars", 1)
...
```


#### time_to_kill (integer)


Specifies the longest time a program is allowed to execute. If the
time is exceeded, the program is killed.


*Default value is 0 (disabled).*


```opensips title="Set 'time_to_kill' parameter"
...
modparam("exec", "time_to_kill", 20)
...
```


#### async (integer)


Turns on the asynchronous mode for the 'exec_msg' function. All commands
will be executed by a different process and the caller will continue
its flow, without waiting for a response.


*Default value is 0 (disabled).*


```opensips title="Set 'async' parameter"
...
modparam("exec", "async", 1)
...
```


### Exported Functions


#### exec_dset(command)


Executes an external command. The current R-URI is appended to the command
as its last parameter. The output of the command will rewrite the current R-URI.
Multiple lines of output lead to multiple branches.


Meaning of the parameters is as follows:


- *command (string, pvar)* - command to be
executed. It can include pseudo-variables or '$$' delimited UNIX
environment variables


WARNING: most OpenSIPS scripting variables should be quoted before being
passed to external commands, as in: exec_avp("log-call.sh '$ct'").
This may help avoid some unexpected behaviour
(e.g. unwanted extra parameters, errors due to special bash characters, etc.)


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```opensips title="exec_dset usage"
...
exec_dset("ruri-changer.sh");
exec_dset("ruri-changer.sh '$ct'");
...
```


#### exec_msg(command)


Executes an external command. The current SIP message is passed to it in
the standard input, no command-line parameters are added and the output
of the command is ignored.


See sip-server/modules/exec/etc/exec.cfg in the source tarball for 
information on usage.


Meaning of the parameters is as follows:


- *command (string)* - command to be executed. It
can include pseudo-variables or '$$' delimited UNIX
environment variables


WARNING: most OpenSIPS scripting variables should be quoted before being
passed to external commands, as in: exec_avp("log-call.sh '$ct'").
This may help avoid some unexpected behaviour
(e.g. unwanted extra parameters, errors due to special bash characters, etc.)


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, LOCAL_ROUTE,
TIMER_ROUTE, EVENT_ROUTE, ONREPLY_ROUTE.


```opensips title="exec_msg usage"
...
exec_msg("call-logger.sh '$ct' >> /var/log/call-logger/'$rU'.calls");
...
```


#### exec_avp(command[, avplist])


Executes an external command. Each output line of the command
is saved in its corresponding AVP from *avplist*.
If *avplist* is missing or is incomplete, the
populated AVPs will be 1, 2, 3... or N, N+1, N+2...


Meaning of the parameters is as follows:


- *command (string)* - command to be
executed. It can include pseudo-variables or '$$' delimited UNIX
environment variables
- *avplist (string)* - comma separated list with AVP
names to store the result in


WARNING: most OpenSIPS scripting variables should be quoted before being
passed to external commands, as in: exec_avp("log-call.sh '$ct'").
This may help avoid some unexpected behaviour
(e.g. unwanted extra parameters, errors due to special bash characters, etc.)


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
LOCAL_ROUTE, STARTUP_ROUTE, TIMER_ROUTE, EVENT_ROUTE, ONREPLY_ROUTE.


```opensips title="exec_avp usage"
...
exec_avp("get-subscriber-details.sh '$rU'", "$avp(credit) $avp(contract_model)");
...
```


#### exec_getenv(environment_variable[, avp])


Obtains the value of a UNIX evironment_variable. The value is saved
in 'avp'. If 'avp' is missing, output will be stored in $avp(1). If there
is no such environment variable no value will be returned.


Meaning of the parameters is as follows:


- *environment_variable (string)* -
environent variable name. Can also be specified as a pseudo-variable
- *avp* - an AVP to store the  result in


WARNING: any OpenSIPS pseudo-vars which may contain special bash
characters should be placed inside quotes, e.g. exec_getenv("'$ct'");


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
LOCAL_ROUTE, STARTUP_ROUTE, TIMER_ROUTE, EVENT_ROUTE, ONREPLY_ROUTE.


```opensips title="exec_getenv usage"
...
exec_getenv("HOSTNAME");
exec_getenv("HOSTNAME", "$avp(localhost)");
...
```


### Known Issues


When imposing an execution timeout using
**[time to kill](#param_time_to_kill)**,
make sure your "/bin/sh" is a shell which does not fork when executed,
case in which the job itself will not be killed, but rather its parent shell,
while the job is silently inherited by "init" and will continue to run.
"/bin/dash" is one of these troublesome shell environments.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
