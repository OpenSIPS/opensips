---
title: "exec Module"
description: "Exec module allows to start an external command from a OpenSIPS script. The commands may be any valid shell commands--the command string is passed to shell using \"popen\" command. OpenSIPS passes additionally lot of information about request in environment variables:"
---

## Admin Guide


### Overview


Exec module allows to start an external command from a OpenSIPS script. 
		The commands may be any valid shell commands--the command string is 
		passed to shell using "popen" command. OpenSIPS passes 
		additionally lot of information about request in environment
		variables:


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


NOTE: The envirnment variables must be specified with double $
		(e.g., $$SIP_OUSER) in the parameters given to exec functions.
		Otherwise they will be evaluated as OpenSIPS pseudo-variables,
		throwing errors.


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


Turn off to disable setting environment variables for executed commands.


*Default value is 1.*


```opensips title="Set 'setvars' parameter"
...
modparam("exec", "setvars", 1)
...
```


#### time_to_kill (integer)


Specifies the longest time a program is allowed to execute. If the 
		time is exceeded, the program is killed.


*Default value is 0.*


```opensips title="Set 'time_to_kill' parameter"
...
modparam("exec", "time_to_kill", 20)
...
```


#### async (integer)


Turns on the asynchronous mode for 'exec_msg' function. All commands
		will be executed by a different process and the caller will continue
		it's flow, without waiting for a response.


*Default value is 0.*


```opensips title="Set 'async' parameter"
...
modparam("exec", "async", 1)
...
```


### Exported Functions


#### exec_dset(command)


Executes an external command. Current URI is passed to the command 
		as parameter. Output of the command is considered URI set 
		(separated by lines).


Meaning of the parameters is as follows:


- *command* - Command to be executed. It can
			include pseudo- variabes;


WARNING: if the var you are passing out has a bash special
		character in it, the var needs to be placed inside quotes, for ex:
		exec_dset("print-contact.sh '$ct'");


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```opensips title="exec_dset usage"
...
exec_dset("echo TEST > /tmp/test.txt");
exec_dset("echo TEST > /tmp/$rU.txt");
...
```


#### exec_msg(command)


Executes an external command. The whole message is passed to it in 
		input, no command-line parameters are added, output of the command is 
		not processed.


See sip-server/modules/exec/etc/exec.cfg in the source tarball for 
		information on usage.


Meaning of the parameters is as follows:


- *command* - Command to be executed. It
			can include pseudo-variables.


WARNING: if the var you are passing out has a bash special
		character in it, the var needs to be placed inside quotes, for ex:
		exec_msg("print-contact.sh '$ct'");


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, LOCAL_ROUTE,
		TIMER_ROUTE, EVENT_ROUTE, ONREPLY_ROUTE.


```opensips title="exec_msg usage"
...
exec_msg("echo TEST > /tmp/test.txt");
exec_msg("echo TEST > /tmp/$rU.txt");
...
```


#### exec_avp(command [, avplist])


Executes an external command. Each line from output of the command
		is saved in an AVP from 'avplist'. If 'avplist' is missing, the
		AVP are named 1, 2, 3, ...


Meaning of the parameters is as follows:


- *command* - Command to be executed. It can
			include pseudo- variabes;
- *avplist* - comma separated list with AVP 
			names to store the result in;


WARNING: if the var you are passing out has a bash special
		character in it, the var needs to be placed inside quotes, for ex:
		exec_avp("print-contact.sh '$ct'");


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		LOCAL_ROUTE, STARTUP_ROUTE, TIMER_ROUTE, EVENT_ROUTE, ONREPLY_ROUTE.


```opensips title="exec_avp usage"
...
exec_avp("echo TEST");
exec_avp("echo TEST", "$avp(test)");
...
```


#### exec_getenv(environment_variable [, avp])


Get the value of an evironment_variable. The value is saved 
		in 'avp'. If 'avp' is missing, the AVP is named 1. If there
		is no such environment variable no value is returned.


Meaning of the parameters is as follows:


- *environment_variable* - Environent 
			variable name. It can include pseudo- variabes;
- *avp* - an AVP names to store the 
			result in;


WARNING: if the var you are passing out has a bash special
		character in it, the var needs to be placed inside quotes, for ex:
		exec_getenv("'$ct'");


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		LOCAL_ROUTE, STARTUP_ROUTE, TIMER_ROUTE, EVENT_ROUTE, ONREPLY_ROUTE.


```opensips title="exec_getenv usage"
...
exec_getenv("HOSTNAME");
exec_getenv("HOSTNAME", "$avp(test)");
...
```


### Known Issues


There is currently no guarantee that scripts ever return and stop 
		blocking SIP server. (There is kill.c but it is not used along with 
		the current mechanisms based on popen. Besides that kill.c is ugly).
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
