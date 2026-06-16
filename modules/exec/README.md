---
title: "exec Module"
description: "The Exec module enables the execution of external commands from the OpenSIPS script. Any valid shell commands are accepted. The final input string is evaluated and executed using the \"/bin/sh\" symlink/binary. OpenSIPS may additionally pass a lot more information about the request using en..."
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


NOTE: Any environment variables which are given to the exec module
		functions must be specified using the '$$' delimiter (e.g., $$SIP_OUSER),
		otherwise they will be evaluated as OpenSIPS pseudo-variables,
		throwing scripting errors.


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


**WARNING: Before enabling this parameter, make sure
		your "/bin/sh" is safe from the Shellshock bash vulnerability!!!**


*Default value is 0 (disabled).*


```c title="Set 'setvars' parameter"
...
modparam("exec", "setvars", 1)
...
```


#### time_to_kill (integer)


If set, this parameter specifies the longest time (in seconds) that a
		program is allowed to execute. Once this duration is exceeded, the
		program is terminated (SIGTERM).


NOTE: due to internal limitations, a SIGTERM will actually be sent to
		**all** job pids once the "time_to_kill"
		expiration timeout hits. On a standard system, this should have no
		side-effects, as pids are monotonically increasing in a slow manner,
		and OpenSIPS should run under the "opensips" user, thus rendering it
		unable to terminate non-child processes. If this is not the case on
		your system, do not use the OpenSIPS "time_to_kill" feature -- rather
		implement it within your external app!


*Default value is 0 (disabled).*


```c title="Set 'time_to_kill' parameter"
...
modparam("exec", "time_to_kill", 20)
...
```


### Exported Functions


#### exec(command, [stdin], [stdout], [stderr], [envavp])


Executes an external command. The input is passed to the standard input of the new
		process, if specified, and the output is saved in the output variable.


The function waits for the external script until it provided all its output (not
		necessary to actually finish). If no output (standard output or standard error)
		is required by the function, it will not block at all - it will simply launch the
		external script and continue the script.


Meaning of the parameters is as follows:


- *command (string)* - command to be executed
- *stdin (string, optional)* - string to be
				passed to the standard input of the command
- *stdout (var, optional)* - optional
				output variable which will hold the standard output of the
				process
- *stderr (var, optional)* - optional
				output variable which will hold the standard error of the
				process
- *envavp (var, optional)* - optional AVP
				which holds the values for the
			environment variables to be passed for the command. The names of the environment
			variables will be "OSIPS_EXEC_#", where "#" starts from 0. For example, if we
			push two values (e.g. "b" and "a") into an AVP variable, which acts like a stack,
			OSIPS_EXEC_0 will hold "a", while OSIPS_EXEC_1 will hold "b".


NOTE: If expecting a multi-line formatted output, you should use $avp
		variables for the "stdout" and "stderr" parameters, to avoid only
		receiving the last lines of each stream.


WARNING: any OpenSIPS pseudo-vars which may contain special bourne shell (sh/bash)
		characters should be placed inside quotes, e.g.
		exec("update-stats.sh '$(ct{re.subst,/'//g})'");


WARNING: "stdin"/"stdout"/"stderr" parameters are not designed for large amounts of
		data, so one should be careful when using them. Because of the basic implementation,
		filled up pipes could cause a read deadlock.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		LOCAL_ROUTE, STARTUP_ROUTE, TIMER_ROUTE, EVENT_ROUTE, ONREPLY_ROUTE.


```c title="exec usage"
...
$avp(env) = "a";
$avp(env) = "b";
exec("ls -l", , $var(out), $var(err), $avp(env));
xlog("The output is $var(out)\n");
xlog("Received the following error\n$var(err)");
...
$var(input) = "input";
exec("/home/../myscript.sh", "this is my $var(input) for exec\n", , , $avp(env));
...
```


### Exported Asynchronous Functions


#### exec(command, [stdin], [stdout], [stderr], [envavp])


Executes an external command. This function does exactly the same as
		[exec](#func_exec) (in terms of input, output and processing),
		but in an asynchronous way. The script execution is suspended until
		the external script provided all its output. OpenSIPS waits for the
		external script to close its output stream, not necessarily to
		terminate (so the script may still be running when OpenSIPS
		resumes the script execution on "seeing" EOF on the the output stream)


NOTE: this function ignore the "stderr" parameter for now - the
		asynchronous waiting is done only on the output stream !! This may
		be fixed in the following versions.


To read and understand more on the asynchronous functions, how to use
		them and what are their advantages, please refer to the OpenSIPS 
		online Manual.


```c title="async exec usage"
{
...
async(exec("ruri-changer.sh", $ru, $ru), resume);
}

route [resume] {
...
}
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
