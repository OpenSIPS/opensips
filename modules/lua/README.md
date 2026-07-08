---
title: "lua Module"
description: "The time needed when writing a new OpenSIPS module unfortunately is quite high, while the options provided by the configuration file are limited to the features implemented in the modules."
---

## Admin Guide


### Overview


The time needed when writing a new OpenSIPS module
   unfortunately is quite high, while the options provided by the
   configuration file are limited to the features implemented in
   the modules.


With this Lua module, you can easily implement your own
   OpenSIPS extensions in Lua.


### Installing the module


This Lua module is loaded in opensips.cfg (just like all the
    other modules) with loadmodule("/path/to/lua.so");.


For the Lua module to compile, you need a recent version of
    Lua (tested with 5.1) linked dynamically. The default version
    of your favorite Linux distribution should work fine.


### Using the module


With the Lua module, you can access to lua function on the
    OpenSIPS side. You need to define a file to load and call
    a function from it. Write a function "mongo_alias" and then
    write in your opensips.cfg


```opensips
...
if (lua_exec("mongo_alias")) {
	...
}
...
```


On the Lua side, you have access to opensips functions and
    variables (AVP, pseudoVar, ...). Read the documentation below
    for further informations.


### Dependencies


#### OpenSIPS Modules


None ;-)


#### External Libraries or Applications


The following libraries or applications must be installed
      before running OpenSIPS with this module loaded:


- Lua 5.1.x or later
- memcached


This module has been developed and tested with Lua 5.1.?, but
      should work with any 5.1.x release. Earlier versions do not work.


On current Debian systems, at least the following packages
      should be installed:


- lua5.1
- liblua5.1-0-dev
- libmemcached-dev
- libmysqlclient-dev


It was reported that other Debian-style distributions (such as Ubuntu) need the same packages.


On OpenBSD systems, at least the following packages should be
      installed:


- Lua


### Exported Parameters


#### luafilename (string)


This is the file name of your script. This may be set once
      only, but it may include an arbitary number of functions and
      "use" as many Lua module as necessary.


The default value is "/etc/opensips/opensips.lua"


```opensips title="Set luafilename parameter"
...
modparam("lua", "luafilename", "/etc/opensips/opensips.lua")
...
        
```


#### lua_auto_reload (int)


Define this value to 1 if you want to reload automatically
      the lua script.
      Disabled by default.


#### warn_missing_free_fixup (int)


When you call a function via moduleFunc() you could have a memleak.
      Enable this warns you when you're doing it.
      Enabled by default.


#### lua_allocator (string)


Change the default memory allocator for the lua module.
      Possible values are :


- opensips (default)
- malloc


### Exported Functions


#### lua_exec(func, [param])


Calls a Lua function with passing it the current SIP message.
      This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
      ONREPLY_ROUTE and BRANCH_ROUTE.


Parameters:


- *func* (string) - Lua function name
- *param* (string, optional) - Parameter to be passed to the Lua function.


```opensips title="lua_exec() usage"
...
if (lua_exec("mongo_alias")) {
	...
}
...
```


#### lua_meminfo()


Logs informations about memory.


### Exported MI Functions


#### watch


Name: *watch*


Parameters: *none*


- *action* (optional) - 'add' or 'delete'
- *extension* (optional) - required if
        *action* is provided


MI FIFO Command Format:


```bash
  opensips-cli -x mi watch
  
```


## OpenSIPS Lua API


### Available functions


This module provides access to a limited number of OpenSIPS
    core functions.


#### xdbg(message)


An alias for xlog(DBG, message)


#### xlog([level],message)


Logs the message with OpenSIPS's logging facility. The logging
      level is one of the following:


- ALERT
- CRIT
- ERR
- WARN
- NOTICE
- INFO
- DBG


#### WarnMissingFreeFixup


Dynamically change the variable warn_missing_free_fixup.


#### getpid


Returns the current pid.


#### getmem


Returns a table with the size of allocated memory and the fragmentation.


#### getmeminfo


Returns a table with memory infos.


#### gethostname


Returns the value of the current hostname.


#### getType(msg)


Returns "SIP_REQUEST" or "SIP_REPLY".


#### isMyself(host, port)


Test if the host and optionally the port represent one of the addresses
      that OpenSIPS listens on.


#### grepSockInfo(host, port)


Similar to isMyself(), but without taking a look into the aliases.


#### getURI_User(msg)


Returns the user of the To URI.


#### getExpires(msg)


Returns the expires header of the current message.


#### getHeader(msg, header)


Returns the value of the specified header.


#### getContact(msg)


Returns a table with the contact header.


#### getRoute(msg)


Returns a table with the Route header.


#### moduleFunc(msg, function, args1, args2, ...)


You can pass arguments to this function.


#### getStatus(msg)


Returns the current status if the SIP message is a SIP_REPLY.


#### getMethod(msg)


Returns the current method.


#### getSrcIp(msg)


Returns the IP address of the source.


#### getDstIp(msg)


Returns the IP address of the destination.


#### AVP_get(name)


Returns an AVP variable.


#### AVP_set(name, value)


Defines an AVP variable.


#### AVP_destroy(name)


Destroys an AVP variable.


#### pseudoVar(msg, variable)


Returns a pseudoVar.


#### pseudoVarSet(msg, variable, value)


Sets the value of a pseudoVar.


#### scriptVarGet(variable)


Returns a script variable.


#### scriptVarSet(variable, value)


Sets the value of a script variable.


#### add_lump_rpl(msg, header)


Add header to the reply.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
