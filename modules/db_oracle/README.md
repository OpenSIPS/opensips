---
title: "oracle Module"
description: "This is a module which provides Oracle connectivity for OpenSIPS. It implements the DB API defined in OpenSIPS. If you want to use the nathelper module, or any other modules that calls the get_all_ucontacts API export from usrloc, then you need to set the *DORACLE_USRLOC* define in the Ma..."
---

## User's Guide


### Overview


This is a module which provides Oracle connectivity for OpenSIPS.
		It implements the DB API defined in OpenSIPS. If you want to use
		the nathelper module, or any other modules that calls the
		get_all_ucontacts API export from usrloc, then you need to set
		the *DORACLE_USRLOC* define in the Makefile.defs
		file before compilation.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *instantclient-sdk-10.2.0.3* - the development headers and libraries of OCI.


### Exported Parameters


#### timeout (fixedpoint)


Timeout value for any operation with BD.


Possible values is from 0.1 to 10.0 seconds.


*Default value is 3.0 (3 second).*


If value of timeout parameter set to 0, module use synchronous
		mode (without timeout).


```opensips title="Set timeout parameter"
...
modparam("db_oracle", "timeout", 1.5)
...
```


```opensips title="Disable asynchronous mode"
...
modparam("db_oracle", "timeout", 0)
...
```


#### reconnect (fixedpoint)


Timeout value for connect (create session) operation.


Possible values is from 0.1 to 10.0 seconds.


*Default value is 0.2 (200 milliseconds).*


```opensips title="Set reconnect parameter"
...
modparam("db_oracle", "reconnect", 0.5)
...
```


### Exported Functions


No function exported to be used from configuration file.


### Installation


Because it dependes on an external library, the oracle module is not
		compiled and installed by default. You can use one of the next options.


- - edit the "Makefile" and remove "db_oracle" from "excluded_modules"
			list. Then follow the standard procedure to install OpenSIPS:
			"make all; make install".
- - from command line use: 'make all include_modules="db_oracle";
			make install include_modules="db_oracle"'.


### Utility opensips_orasel


For working with opensips-cli tool, should be able to print the 'query' 
		results to the terminal in a user-readable form. The standard command-line 
		Oracle client (sqlplus) is not quite suitable for this, as it cannot align 
		row width to real (received) data's (it always prints a cell width as 
		described in the db scheme). This problem has been solved by inclusion the 
		utility opensips_orasel, which formats printing approximately in the same 
		way as the 'mysql' client utility. In addition, this utility known about 
		the "agreements and types" in DB that are used in OpenSIPS for the work 
		with Oracle and formats printing taking these into account.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
