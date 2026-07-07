---
title: "Python Module"
description: "This module can be used to efficiently run Python code directly from the OpenSIPS script, without executing the *python* interpreter."
---

## Admin Guide


### Overview


This module can be used to efficiently run Python code directly from
		the OpenSIPS script, without executing the *python*
		interpreter.


The module provides the means to load a python module and run
		its functions. Each function has to receive the SIP message as
		parameter, and optionally some extra arguments passed from the
		script.


In order to run Python functions, one has to load the module
		that contains them, by specifying the script name using the
		*script_name* parameter. The module has to contain
		the following components:


- A class that contains all the methods that can be invoked from the
		script.
- A method within the class that is called when a SIP child is created.
		The method should receive an integer parameter, which represents the
		rank of the child, and must return 0 or positive in case the function
		was executed successfully, or negative otherwise. The name of this
		method is specified by the *child_init_method*
		parameter.
- A global function that initializes the Python module and returns an
		object from the class whose functions will be invoked by the script.
		The name of the global function is indicated by the
		*mod_init_method* parameter.


A minimal example of a Python script that satisfies these requirements
		is:


```c
	def mod_init():
		return SIPMsg()

	class SIPMsg:
        def child_init(self, rank):
	        return 0
		
```


A function from the object returned above can be executed from the
		script using the *python_exec()* script function. The
		python method has to receive the following parameters:


- The SIP message, that has the structure detailed below
- Optionally, a string passed from the script


The SIP message received as parameter by the function has the following
		fields and methods:


- *Type* - the type of the message, either
		*SIP_REQUEST* or *SIP_REPLY*
- *Method* - the method of the message
- *Status* - the status of the message, available only
		for replies
- *RURI* - the R-URI of the message, available only for
		requests
- *src_address* - the (IP, port) tuple representing
		source address of the message
- *dst_address* - the (IP, port) tuple representing
		the destination address (OpenSIPS address) of the message
- *copy()* - copies the current SIP message in a new
		object
- *rewrite_ruri()* - changes the R-URI of the message;
		available only for requests
- *set_dst_uri()* - sets the destination URI of the
		message; available only for requests
- *getHeader()* - returns the header of a message
- *call_function()* - calls built-in script function
		or function exported by other module
- *get_pseudoVar(name)* - returns the value of the
		the pseudo-variable specified by the *name* as
		Unicode string.
- *set_pseudoVar(name, value)* - sets pseudo-variable
		using Unicode string *value*.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *None*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *python-dev* - provides the Python bindings.


### Exported Parameters


#### script_name (string)


The script that contains the Python module.


*Default value is "/usr/local/etc/opensips/handler.py".*


```opensips title="Set script_name parameter"
...
modparam("python", "script_name", "/usr/local/bin/opensips_handler.py")
...
```


#### mod_init_function (string)


The method used to initialize the Python module and return the object.


*Default value is "mod_init".*


```opensips title="Set mod_init_function parameter"
...
modparam("python", "mod_init_function", "module_initializer")
...
```


#### child_init_method (string)


The method called for each child process.


*Default value is "child_init".*


```opensips title="Set child_init_method parameter"
...
modparam("python", "child_init_method", "child_initializer")
...
```


### Exported Functions


#### python_exec(method_name [, extra_args])


This function is used to execute a method from the Python module
				loaded.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE,
				FAILURE_ROUTE and BRANCH_ROUTE.


Meaning of the parameters is as follows:


- *method_name* (string) - name of the method called
- *extra_args* (string, optional) - extra arguments that can
					be passed from the script to the python function.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
