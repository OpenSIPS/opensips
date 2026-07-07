---
title: "Example Module"
description: "This module serves as an example of how to write a module in OpenSIPS. Its primary goal is to simplify the development of new modules for newcomers, providing a clear and accessible starting point."
---

## Admin Guide


### Overview


This module serves as an example of how to write a module in OpenSIPS.
		Its primary goal is to simplify the development of new modules for
		newcomers, providing a clear and accessible starting point.


### Dependencies


#### OpenSIPS Modules


The following  modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### default_str (string)


The default parameter used when the [example str](#func_example_str)
			function is called without any parameter.


*Default value is "" (empty sring).*


```opensips title="Set 'default_str' parameter"
...
modparam("example", "default_str", "TEST")
...
```


#### default_int (integer)


The default parameter used when the [example int](#func_example_int)
			function is called without any parameter.


*Default value is "0".*


```opensips title="Set 'default_int' parameter"
...
modparam("example", "default_int", -1)
...
```


### Exported Functions


#### example()


Function that simply prints a message to log, saying that it has been called.


This function can be used from any route.


```opensips title="example usage"
...
example();
...
```


#### example_str([string])


Function that simply prints a message to log, saying that it has been called.
			If a parameter is passed, it is printed in the log, otherwise the value of
			[default str](#param_default_str) parameter is used.


Meaning of the parameters is as follows:


- *string (string, optional)* - parameter to be logged


This function can be used from any route.


```opensips title="example_str() usage"
...
example_str("test");
...
```


#### example_int([int])


Function that simply prints a message to log, saying that it has been called.
			If a parameter is passed, it is printed in the log, otherwise the value of
			[default int](#param_default_int) parameter is used.


Meaning of the parameters is as follows:


- *int (integer, optional)* - parameter to be logged


This function can be used from any route.


```opensips title="example_int() usage"
...
example_int(10);
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
