---
title: "launch_darkly Module"
description: "This module implements support for the [Launch Darkly](https://launchdarkly.com/) feature management cloud. The module provide the conectivity to the cloud and the ability to query for feature flags."
---

## Admin Guide


### Overview


This module implements support for the
		[Launch Darkly](https://launchdarkly.com/) feature
		management cloud. The module provide the conectivity to the cloud and
		the ability to query for feature flags.


OpenSIPS uses the [server side C/C++ SDK](https://launchdarkly.com/features/sdk/) provided by Launch Darkly.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *none*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *ldserverapi*


*ldserverapi* must be compiled and installed
			from the official
			[GITHUB repository](https://github.com/launchdarkly/c-server-sdk).


The instructions for a quick installations of the library (note that it has to be compiled as shared lib in order to be compatible with the OpenSIPS modules):


```c
...
	$ git clone https://github.com/launchdarkly/c-server-sdk.git
	$ cd c-server-sdk
	$ cmake -DBUILD_SHARED_LIBS=On -DBUILD_TESTING=OFF .
	$ sudo make install
...
```


### Exported Parameters


#### sdk_key (string)


The LaunchDarkly SDK key used to connect to the service. This
		is a mandatory parameter.


```c title="Set sdk_key parameter"
...
modparam("launch_darkly", "sdk_key", "sdk-12345678-abcd-12ab-1234-0123456789abc")
...
```


#### ld_log_level (string)


The LaunchDarkly specific log level to be used by the LD SDK/libray to
		log its internal messages. Note that these log produced by the LD
		library (according to this ld_log_level) will be further subject to
		filtering according to the overall OpenSIPS log_level.


Accepted values are 
		*LD_LOG_FATAL*, 
		*LD_LOG_CRITICAL*, 
		*LD_LOG_ERROR*, 
		*LD_LOG_WARNING*, 
		*LD_LOG_INFO*, 
		*LD_LOG_DEBUG*, 
		*LD_LOG_TRACE*.


If not set or set to an unsupported value, the 
		*LD_LOG_WARNING* level will be used by default.


```c title="Set log_level parameter"
...
modparam("launch_darkly", "ld_log_level", "LD_LOG_CRITICAL")
...
```


#### connect_wait (integer)


The time to wait (in miliseconds) when connecting to the LD service.
		An initial failure in connecting to the LD service may be addressed 
		by increasing this wait value.


The default value is 500 miliseconds.


```c title="Set connect_wait parameter"
...
modparam("launch_darkly", "connect_wait", 100)
...
```


#### re_init_interval (integer)


The minimum time interval (in seconds) to try again to init 
		the LD client in the situation when the module was not able to init 
		the LC connection at startup. In case of such failure, the module will 
		automatically re-try to init its LD client on-demand, whnever the 
		feature flag is checked from script, but not sooner than
		`re_init_interval`. Note: if there are no flag checkings to be
		performed, the re-init may be attempted longer than `re_init_interval`.


The default value is 10 seconds.


```c title="Set re_init_interval parameter"
...
modparam("launch_darkly", "re_init_interval", 30)
...
```


### Exported Functions


#### ld_feature_enabled( flag, user, [user_extra], [fallback])


Function to evaluate a LaunchDarkly boolean feature flag


Returns *1* if the flag was found TRUE
			or *-1* otherwise.


In case of error, the fallback (TRUE or FALSE) value will be
			returned  In such cases, a "fallback" TRUE is returned as 2 and a
			fallback FALSE as -2, so you can may a difference between a real
			TRUE (returned by the LD service) and a fallback TRUE due to an
			error.


This function can be used from any route.


The function has the following parameters:


- *flag* (string) - the key of the flag
					to evaluate. May not be NULL or empty.
- *user* (string) - the user to evaluate
					the flag against. May not be NULL or empty.
- *user_extra* (AVP, optional) - an AVP
					holding one or multiple key-value attributes to be 
					attached to the user. The format of the AVP value is
					"key=value".
- *fallback* (int, optional) - the value
					to be returned on error. By default FALSE will be returned.


```c title="ld_feature_enabled() function usage"
	...
	$avp(extra) = "domainId=123456";
	if (ld_feature_enabled("my-flag","opensips", $avp(extra), false))
		xlog("-------TRUE\n");
	else
		xlog("-------FALSE\n");
	...
	
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
