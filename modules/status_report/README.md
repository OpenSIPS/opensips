---
title: "Status/Reports Module"
description: "The Status/Report module is a wrapper over the internal status/report framework, allowing the script writer to dynamically define and use of SR groups."
---

## Admin Guide


### Overview


The Status/Report module is a wrapper over the 
		internal status/report framework, allowing the script writer to 
		dynamically define and use of SR groups.


By bringing the Status/Report support into the script, it opens the
		possibility to create custom reports from script, depending on
		the logic you have there.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### script_sr_group (string)


Name of a new Status/Report group to be created and later used
		from script level.


This parameter may be defined multiple times, in order to define
		multiple groups.


```opensips title="script_sr_group example"
modparam("status_report", "script_sr_group", "security")
modparam("status_report", "script_sr_group", "alarms")
```


### Exported Functions


#### sr_set_status( group, status, [details])


Sets a new status (and details) for a Status/Report group.


Meaning of the parameters is as follows:


- *group* (string) - the name of the
			SR group; you can change the status only for the groups defined via
			this module (as parameter).
- *status* (int) - the new status value
			( strict positive meaning OK, strict negative meaning NOT OK,
			0 is not accepts, it is converted to 1 automatically).
- *details* (string, optional) - a
			descripting text to detail the status value


This function can be used from any route.


```opensips title="sr_set_status usage"
...
sr_set_status( "script_caching", 1, "completed");
...
```


#### sr_add_report( group, report)


Adds a new report/log to a Status/Report group.This must have been
		defined via this module too.


Meaning of the parameters is as follows:


- *group* (string) - the name of the
			SR group; you can change the status only for the groups defined via
			this module (as parameter).
*report* (string) - the log to be added.


This function can be used from any route.


```opensips title="sr_add_report usage"
...
sr_add_report("security","IP $si detected as attacker");
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
