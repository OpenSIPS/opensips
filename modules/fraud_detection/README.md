---
title: "Fraud Detection Module"
description: "This module provides a way to prevent some basic fraud attacks. Alerts are provided through return codes and events."
---

## Admin Guide


### Overview


This module provides a way to prevent some basic fraud attacks.
		Alerts are provided through return codes and events.


#### Monitored Stats


Basically, this module watches the following parameters:


- Total calls
- Calls per minute
- Concurrent calls
- Number of sequential calls
- Call duration


Each of the above parameters is monitored for every user and
			every called prefix separately. The stats are altered whenever
			the *check_fraud* function is called. The
			function assumes a new call is made, and checks the called
			number against all the rules from the supplied profile. The
			rule's prefix is considered to be the called prefix which along with
			the provided user will be used to monitor values for the 5
			parameters.


#### Fraud rules


A rule is a set of two thresholds (warning and critical thresholds) for each of the
			five parameters (as described above) and is only available for a specified prefix.
			Further more, a rule will only match between the indicated hours in the indicated days
			of the week (similarly to a dr rule). A fraud profile is simply a group of fraud rules
			and is used to only to limit the list of rules to match when calling the check_fraud
			function.


### Dependencies


#### OpenSIPS modules


The following modules must be loaded before this module:


- drouting
- dialog


#### External libraries or applications


The following libraries or applications must be installed before
		running OpenSIPS with this module:


- *none*.


### Exported Parameters


#### db_url (string)


Database where to load the rules from.


*Default value is "NULL". At least one db_url should
			be defined for the fraud_detection module to work.*


```opensips title="Set the 'db_url' parameter"
...
modparam("fraud_detection", "db_url", "mysql://user:passwb@localhost/database")
...
```


#### use_utc_time (integer)


Set this parameter to non-zero in order to enable UTC-based interval
		matching and statistics resets, rather than local time-based.


*The default value is "0" (use local time).*


```opensips title="Set the 'use_utc_time' parameter"
...
modparam("fraud_detection", "use_utc_time", 1)
...
```


#### table_name (string)


If you want to load the rules from the database you must set
		this parameter as the database name.


*The default value is "fraud_detection".*


```opensips title="Set the 'table_name' parameter"
...
modparam("fraud_detection", "table_name", "my_fraud")
...
```


#### rid_col (string)


The column's name in the database storing the
			fraud rule's id.


*Default value is "ruleid".*


```opensips title="Set 'rid_col' parameter"
...
modparam("fraud_detection", "rid_col", "theruleid")
...
```


#### pid_col (string)


The column's name in the database storing the
			fraud profile's id.


Please keep in mind that a profile is merely
			a set of rules.


*Default value is "profileid".*


```opensips title="Set 'pid_col' parameter"
...
modparam("fraud_detection", "pid_col", "profile")
...
```


#### prefix_col (string)


The column's name in the database storing the
			prefix for which the fraud rule will match.


*Default value is "prefix".*


```opensips title="Set 'prefix_col' parameter"
...
modparam("fraud_detection", "prefix_col", "myprefix")
...
```


#### start_h (string)


The column's name in the database storing the
			the start time of the interval in which the
			rule will match.


The time needs to be specified as string using
			the format: "HH:MM"


*Default value is "start_hour".*


```opensips title="Set 'start_h' parameter"
...
modparam("fraud_detection", "start_h", "the_start_time")
...
```


#### end_h (string)


The column's name in the database storing the
			the end time of the interval in which the
			rule will match.


The time needs to be specified as string using
			the format: "HH:MM"


*Default value is "end_hour".*


```opensips title="Set 'end_h' parameter"
...
modparam("fraud_detection", "end_h", "the_end_time")
...
```


#### days_col (string)


The column's name in the database storing the
			week days in which the fraud rule's interval
			is available.


The daysoftheweek needs to be specified as a
			string containing a list of days or intervals.
			Each day must be specified using the first
			three letters of its name. A valid string
			would be: "Fri-Mon, Wed, Thu"


*Default value is "daysoftheweek".*


```opensips title="Set 'days_col' parameter"
...
modparam("fraud_detection", "days_col", "days")
...
```


#### cpm_thresh_warn_col (string)


The column's name in the database storing the
			warning threshold value for calls per minute.


*Default value is "cpm_warning".*


```opensips title="Set 'cpm_thresh_warn_col' parameter"
...
modparam("fraud_detection", "cpm_thresh_warn_col", "cpm_warn_thresh")
...
```


#### cpm_thresh_crit_col (string)


The column's name in the database storing the
			critical threshold value for calls per minute.


*Default value is "cpm_critical".*


```opensips title="Set 'cpm_thresh_crit_col' parameter"
...
modparam("fraud_detection", "cpm_thresh_crit_col", "cpm_crit_thresh")
...
```


#### calldur_thresh_warn_col (string)


The column's name in the database storing the
			warning threshold value for call duration.


*Default value is "call_duration_warning".*


```opensips title="Set 'calldur_thresh_warn_col' parameter"
...
modparam("fraud_detection", "calldur_thresh_warn_col", "calldur_warn_thresh")
...
```


#### calldur_thresh_crit_col (string)


The column's name in the database storing the
			critical threshold value for call duration.


*Default value is "call_duration_critical".*


```opensips title="Set 'calldur_thresh_crit_col' parameter"
...
modparam("fraud_detection", "calldur_thresh_crit_col", "calldur_crit_thresh")
...
```


#### totalc_thresh_warn_col (string)


The column's name in the database storing the
			warning threshold value for the number of total calls.


*Default value is "total_calls_warning".*


```opensips title="Set 'totalc_thresh_warn_col' parameter"
...
modparam("fraud_detection", "totalc_thresh_warn_col", "totalc_warn_thresh")
...
```


#### totalc_thresh_crit_col (string)


The column's name in the database storing the
			critical threshold value for the number of total calls.


*Default value is "total_calls_critical".*


```opensips title="Set 'totalc_thresh_crit_col' parameter"
...
modparam("fraud_detection", "totalc_thresh_crit_col", "totalc_crit_thresh")
...
```


#### concalls_thresh_warn_col (string)


The column's name in the database storing the
			warning threshold value for the number of
			concurrent calls.


*Default value is "concurrent_calls_warning".*


```opensips title="Set 'concalls_thresh_warn_col' parameter"
...
modparam("fraud_detection", "concalls_thresh_warn_col", "concalls_warn_thresh")
...
```


#### concalls_thresh_crit_col (string)


The column's name in the database storing the
			critical threshold value for the number of
			concurrent calls.


*Default value is "concurrent_calls_critical".*


```opensips title="Set 'concalls_thresh_crit_col' parameter"
...
modparam("fraud_detection", "concalls_thresh_crit_col", "concalls_crit_thresh")
...
```


#### seqcalls_thresh_warn_col (string)


The column's name in the database storing the
			warning threshold value for the number of
			sequential calls.


*Default value is "sequential_calls_warning".*


```opensips title="Set 'seqcalls_thresh_warn_col' parameter"
...
modparam("fraud_detection", "seqcalls_thresh_warn_col", "seqcalls_warn_thresh")
...
```


#### seqcalls_thresh_crit_col (string)


The column's name in the database storing the
			critical threshold value for the number of
			sequential calls.


*Default value is "sequential_calls_critical".*


```opensips title="Set 'seqcalls_thresh_crit_col' parameter"
...
modparam("fraud_detection", "seqcalls_thresh_crit_col", "seqcalls_crit_thresh")
...
```


### Exported Functions


#### check_fraud(user, number, profile_id)


This method should be called each time a given *user*
			calls a given *number*. It will try to match a fraud rule
			within the given fraud profile and update the stats (see above). Furthermore,
			the stats will be checked against the rule's thresholds. If any of the stats
			is above its threshold value, the appropriate event will also be raised
			(see further details below).


Designed to only work with initial INVITE messages!  If a dialog is
			not already present, one will be created (equivalent of
			create_dialog()).


Meaning of the parameters is as follows:


- *user* (string) - the user who is making the call. Please keep in mind that
				the user doesn't have to be registered. This string is only used to keep different stats
				for different registered users.
- *number* (string) - the number the user is calling to.
- *profile_id* (int) - the fraud profile id (i.e. the subset of fraud
				rules) in which to try and find a matching fraud rule.


The meaning of the return code is as follows:


- *2* - no matching fraud rule was found
- *1* - a matching rule was found, but there is no
					parameter above the rule's threshlod, i.e - everything is ok
- *-1* - there is a parameter above the warning threshold value.
					Check the raised event for more info
- *-2* - there is a parameter above the critical threshold value.
					Check the raised event for more info
- *-3* - something went wrong (internal mechanism failed)


This function can be used from REQUEST_ROUTE and ONREPLY_ROUTE.


### Exported MI Functions


#### fraud_detection:show_stats


Replaces obsolete MI command: *show_fraud_stats*.


Show the current statistics for all dials of a
		*user* to a *prefix*.


NOTE: Since the fraud statistics are refreshed on-the-fly, as
		check_fraud() is called, **this function will
		return stale data** if check_fraud() has not been called at
		least once for the (user, prefix) pair within a newly matching time
		interval!


Name: *fraud_detection:show_stats*


Parameters:


- user
- prefix


#### fraud_detection:reload


Replaces obsolete MI command: *fraud_reload*.


Reload the all the fraud rules.


Name: *fraud_detection:reload*


Parameters: *none*


### Exported Events


#### E_FRD_WARNING


This event is raised whenever one of the 5 monitored parameters
			is above the warning threshold value


Parameters:


- *param* - the name of the parameter.
- *value* - the current value of the parameter.
- *threshold* - the warning threshold value.
- *user* - the user who initiated the call.
- *called_number* - the number that was called.
- *rule_id* - the id of the fraud rule that matched
					when the call was initiated
- *profile_id* - the profile id used


#### E_FRD_CRITICAL


This event is raised whenever one of the 5 monitored parameters
			is above the warning threshold value


Parameters:


- *param* - the name of the parameter.
- *value* - the current value of the parameter.
- *threshold* - the warning threshold value.
- *user* - the user who initiated the call.
- *called_number* - the number that was called.
- *rule_id* - the id of the fraud rule that matched
					when the call was initiated
- *profile_id* - the profile id used
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
