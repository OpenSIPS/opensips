---
title: "Prometheus Module"
description: "This module provides a HTTP interface for the [Prometheus](https://prometheus.io/) monitoring system, allowing it to fetch different statistics from OpenSIPS."
---

## Admin Guide


### Overview


This module provides a HTTP interface for the
		[Prometheus](https://prometheus.io/)
		monitoring system, allowing it to fetch different
		statistics from OpenSIPS.


In order to use it, you have to explicitely define the
		statistics you want to provide by listing them in the
		[statistics](#param_statistics) parameter.


Currently only *counter* and *gauge*
		metrics types are supported by the module, and whether to choose
		one or the other for a specific statistic is dictated by the way that
		statistic was defined either internally, or explicitely through the
		*variable* parameter of the *statistics*
		module.


Each exported statistic comes with a *group* label that
		indicates the group it belongs to.


### Dependencies


#### External Libraries or Applications


None


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *httpd* module.


### Exported Parameters


#### root(string)


Specifies the root metrics path Promethus uses to query the stats:
		http://[opensips_IP]:[opensips_httpd_port]/[root]


*The default value is "metrics".*


```c title="Set root parameter"
...
modparam("prometheus", "root", "prometheus")
...
```


#### prefix(string)


Appends a prefix to each statistic exported.


*The default value is "opensips".*


```c title="Set prefix parameter"
...
modparam("prometheus", "prefix", "opensips_1")
...
```


#### group_prefix(string)


Appends a prefix to the name of the group the statistic belongs to.


*The default value is "" (no group prefix).*


```c title="Set group_prefix parameter"
...
modparam("prometheus", "group_prefix", "opensips")
...
```


#### delimiter(string)


Specifies the delimiter to be used to separate *prefix*
		and *group_prefix*.


*The default value is "_".*


```c title="Set delimiter parameter"
...
modparam("prometheus", "delimiter", "-")
...
```


#### group_label(string)


Specifies the label used to store the group when *group_mode* is 2.


*The default value is "group".*


```c title="Set group_label parameter"
...
modparam("prometheus", "group_label", "grp")
...
```


#### group_mode(int)


Specifies how the group of the statistic should be provisioned to
		Prometheus. Available modes are:


- *0* - do not send the statistics groups.
- *1* - send the group in the name of the statstic.
timestamp
core
opensips_core_timestamp
group_prefix
- *2* - send the group as a label of the statstic.
group_label


*The default value is 0 (do not specify the group).*


```c title="Set group_mode parameter"
...
modparam("prometheus", "group_mode", 1)
...
```


#### statistics(string)


The statistics that are being exported by OpenSIPS, separated by space.
			The list can also contain statistics groups's names - to do that, you shall
			add a colon (*:*) at the end of the groups's name.


If the *all* value is used, then the module will expose
			all available statistics - therefore any other settings of this parameter
			is useless;


This parameter can be defined multiple times.


*The default value is empty: no metric is exported.*


```c title="Set statistics parameter"
...
# export the number of active dialogs and the load statistics class
modparam("prometheus", "statistics", "active_dialogs load:")
...
```


#### labels(string)


Rules that define how to convert the name of a statistic
			within a group to obtain the name and set of labels to be
			pushed in Prometheus.


The format is *group: regex*, where
			*group* represents the group of statistics
			for whom the regular expression should be applied for, and
			*regexp* is a regular expression used to
			match the statistic's name and convert it to the desired name
			and labels.


The *regex* format is
			*/matching_expression/substitution_expression/flags*.
			The *substitution_expression* resulted after
			the substituion should result in a string with the following
			format: *name:labels*, where
			*name* represents the name of the statistic
			as it will be pushed towards Prometheus, and *labels*
			the labels, expressed as *key=value* pairs
			separated by comma, as they are received by Prometheus.
			*Note* that the *labels*
			string resulted is concatenated to the other labeles as
			plain string - no other transformations are performed.


If a statistic's name within the declared group does not match the
			regular, or the resulted format does not comply with the
			*name:labels* format, the statistics transformations
			are ignored and it shall be printed as a regular statistic, as if
			the rule was not even used.


This parameter can be defined multiple times, even for a single group.
			However, if the statistic matches multiple regular expressions, only
			the first regular expression that matches is considered. The order
			they are checked is the order declared in the script.


*The default value is empty: statistic name is provided.*


```c title="Set statistics parameter"
...
# convert duration_gateway to stat duration with gateway as a label
modparam("prometheus", "labels", "group: /^(.*)_(.*)$/\1:gateway=\"\2\"/")
...
```


#### script_route(string)


Specifies the route name to be used to for adding custom prometheus information.


*The default value is "" - no custom route called.*


```c title="Set script_route parameter"
...
modparam("prometheus", "script_route", "my_custom_prometheus_route")
...
route[my_custom_prometheus_route] {
	# * the returned JSON needs to contain an array of objects
	#   containing a header and a values field
	# * the header field to contain the custom prometheus stats header
	# * the values field is an array itself, of name/value objects
	#   used for individual stats publishing
	return (1, '[{
        "header": "# TYPE opensips_total_cps gauge",
        "values": [
            {
                "name": "opensips_total_cps",
                "value": 3
            }
        ]
    }, {
        "header": "# TYPE opensips_disabled_rtpengine gauge",
        "values": [
            {
                "name": "opensips_disabled_rtpengine",
                "value": 0
            }
        ]
    }]');
}
...
```


### Exported Functions


#### prometheus_declare_stat(name, [type], [help])


*NOTE:* this function can only be used in the
			route declared in the [script route](#param_script_route) parameter.


Declares a custom statistic exported to Prometheus server. It specifies
			its type and optionally a help string.


Parameters


- *name* (string) - the name of the statistic
*type* (string, optional) - the type of the
			statistic (i.e. *counter* or *gauge*).
			If missing the statistic is declared as *gauge*.
*help* (string, optional) - an optional value
			used to describe the statistic meaning. If missing, it is not used.


This function can only be used in the request
			route declared in the [script route](#param_script_route) parameter.


```c title="prometheus_declare_stat usage"
...
modparam("prometheus", "script_route", "my_custom_prometheus_route")
...
route[my_custom_prometheus_route] {
	...
	prometheus_declare_stat("opensips_cps");
	prometheus_push_stat(3);
	...
}
```


#### prometheus_push_stat(value, [label_name], [label_value])


*NOTE:* this function can only be used in the
			route declared in the [script route](#param_script_route) parameter.


Pushes a custom statistic value and optionally a set of labels
			to the Prometheus server.


*NOTE:* a statistic's value should only be pushed
			after it had been declared using the
			[prometheus declare stat](#func_prometheus_declare_stat) function.


Parameters


- *value* (integer) - the value of the statistic
*label_name* (string, optional) - used to define
			labels for the pushed statistic. If the *label_value*
			parameter is missing, this parameter is appended to the name of the
			statisic - this means that it should contain the whole set of labels
				for the value (including curly brackets). If the
			*label_value* is provided as well, then the parameter
			should only contain one label's name.
*label_value* (string, optional) - the value that
			should be used for the *label_name* parameter label.


This function can only be used in the request
			route declared in the [script route](#param_script_route) parameter.


```c title="prometheus_push_stat usage"
...
modparam("prometheus", "script_route", "my_custom_prometheus_route")
...
route[my_custom_prometheus_route] {
	...
	prometheus_declare_stat("opensips_cps");
	prometheus_push_stat(3); # no label is being used
	prometheus_declare_stat("opensips_cc");
	# the next two are equivalent
	prometheus_push_stat(10, "{gateway=\"gw1\"}"); # no label is being used
	prometheus_push_stat(10, "gateway", "gw1"); # same as the above
	...
}
```


### Examples


In order to have Prometheus query OpenSIPS for statistics, you need to
			tell him where to get statistics from. To do that, you should define
			a scarpe job in Prometheus's *scrape_configs* config,
			indicating the IP and port you've configured the *httpd*
			module to listen on (default: *0.0.0.0:8888*).


```c title="Prometheus Scrape Config"
scrape_configs:
  - job_name: opensips

    static_configs:
    - targets: ['localhost:8888']
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
