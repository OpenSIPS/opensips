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


### Exported Functions


No function exported to be used from configuration file.


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
