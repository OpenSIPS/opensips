---
title: "domain Module"
description: "Domain module implements checks that based on domain table determine if a host part of an URI is \"local\" or not. A \"local\" domain is one that the proxy is responsible for."
---

## Admin Guide


### Overview


Domain module implements checks that based on domain table determine 
		if a host part of an URI is "local" or 
		not.  A "local" domain is one that the proxy is responsible 
		for.


Domain module operates in caching or non-caching mode depending on 
		value of module parameter `db_mode`.
		In caching mode domain module reads the contents of domain table into 
		cache memory when the module is loaded.  After that domain table is 
		re-read only when module is given domain:reload MI command.  Any
		changes in domain table must thus be followed by 
		"domain:reload" command in order to reflect them in
		module behavior. In non-caching mode domain module always queries domain
		table in the database.


Caching is implemented using a hash table. The size of the hash table 
		is given by HASH_SIZE constant defined in domain_mod.h. 
		Its "factory default" value is 128.


### Dependencies


The module depends on the following modules (in the other words the 
		listed modules must be loaded before this module):


- *database* -- Any database module


### Exported Parameters


#### db_url (string)


This is URL of the database to be used.


Default value is 
			"mysql://opensipsro:opensipsro@localhost/opensips"


```c title="Setting db_url parameter"
modparam("domain", "db_url", "mysql://ser:pass@db_host/ser")
```


#### db_mode (integer)


Database mode: 0 means non-caching, 1 means caching.


Default value is 0 (non-caching).


```c title="db_mode example"
modparam("domain", "db_mode", 1)   # Use caching
```


#### domain_table (string)


Name of table containing names of local domains that the proxy is 
		responsible for. Local users must have in their sip uri a host part 
		that is equal to one of these domains.


Default value is "domain".


```c title="Setting domain_table parameter"
modparam("domain", "domain_table", "new_name")
```


#### domain_col (string)


Name of column containing domains in domain table.


Default value is "domain".


```c title="Setting domain_col parameter"
modparam("domain", "domain_col", "domain_name")
```


#### attrs_col (string)


Name of column containing attributes in domain table.


Default value is "attrs".


```c title="Setting attrs_col parameter"
modparam("domain", "attrs_col", "attributes")
```


#### subdomain_col (int)


Name of the "accept_subdomain" column in the domain table.
		A positive value for the column means the domain accepts subdomains.
		A 0 value means it does not.


Default value is "accept_subdomain".


```c title="Setting subdomain_col parameter"
modparam("domain", "subdomain_col", "has_subdomain")
```


### Exported Functions


#### is_from_local([attrs_var])


Checks based on domain table if host part of From header uri is
		one of the local domains that the proxy is responsible for.
		The argument is optional and if present it should contain a writable
		variable that will be populated with the attributes from the
		database.


This function can be used from REQUEST_ROUTE.


```c title="is_from_local usage"
...
if (is_from_local()) {
	...
};
...
if (is_from_local($var(attrs))) {
	xlog("Domain attributes are $var(attrs)\n");
	...
};
...
		
```


#### is_uri_host_local([attrs_var])


If called from route or failure route block, checks
		based on domain table if host part of Request-URI is one
		of the local domains that the proxy is responsible for.
		If called from branch route, the test is made on host
		part of URI of first branch, which thus must have been
		appended to the transaction before is_uri_host_local()
		is called.
		The argument is optional and if present it should contain a writable
		variable that will be populated with the attributes from the
		database.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		BRANCH_ROUTE.


```c title="is_uri_host_local usage"
...
if (is_uri_host_local()) {
	...
};
...
if (is_uri_host_local($var(attrs))) {
	xlog("Domain attributes are $var(attrs)\n");
	...
};
		
```


#### is_domain_local(domain, [attrs_var])


This function checks if the domain contained in the first parameter is local.


This function is a generalized form of the is_from_local()
		and is_uri_host_local() functions, being able to completely
		replace them and also extends them by allowing the domain to
		be taken from any of the above mentioned sources.
                The following equivalences exist:


- is_domain_local($rd) is same as is_uri_host_local()
- is_domain_local($fd) is same as is_from_local()


Parameters:


- *domain* (string)
- *attrs_var* (var, optional) - a writable
				variable that will be populated with the attributes from the
				database.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		BRANCH_ROUTE.


```c title="is_domain_local usage"
...
if (is_domain_local($rd)) {
	...
};
if (is_domain_local($fd)) {
	...
};
if (is_domain_local($avp(some_avp_alias))) {
	...
};
if (is_domain_local($avp(850))) {
	...
};
if (is_domain_local($avp(some_avp))) {
	...
};
if (is_domain_local($avp(some_avp), $avp(attrs))) {
	xlog("Domain attributes are $avp(attrs)\n");
	...
};
...
		
```


### Exported MI Functions


#### domain:reload


Replaces obsolete MI command: *domain_reload*.


Causes domain module to re-read the contents of domain table
		into cache memory.


Name: *domain:reload*


Parameters: *none*


MI FIFO Command Format:


```c
		opensips-cli -x mi domain:reload
		
```


#### domain:dump


Replaces obsolete MI command: *domain_dump*.


Causes domain module to dump hash indexes and domain names in
		its cache memory.


Name: *domain:dump*


Parameters: *none*


MI FIFO Command Format:


```c
		opensips-cli -x mi domain:dump
		
```


### Known Limitations


There is an unlikely race condition on domain list update.  If a 
		process uses a table, which is reloaded at the same time twice 
		through FIFO, the second reload will delete the 
		original table still in use by the process.


## Developer Guide


The module provides is_domain_local API
    function for use by other OpenSIPS modules.


### Available Functions


#### is_domain_local(domain)


Checks if domain given in str* parameter is local.


The function returns 1 if domain is local and -1 if
		domain is not local or if an error occurred.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
