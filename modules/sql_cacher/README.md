---
title: "SQL Cacher Module"
description: "The sql_cacher module introduces the possibility to cache data from a SQL-based database (using different OpenSIPS modules which implement the DB API) into a cache system implemented in OpenSIPS through the CacheDB Interface. This is done by specifying the databases URLs, SQL table to be used,..."
---

## Admin Guide


### Overview


The sql_cacher module introduces the possibility to cache data from a
	SQL-based database (using different OpenSIPS modules which implement the DB API)
	into a cache system implemented in OpenSIPS through the CacheDB Interface.
	This is done by specifying the databases URLs, SQL table to be used, desired
	columns to be cached and other details in the OpenSIPS configuration script.


The cached data is available in the script through the read-only pseudovariable
	"$sql_cached_value" similar to a Key-Value system. A specified
	column from the SQL table has the role of "key" therefore the value
	of this column along with the name of a required column are provided as
	"parameters" to the pseudovariable returning the appropriate value of the column.


There are two types of caching available:


- *full caching* - the entire SQL table (all the rows) is loaded
		into the cache at OpenSIPS startup;
- *on demand* - the rows of the SQL table are loaded at runtime
		when appropriate keys are requested.


For on demand caching, the stored values have a configurable expire period after
	which they are permanently removed unless an MI reload function is called for a
	specific key. In the case of full caching the data is automatically reloaded at
	a configurable interval. Consequently if the data in the SQL database changes
	and a MI reload function is  called, the old data remains in cache only
	until it expires.


### Dependencies


The following modules must be loaded before this module:


- *The OpenSIPS modules that offer actual database back-end
		    	connection*


### Exported Parameters


#### cache_table (string)


This parameter can be set multiple times in order to cache multiple SQL
		tables or even the same table but with a different configuration. The module
		distinguishes those different entries by an "id" string.


The caching entry is specified via this parameter that has it's own
		subparameters. Each of those parameters are separated by a
		delimiter configured by [spec delimiter](#param_spec_delimiter)
		and have the following format:
		*param_name=param_value*
		The parameters are:


- *id* : cache entry id
- *db_url* : the URL of the SQL database
- *cachedb_url* : the URL of the CacheDB database
- *table* : SQL database table name
- *key* : SQL database column name of the "key" column
- *key_type* : data type for the SQL "key" column:
			
				string
				int
			
			If not present, default value is "string"
- *columns* : names of the columns to be cached from the
			SQL database, separated by a delimiter configured by
			[columns delimiter](#param_columns_delimiter).
			If not present, all the columns from the table will be cached
- *on_demand* : specifies the type of caching:
			
				0 : full caching
				1 : on demand
			
			If not present, default value is "0"
- *expire* : expire period for the values stored
			in the cache for the on demand caching type in seconds
			If not present, default value is "1 hour"


The parameters must be given in the exact order specified above.


Overall, the parameter does not have a default value, it must be set
		at least once in order to cache any table.


```opensips title="cache_table parameter usage"
modparam("sql_cacher", "cache_table",
"id=caching_name
db_url=mysql://root:opensips@localhost/opensips_2_2
cachedb_url=mongodb:mycluster://127.0.0.1:27017/db.col
table=table_name
key=column_name_0
columns=column_name_1 column_name_2 column_name_3
on_demand=0")
```


#### spec_delimiter (string)


The delimiter to be used in the caching entry specification provided in the
		*cache_table* parameter to separate the subparameters. It
		must be a single character.


The default value is newline.


```opensips title="spec_delimiter parameter usage"
modparam("sql_cacher", "spec_delimiter", "\n")
```


#### pvar_delimiter (string)


The delimiter to be used in the "$sql_cached_value"
		pseudovariable to separate the caching id, the desired column name
		and the value of the key. It must be a single character.


The default value is ":".


```opensips title="pvar_delimiter parameter usage"
modparam("sql_cacher", "pvar_delimiter", " ")
```


#### columns_delimiter (string)


The delimiter to be used in the *columns* subparameter of
		the caching entry specification provided in the *cache_table*
		parameter to separate the desired columns names. It must be a single character.


The default value is " "(space).


```opensips title="columns_delimiter parameter usage"
modparam("sql_cacher", "columns_delimiter", ",")
```


#### sql_fetch_nr_rows (integer)


The number of rows to be fetched into OpenSIPS private memory in one chunk from
		the SQL database driver. When querying large tables, adjust this parameter
		accordingly to avoid the filling of OpenSIPS private memory.


The default value is "100".


```opensips title="sql_fetch_nr_rows parameter usage"
modparam("sql_cacher", "sql_fetch_nr_rows", 1000)
```


#### full_caching_expire (integer)


Expire period for the values stored in cache for the full caching type
		in seconds. This is the longest time that deleted or modified data remains
		in cache.


The default value is "24 hours".


```opensips title="full_caching_expire parameter usage"
modparam("sql_cacher", "full_caching_expire", 3600)
```


#### reload_interval (integer)


This parameter represents how many seconds before the data expires (for full caching) the
		automatic reloading is triggered.


The default value is "60 s".


```opensips title="reload_interval parameter usage"
modparam("sql_cacher", "reload_interval", 5)
```


#### bigint_to_str (integer)


Controls bigint conversion.
		By default bigint values are returned as int.
		If the value stored in bigint is out of the int range,
		by enabling bigint to string conversion,
		the bigint value will be returned as string.


The default value is "0" (disabled).


```opensips title="bigint_to_str parameter usage"
modparam("sql_cacher", "bigint_to_str", 1)
```


### Exported Functions


#### sql_cache_dump(caching_id, columns, result_avps)


Dump all *columns* cached within the given *caching_id*,
	and write them to their respective *result_avps*.


Parameters:


- *caching_id* (string) - Identifier for the SQL cache
- *columns* (string) - the desired SQL columns to be dumped,
				specified as comma-separated values
- *result_avps* (string) - comma-separated list of AVPs where
				the results will be written to


Return Codes:


- **-1** - Internal Error
- **-2** - Zero Results Returned
- **1, 2, 3, ...** - Number of results returned into each output AVP


This function can be used from any route.


```opensips title="sql_cache_dump usage"
...
# Example of pulling all cached CNAM records
$var(n) = sql_cache_dump("cnam", "caller,callee,calling_name,fraud_score",
                "$avp(caller),$avp(callee),$avp(cnam),$avp(fraud)");
$var(i) = 0;
while ($var(i) < $var(n)) {
	xlog("Caller $(avp(caller)[$var(i)]) has CNAM $(avp(cnam)[$var(i)])\n");
	$var(i) += 1;
}
...
```


### Exported MI Functions


#### sql_cacher:reload


Replaces obsolete MI command: *sql_cacher_reload*.


Reloads the entire SQL table in cache or the single key (if key provided) in
			*full caching* mode.


Reloads the given key or invalidates all the keys in cache in *on demand* mode.


Parameters:


- *id* - the caching entry's id
- *key* (optional) - the specific key to be reloaded.


```bash title="sql_cacher:reload usage"
...
$ opensips-cli -x mi sql_cacher:reload subs_caching
...
$ opensips-cli -x mi sql_cacher:reload subs_caching alice@domain.com
...
```


### Exported Pseudo-Variables


#### $sql_cached_value(id{sep}col{sep}key)


The cached data is available through this read-only PV.The format
				is the following:


- *sep* : separator configured by
					[pvar delimiter](#param_pvar_delimiter)
- *id*  : cache entry id
- *col* : name of the required column
- *key* : value of the "key" column


```opensips title="sql_cached_value(id{sep}col{sep}key) pseudo-variable usage"
...
$avp(a) = $sql_cached_value(caching_name:column_name_1:key1);
...
				 
```


### Usage Example


This section provides an usage example for the caching of an SQL table.


Suppose one in interested in caching the columns: "host_name",
	"reply_code", "flags" and "next_domain"
	 from the "carrierfailureroute" table of the OpenSIPS database.


```c title="Example database content - carrierfailureroute table"
...
+----+---------+-----------+------------+--------+-----+-------------+
| id | domain  | host_name | reply_code | flags | mask | next_domain |
+----+---------+-----------+------------+-------+------+-------------+
|  1 |      99 |           | 408        |    16 |   16 |             |
|  2 |      99 | gw1       | 404        |     0 |    0 | 100         |
|  3 |      99 | gw2       | 50.        |     0 |    0 | 100         |
|  4 |      99 |           | 404        |  2048 | 2112 | asterisk-1  |
+----+---------+-----------+------------+-------+------+-------------+
...
		
```


In the first place, the details of the caching must be provided by setting
		the module parameter "cache_table" in the OpenSIPS configuration script.


```opensips title="Setting the cache_table parameter"
modparam("sql_cacher", "cache_table",
"id=carrier_fr_caching
db_url=mysql://root:opensips@localhost/opensips
cachedb_url=mongodb:mycluster://127.0.0.1:27017/my_db.col
table=carrierfailureroute
key=id
columns=host_name reply_code flags next_domain")
		
```


Next, the values of the cached columns ca be accessed through the "$sql_cached_value" PV.


```opensips title="Accessing cached values"
...
$avp(rc1) = $sql_cached_value(carrier_fr_caching:reply_code:1);
$avp(rc2) = $sql_cached_value(carrier_fr_caching:reply_code:2);
...
var(some_id)=4;
$avp(nd) = $sql_cached_value(carrier_fr_caching:next_domain:$var(some_id));
...
xlog("host name is: $sql_cached_value(carrier_fr_caching:host_name:2)");
...
		
```


### Exported Status/Report Identifiers


The module provides the "sql_cacher" Status/Report group, where each
	full cache is defined as a separate SR identifier. NOTE that there
	are no identifiers created for the on-demand caches.


#### [cache_entry_id]


The status of these identifiers reflects the readiness/status of the
	cached data (if available or not when being loaded from DB):


- *-2* - no data at all (initial status)
- *-1* - no data, initial loading in progress
- *1* - data loaded, partition ready
- *2* - data available, a reload in progress


In terms of reports/logs, the following events will be reported:


- starting DB data loading
- DB data loading failed, discarding
- DB data loading successfully completed
- N records loaded)


For how to access and use the Status/Report information, please see
	[https://www.opensips.org/Documentation/Interface-StatusReport-3-3](>https://www.opensips.org/Documentation/Interface-StatusReport-3-3).
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
