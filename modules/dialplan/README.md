---
title: "dialplan Module"
description: "This module implements generic string translations based on matching and replacement rules. It can be used to manipulate R-URI or a PV and to translated to a new format/value."
---

## Admin Guide


### Overview


This module implements generic string translations based on matching and
	replacement rules. It can be used to manipulate R-URI or a PV and to
	translated to a new format/value.


### How it works


At startup, the module will load all transformation rules from one or more
	dialplan-compatible tables. The data of each table will be stored in a
	*partition* (data source), which is defined by the
	"db_url" and "table_name" properties.  Every table row will be stored in
	memory as a translation rule. Each rule will describe how the matching
	should be made, how the input value should be modified and which attributes
	should be set for the matching transformation.


A dialplan rule can be of two types:


- *"String matching" rule* - performs a
		string equality test against the input string. The case of the
		characters can be ignored by enabling bit 1 of the rule's "match_flags"
		bitmask column
		(i.e. set the column value to 1 or 0, for insensitive or sensitive)
- *"Regex matching" rule* - uses Perl
		Compatible Regular Expressions, and will attempt to match the rule's
		expression against an input string. The regex
		maching can be done in a caseless manner by enabling bit 1 of the
		rule's "match_flags" bitmask column
		(i.e. set the column value to 1 or 0, for insensitive or sensitive)


The module provides the *dp_translate()* script function,
	which expects an input **string** value that
	will be matched, at worst, against all rules of a partition.


Internally, the module groups a partition's rules into two sets, "string" and "regex".
	The matching logic will attempt to find the first match within each of
	these two sets of rules. Each set will be iterated in
	**ascending** order of priority. If an input
	string happens to match a rule in each of the two sets, the rule with the
	smallest priority will be chosen. Furthermore, should these two matching
	rules also have equal priorities, the one with the smallest "id" field
	(the unique key) will be chosen.


Once a single rule is decided upon, the defined transformation (if any) is
	applied and the result is returned as output value. Also, if any string
	attribute is associated to the rule, this will be returned to the script
	along with the output value.


### Usage cases


The module can be used to implement dialplans - to do auto completion of
	the dialed numbers (e.g. national to international), to convert generic
	numbers to specific numbers (e.g. for emergency numbers).


Also the module can be used for detecting ranges or sets of numbers mapped
	on a service/case - the "attributes" string column can be used here to
	store extra information about the service/case.


Non-SIP string translation can also be implemented - like converting country
	names from all possible formats to a canonical format:
	(UK, England, United Kingdom) -> GB.


Any other string-based translation or detection for whatever other purposes.


### Database structure and usage


Depending what kind of operation (translation, matching, etc) you want
		to do with the module, you need to populate the appropriate DB records.


The definition of the tables used by the dialplan module can be found
		at [[https://opensips.org/docs/db/db-schema-devel.html](https://opensips.org/docs/db/db-schema-devel.html)#AEN1501](https://opensips.org/db-schema.html#AEN1501)


#### What to place in table


##### String translation (regexp detection, subst translation)


Recognize a number block in all forms (international, national)
			and convert it to a canonical format (E.164)


- *match_op* = 1 (regexp)
- *match_exp* = "^(0040|\+40|0|40)21[0-9]+" ;
				regular expression that will be used to match with this rule (if
				the rule should be applied for the input string)
- *match_flags* = 0 (0 - case sensitive,
				1 - case insensitive matching)
- *subst_exp* = "^(0040|\+40|0|40)(.+)" ;
				regular expression used to do the transformation (first part
				of the subst operation)
- *repl_exp* = "40\2" ; second part of the
				subst (output) - linked to the subst_exp field; when both
				defined, they work as a subst()


##### String translation (regexp detection, replacement)


Recognize the name of a country (multiple languages) and convert
			it to a single, fixed value


- *match_op* = 1 (regexp)
- *match_exp* = "^((Germany)|(Germania)|(Deutschland)|(DE))" ;
				regular expression that will be used to match with this rule (if
				the rule should be applied for the input string)
- *match_flags* = 0 (0 - case sensitive,
				1 - case insensitive matching)
- *subst_exp* = NULL ;
				when translation is actually a replacement, this field must
				be NULL.
- *repl_exp* = "DE" ; static string to
				replace the input - whenever this rule will match, it will
				return this string as output.


##### Number detection (regexp detection, no replacement)


Recognize a block of numbers as belong to a single service and
			signalize this via an attribute.


- *match_op* = 1 (regexp)
- *match_exp* = "^021456[0-9]{5}" ;
				regular expression that will be used to match with this rule (if
				the rule should be applied for the input string)
- *match_flags* = 0 (0 - case sensitive,
				1 - case insensitive matching)
- *subst_exp* = NULL ;
				no translation
- *repl_exp* = NULL ;
				no translation
- *attrs* = "serviceX" ;
				whatever string you will get into OpenSIPS script and it will
				provide you more information (totally custom)


##### String conversion (equal detection, replacement)


Recognize a fixed string/number and replace it with something fixed.


- *match_op* = 0 (equal)
- *match_exp* = "SIP server" ;
				string to be matched
- *match_flags* = 0 (0 - case sensitive,
				1 - case insensitive matching)
- *subst_exp* = NULL ;
				no subst translation
- *repl_exp* = "OpenSIPS" ;
				output string


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *None*


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *libpcre-dev - the development libraries of [PCRE](http://www.pcre.org/)*.


### Exported Parameters


#### partition (string)


Specify a new dialplan partition (data source).  This parameter may
		be set multiple times.  Each partition may have a specific "db_url" and
		"table_name".  If not specified, these values will be inherited from
		[db url](#param_db_url), db_default_url or
		[table name](#param_table_name), respectively.  The name of
		the default partition is 'default'.


Note: OpenSIPS will validate each partition, so make sure to add any
		required entries in the "version" table of each database defined
		through the 'db_url' property.


```c title="Defining the 'pstn' partition"
...
modparam("dialplan", "partition", "
	pstn:
		table_name = dialplan;
		db_url = mysql://opensips:opensipsrw@127.0.0.1/opensips")
...
		
```


```c title="Define the 'pstn' partition and make it the 'default' partition, so we avoid loading the 'dialplan' table"
...
db_default_url = "mysql://opensips:opensipsrw@localhost/opensips"

loadmodule "dialplan.so"
modparam("dialplan", "partition", "
	pstn:
		table_name = dialplan_pstn")
modparam("dialplan", "partition", "default: pstn")
...
		
```


#### db_url (string)


The default DB connection of the module, overriding the global
		'db_default_url' setting.  Once specified, partitions which are missing
		the 'db_url' property will inherit their URL from this value.


*Default value is NULL (not set).*


```c title="Set db_url parameter"
...
modparam("dialplan", "db_url", "mysql://user:passwd@localhost/db")
...
		
```


#### table_name (string)


The default name of the table from which to load translation rules.
		Partitions which are missing the 'table_name' property will inherit
		their table name from this value.


*Default value is "dialplan".*


```c title="Set table_name parameter"
...
modparam("dialplan", "table_name", "my_table")
...
		
```


#### dpid_col (string)


The column name to store the dialplan ID group.


*Default value is "dpid".*


```c title="Set dpid_col parameter"
...
modparam("dialplan", "dpid_col", "column_name")
...
		
```


#### pr_col (string)


The column name to store the priority of the corresponding rule from
		the table row. Smaller priority values have higher precedence.


*Default value is "pr".*


```c title="Set pr_col parameter"
...
modparam("dialplan", "pr_col", "column_name")
...
		
```


#### match_op_col (string)


The column name to store the type of matching of the rule.


*Default value is "match_op".*


```c title="Set match_op_col parameter"
...
modparam("dialplan", "match_op_col", "column_name")
...
		
```


#### match_exp_col (string)


The column name to store the rule match expression.


*Default value is "match_exp".*


```c title="Set match_exp_col parameter"
...
modparam("dialplan", "match_exp_col", "column_name")
...
		
```


#### match_flags_col (string)


The column name to store various matching flags. Currently
		0 - case sensitive matching, 1 - case insensitive matching.


*Default value is "match_flags".*


```c title="Set match_flags_col parameter"
...
modparam("dialplan", "match_flags_col", "column_name")
...
		
```


#### subst_exp_col (string)


The column name to store the rule's substitution expression.


*Default value is "subst_exp".*


```c title="Set subs_exp_col parameter"
...
modparam("dialplan", "subst_exp_col", "column_name")
...
		
```


#### repl_exp_col (string)


The column name to store the rule's replacement expression.


*Default value is "repl_exp".*


```c title="Set repl_exp_col parameter"
...
modparam("dialplan", "repl_exp_col", "column_name")
...
		
```


#### timerec_col (integer)


The column name that indicates an additional time recurrence check 
		within the rule (column values are RFC 2445-compatible strings).  The
		value format is identical to the input of the
		[check_time_rec()](../cfgutils#func_check_time_rec)
		function of the *cfgutils* module, including the
		optional use of logical operators linking multiple such strings into a
		larger expression.


*Default value is "timerec".*


```c title="Set timerec_col parameter"
...
modparam("dialplan", "timerec_col", "month_match")
...
		
```


#### disabled_col (integer)


The column name that indicates if the dialplan rule is disabled.


*Default value is "disabled".*


```c title="Set disabled_col parameter"
...
modparam("dialplan", "disabled_col", "disabled_column")
...
		
```


#### attrs_col (string)


The column name to store rule-specific attributes.


*Default value is "attrs".*


```c title="Set attrs_col parameter"
...
modparam("dialplan", "attrs_col", "column_name")
...
		
```


### Exported Functions


#### dp_translate(id, input, [out_var], [attrs_var], [partition])


Will try to translate the src string into dest string according to
	the translation rules with dialplan ID equal to id.


Meaning of the parameters is as follows:


- *id* (int) - the dialplan id to be used for matching rules
- *input* (string) - input string to be used for rule matching
		and for computing the output string.
- *out_var* (var, optional) - variable to be populated/written with 
		the output string (if provided by the translation rule), on a successful translation.
- *attrs_var* (var, optional) - variable to be populated/written 
		with the "attributes" field of the translation rule, on a successful translation.
		If the field is NULL or empty-string, the variable will be set to empty-string.
- *partition* (string, optional) - the name of the partition
		(set of data) to be used for locating the DP ID.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, LOCAL_ROUTE,
	BRANCH_ROUTE, STARTUP_ROUTE, TIMER_ROUTE and EVENT_ROUTE.


```c title="dp_translate usage"
...
dp_translate(240, $ru, $var(out));
xlog("translated into '$var(out)' \n");
...
	
```


```c title="dp_translate usage"
...
$avp(src) = $ruri.user;
dp_translate($var(x), $avp(src), $var(y), $var(attrs));
xlog("translated to var $var(y) with attributes: '$var(attrs)'\n");
...
	
```


```c title="dp_translate usage"
...
$var(id) = 10;
dp_translate($var(id), $avp(in), , $avp(attrs), "example_partition");
xlog("matched with attributes '$avp(attrs) against example_partition'\n");
...
	
```


```c title="dp_translate usage"
...
dp_translate(10, $var(in), , , $var(part));
xlog("'$var(in)' matched against partition '$var(part)'\n")
...
	
```


### Exported MI Functions


#### dialplan:reload


Replaces obsolete MI command: *dp_reload*.


It will update the translation rules, loading the database info.


Name: *dialplan:reload*


Parameters: *1*


- *partition* (optional) - Partition
					to be reloaded.  If not specified, all partitions will be
					reloaded.


MI DATAGRAM Command Format:


```c
		opensips-cli -x mi dialplan:reload
		
```


#### dialplan:translate


Replaces obsolete MI command: *dp_translate*.


It will apply a translation rule identified by a dialplan
				id on an input string.


Name: *dialplan:translate*


Parameters: *3*


- *dpid* - the dpid of the rule set used for
			match the input string
- *input* - the input string
- *partition* - (optional) the name of the 
			partition when the dpid is located


MI DATAGRAM Command Format:


```c
        opensips-cli -x mi dialplan:translate 10 +40123456789
		
```


#### dialplan:show_partition


Replaces obsolete MI command: *dp_show_partition*.


Display partition(s) details.


Name: *dialplan:show_partition*


Parameters: *2*


- *partition* (optional) - The 
				partition name. If no partition is specified, all known 
				partitions will be listed.


MI DATAGRAM Command Format:


```c
        opensips-cli -x mi dialplan:show_partition default
		
```


### Exported Status/Report Identifiers


The module provides the "dialplan" Status/Report group, where each
	dialplan partition is defined as a separate SR identifier.


#### [partition_name]


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
- N rules loaded (N discarded)


```c
    {
        "Name": "default",
        "Reports": [
            {
                "Timestamp": 1652778355,
                "Date": "Tue May 17 12:05:55 2022",
                "Log": "starting DB data loading"
            },
            {
                "Timestamp": 1652778355,
                "Date": "Tue May 17 12:05:55 2022",
                "Log": "DB data loading successfully completed"
            },
            {
                "Timestamp": 1652778355,
                "Date": "Tue May 17 12:05:55 2022",
                "Log": "5 rules loaded (0 discarded)"
            },
            {
                "Timestamp": 1652778405,
                "Date": "Tue May 17 12:06:45 2022",
                "Log": "starting DB data loading"
            },
            {
                "Timestamp": 1652778405,
                "Date": "Tue May 17 12:06:45 2022",
                "Log": "DB data loading successfully completed"
            },
            {
                "Timestamp": 1652778405,
                "Date": "Tue May 17 12:06:45 2022",
                "Log": "5 rules loaded (0 discarded)"
            }
        ]
    }
	
```


For how to access and use the Status/Report information, please see
	[https://www.opensips.org/Documentation/Interface-StatusReport-3-3](>https://www.opensips.org/Documentation/Interface-StatusReport-3-3).


### Installation


The modules requires one table in OpenSIPS database: dialplan.The SQL
		syntax to create them can be found in dialplan-create.sql
		script in the database directories in the opensips/scripts folder.
		You can also find the complete database documentation on the
		project webpage, [https://opensips.org/docs/db/db-schema-devel.html](https://opensips.org/docs/db/db-schema-devel.html).


## Developer Guide


The module does not provide any API to use in other OpenSIPS modules.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
