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


At startup, the module will load a set of transformation rules from a 
	database. Every database raw will be stored in memory as a translation 
	rule. Each rule will describe how the matching should be made, how the 
	input value should be modified and which attributes should be set for 
	the matching transformation.


The module expects an input value which will be matched against a rules
	via regexp or string matching. Overlapping matching expressions can be
	controlled via priorities. Once a rule is matched, the defined 
	transformation (if any) is applied and the result is returned as output 
	value. Also, if any string attribute is associated to the rule, this will 
	be returned to the script along with the output value.


*The first matching rule will be processed.*


### Usage cases


The module can be used to implement dialplans - do to auto completion of 
	the dial numbers (like national to international), to convert generic 
	numbers to specific numbers (like for emergency numbers).


Also the module can be used for detecting range or sets of numbers mapped 
	on a service/case - attributes string can be used here to store extra 
	information about the service/case.


Non-SIP string translation can be implemented - like converting country 
	names from all possible formats to a canonical format:
	(UK, England, United Kingdom) -> GB.


Any other string-base translation or detection for whatever other purposes.


### Database structure and usage


Depending what kind of operation (translation, matching, etc) you want
		to do with the module, you need to appropriate populate the DB records.


The definition of the tables used by the dialplan module can be found
		at [[http://www.opensips.org/html/docs/db/db-schema-devel.html](http://www.opensips.org/html/docs/db/db-schema-devel.html)#AEN1501](http://www.opensips.org/html/db-schema.html#AEN1501)


#### What to place in table


##### String translation (regexp detection, subst translation)


Recognize a number block in all forms (international, national)
			and convert it to a canonical format (e.164)


- *match-op* = 1 (regexp)
- *match_exp* = "^(0040|\+40|0|40)21[0-9]+" ;
				regular expresion that will be used to match with this rule (if
				the rule should be applied for the input string)
- *match_len* = 0 (not used for regexp op)
- *subst_exp* = "^(0040|\+40|0|40)(.+)" ;
				regular expresion used to do the transformation (first part
				of the subst operation)
- *repl_exp* = "40\2" ; second part of the 
				subst (output) - linked to the subst_exp field; when both
				defined, they work as a subst()


##### String translation (regexp detection, replacement)


Recognize the name of a country (multiple languages) and convert
			it to a single fix value


- *match-op* = 1 (regexp)
- *match_exp* = "^((Germany)|(Germania)|(Deutschland)|(DE))" ;
				regular expresion that will be used to match with this rule (if
				the rule should be applied for the input string)
- *match_len* = 0 (not used for regexp op)
- *subst_exp* = NULL ;
				when translation is actually a replacement, this field must 
				be NULL.
- *repl_exp* = "DE" ; static string to 
				replace the input - whenever this rule will match, it will
				return this string as output.


##### Number detection (regexp detection, no replacement)


Recognize a block of numbers as belong to a single service and 
			signalize this via an attribute.


- *match-op* = 1 (regexp)
- *match_exp* = "^021456[0-9]{5}" ;
				regular expresion that will be used to match with this rule (if
				the rule should be applied for the input string)
- *match_len* = 0 (not used for regexp op)
- *subst_exp* = NULL ;
				no translation
- *repl_exp* = NULL ; 
				no translation
- *attrs* = "serviceX" ; 
				whatever string you will get into OpenSIPS script and it will 
				provide you more information (totally custom)


##### String conversion (equal detection, replacement)


Recognize a fix string/number and replace it with something fix.


- *match-op* = 0 (equal)
- *match_exp* = "SIP server" ;
				string to be matched
- *match_len* = 10
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


#### db_url (string)


The translation rules will be loaded using this database url.


*Default value is 
				"mysql://opensips:opensipsrw@localhost/opensips".*


```c title="Set db_url parameter"
...
modparam("dialplan", "db_url", "mysql://user:passwb@localhost/db")
...
		
```


#### table_name (string)


The table's name from which to load the translation rules.


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


The column name to store the priority of the corresponding rule from the 		database raw.


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


#### match_len_col (string)


The column name to store the length of a string matching the 
		match expression.


*Default value is "match_len".*


```c title="Set pr_col parameter"
...
modparam("dialplan", "match_len_col", "column_name")
...
		
```


#### subst_exp_col (string)


The column name to store the rule's substitution expression.


*Default value is "subst_exp".*


```c title="Set pr_col parameter"
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


#### attrs_col (string)


The column name to store the rule's attributes to be set to the message.


*Default value is "attrs".*


```c title="Set attrs_col parameter"
...
modparam("dialplan", "attrs_col", "column_name")
...
		
```


#### attrs_pvar (string)


The pvar to store the rule's attributes, after translation (dp_translate() succeeds).
		This parameter can be any PVAR that can be written.


*Default value is "NULL".*


```c title="Set attrs_pvar parameter"
...
modparam("dialplan", "attrs_pvar", "$avp(s:dest)")
...
		
```


#### fetch_rows (int)


The number of rows to be fetched at once from database/


*Default value is "1000".*


```c title="Set fetch_rows parameter"
...
modparam("dialplan", "fetch_rows", 4000)
...
		
```


### Exported Functions


#### dp_translate(id, src/dest)


Will try to translate the src string into dest string according to 
	the translation rules with dialplan ID equal to id.


Meaning of the parameters is as follows:


- *id* -the dialplan id of the possible matching rules.
		This parameter can have the following types:

  - *integer*- the dialplan id is statically 
			assigned
  - *pvar* 
			-the dialplan id is the value of an existing pseudo-variable
			(as interger value)
- *src/dest* - input and output of the function.
		If this parameter is missing the default parameter 
		"ruri.user/ruri.user" will be used, thus translating 
		the request uri.
The "src" variable can be any type of pseudo-variable.
The "dest" variable  can be also any type of 
		pseudo-variable, but it must be a writtable one.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE.


```c title="dp_translate usage"
...
dp_translate("240", "$ruri.user/$avp(s:dest)");
xlog("translated to var $avp(s:dest) \n");
...
	
```


```c title="dp_translate usage"
...
$avp(s:src) = $ruri.user;
dp_translate("$var(x)", "$avp(s:src)/$var(y)");
xlog("translated to var $var(y) \n");
...
	
```


### Exported MI Functions


#### dp_reload


It will update the translation rules, loading the database info.


Name: *dp_reload*


Parameters: *none*


MI DATAGRAM Command Format:


```c
		:dp_reload:
		_empty_line_
		
```


#### dp_translate


It will apply a translation rule identified by a dialplan
                id and an input string.


Name: *dp_translate*


Parameters: *2*


- *Dial plan ID*
- *Input String*


MI DATAGRAM Command Format:


```c
            :dp_translate:
            dpid
            input
		_empty_line_
		
```


### Installation


The modules requires one table in OpenSIPS database: dialplan.The SQL 
		syntax to create them can be found in dialplan-create.sql     
		script in the database directories in the opensips/scripts folder.
		You can also find the complete database documentation on the
		project webpage, [http://www.opensips.org/html/docs/db/db-schema-devel.html](http://www.opensips.org/html/docs/db/db-schema-devel.html).


## Developer Guide


The module does not provide any API to use in other OpenSIPS modules.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
