---
title: "AVPops Module"
description: "AVPops (AVP-operations) modules implements a set of script functions which allow access and manipulation of user AVPs (preferences) and pseudo-variables. AVPs are a powerful tool for implementing services/preferences per user/domain. Now they are usable directly from configuration script...."
---

## Admin Guide


### Overview


AVPops (AVP-operations) modules implements a set of script
		functions which allow access and manipulation of user AVPs
		(preferences) and pseudo-variables. AVPs are a powerful tool
		for implementing services/preferences per user/domain. Now they
		are usable directly from configuration script. Functions for
		interfacing DB resources (loading/storing/removing), functions
		for swapping information between AVPs and SIP messages, function for
		testing/checking the value of an AVP.


AVPs are persistent per SIP transaction, being available in "route",
		"branch_route" and "failure_route". To make them available in
		"onreply_route" armed via TM module, set "onreply_avp_mode" parameter
		of TM module (note that in the default "onreply_route", the AVPs of
		the transaction are not available).


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *Optionally a database module*


#### External Libraries or Applications


The following libraries or applications must be installed
				before running OpenSIPS with this module loaded:


- *None*


### AVP naming format


The format of the parameters specifying an AVP in functions exported
		by this module is:
			**$avp(avp_name)**.


- *avp_name* = string | integer
string - might be any alphanumeric string, wich contain following
		characters: [a-z] [A-Z] [0-9] '_'


```c title="AVP naming examples"
...
$avp(11) - the AVP identified by name 11
$avp(foo) - the AVP identified by the string 'foo'
...
				
```


### Exported Parameters


#### db_url (string)


DB URL for database connection. As the module allows the usage
			of multiple DBs (DB URLs), the actual DB URL may be preceded by
			an reference number. This reference number is to be passed to
			AVPOPS function that what to explicitly use this DB connection.
			If no reference number is given, 0 is assumed - this is the default
			DB URL.


*This parameter is optional, it's default value being NULL.*


```c title="Set avp_url parameter"
...
# default URL
modparam("avpops","db_url","mysql://user:passwd@host/database")
# an additional DB URL
modparam("avpops","db_url","1 postgres://user:passwd@host2/opensips")
...
				
```


#### avp_table (string)


DB table to be used.


*This parameter is optional, it's default value being NULL.*


```c title="Set avp_table parameter"
...
modparam("avpops","avp_table","avptable")
...
				
```


#### use_domain (integer)


If the domain part of the an URI should be used for
				identifying an AVP in DB operations.


*Default value is 0 (no).*


```c title="Set use_domain parameter"
...
modparam("avpops","use_domain",1)
...
				
```


#### uuid_column (string)


Name of column containing the uuid (unique user id).


*Default value is "uuid".*


```c title="Set uuid_column parameter"
...
modparam("avpops","uuid_column","uuid")
...
				
```


#### username_column (string)


Name of column containing the username.


*Default value is "username".*


```c title="Set username_column parameter"
...
modparam("avpops","username_column","username")
...
				
```


#### domain_column (string)


Name of column containing the domain name.


*Default value is "domain".*


```c title="Set domain_column parameter"
...
modparam("avpops","domain_column","domain")
...
				
```


#### attribute_column (string)


Name of column containing the attribute name (AVP name).


*Default value is "attribute".*


```c title="Set attribute_column parameter"
...
modparam("avpops","attribute_column","attribute")
...
				
```


#### value_column (string)


Name of column containing the AVP value.


*Default value is "value".*


```c title="Set value_column parameter"
...
modparam("avpops","value_column","value")
...
				
```


#### type_column (string)


Name of column containing the AVP type.


*Default value is "type".*


```c title="Set type_column parameter"
...
modparam("avpops","type_column","type")
...
				
```


#### db_scheme (string)


Definition of a DB scheme to be used for non-standard
				access to Database information.


Definition of a DB scheme. Scheme syntax is:


- *db_scheme = name':'element[';'element]**
- *element* =
					
						'uuid_col='string
						'username_col='string
						'domain_col='string
						'value_col='string
						'value_type='('integer'|'string')
						'table='string


*Default value is "NULL".*


```c title="Set db_scheme parameter"
...
modparam("avpops","db_scheme",
"scheme1:table=subscriber;uuid_col=uuid;value_col=first_name")
...
				
```


#### buf_size (integer)


Allocated size for AVP variables.


*Default value is "1024".*


```c title="Set buf_size parameter"
...
modparam("avpops", "buf_size", 1024)
...
				
```


### Exported Functions


#### avp_db_load(source, name[, db_id[, prefix]])


Loads from DB into memory the AVPs corresponding to the given
			*source*. If given, it sets the script flags
			for loaded AVPs. It returns true if it loaded some values
			in AVPs, false otherwise (db error, no avp loaded ...).


AVPs may be preceded by an optional *prefix*, in
			order to avoid some conflicts.


Meaning of the parameters is as follows:


- *source* - what info is used for
				identifying the AVPs. Parameter syntax:
				
					*source = (pvar|str_value)
					['/'('username'|'domain'|'uri'|'uuid')])*
					*pvar = any pseudo variable defined in OpenSIPS. If
					the pvar is $ru (request uri), $fu (from uri), $tu (to uri)
					or $ou (original uri), then the implicit flag is 'uri'.
					Otherwise, the implicit flag is 'uuid'.*
- *name* - which AVPs will be loaded
				from DB into memory. Parameter syntax is:
				
					*name = avp_spec['/'(table_name|'$'db_scheme)]*
					*avp_spec = matching_flags|$avp(avp_name)|$avp(avp_alias)*
					*matching_flags = 'a' | 'A' | 'i' | 'I' | 's' | 'S'
					[script_flags]*'a' or 'A' means matching any of
					AVP name types ('i' and 's'), the rest have the
					meaning descriped in 'AVP naming format' chapter.
- *db_id* - reference to a defined
				DB URL (a numerical id) - see the "db_url"
				module parameter.
- *prefix* - static string which will
					precede the names of the AVPs populated by this function.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE, LOCAL_ROUTE and ONREPLY_ROUTE.


```c title="avp_db_load usage"
...
avp_db_load("$fu", "$avp(678)");
avp_db_load("$ru/domain", "i/domain_preferences");
avp_db_load("$avp(uuid)", "$avp(404fwd)/fwd_table");
avp_db_load("$ru", "$avp(123)/$some_scheme");

# use DB URL id 3
avp_db_load("$ru", "$avp(1)", "3");

# precede all loaded AVPs by the "caller_" prefix
avp_db_load("$ru", "$avp(100)", "", "caller_");
xlog("Loaded: $avp(caller_100)\n");

...
				
```


#### avp_db_store(source,name[,db_id])


Stores to DB the AVPs corresponding to the given
			*source*.


The meaning and usage of the parameters are identical as for
			*avp_db_load(source,name)*
			function. Please refer to its description.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE, LOCAL_ROUTE and ONREPLY_ROUTE.


```c title="avp_db_store usage"
...
avp_db_store("$tu","$avp(678)");
avp_db_store("$ru/username","$avp(email)");
# use DB URL id 3
avp_db_store("$ru","$avp(1)","3");
...
				
```


#### avp_db_delete(source,name[,db_id])


Deletes from DB the AVPs corresponding to the given
			*source*.


The meaning and usage of the parameters are identical as for
			*avp_db_load(source,name)*
			function. Please refer to its description.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE, LOCAL_ROUTE and ONREPLY_ROUTE.


```c title="avp_db_delete usage"
...
avp_db_delete("$tu","$avp(678)");
avp_db_delete("$ru/username","$avp(email)");
avp_db_delete("$avp(uuid)","$avp(404fwd)/fwd_table");
# use DB URL id 3
avp_db_delete("$ru","$avp(1)","3");
...
				
```


#### avp_db_query(query[[,dest],db_id])


Make a database query and store the result in AVPs.


The meaning and usage of the parameters:


- *query* - must be a valid SQL
				query. The parameter can contain pseudo-variables.
You must escape any pseudo-variables manually to prevent
				SQL injection attacks. You can use the existing transformations
				*escape.common* and
				*unescape.common*
				to escape and unescape the content of any pseudo-variable.
				Failing to escape the variables used in the query makes you
				vulnerable to SQL injection, e.g. make it possible for an
				outside attacker to alter your database content.
				The function returns true if the query was successful, -2 in case
				the query returned an empty result set, and -1 for all other types
				of errors
- *dest* - a list with AVP names where
				to store the result. The format is
				"$avp(name1);$avp(name2);...". If this parameter
				is ommited, the result is stored in
				"$avp(1);$avp(2);...". If the result gives
				many rows, then multiple AVPs with corresponding name will
				be added. The value type of the AVP (string or integer) will
				be derived from the type of the columns.
- *db_id* - reference to a defined
				DB URL (a numerical id) - see the "db_url"
				module parameter. It can be either a constant, or a
				string/int variable.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE, LOCAL_ROUTE and ONREPLY_ROUTE.


```c title="avp_db_query usage"
...
avp_db_query("select password, ha1 from subscriber where username='$tu'",
	"$avp(678);$avp(679)");
avp_db_query("delete from subscriber");
avp_db_query("delete from subscriber","","2");

$avp(id)=2;#also works $avp(id)="2"
avp_db_query("delete from subscriber","","$avp(id)");

...
				
```


#### avp_delete(name)


Deletes from memory the AVPs with *name* or,
			if *, all AVPs.


Meaning of the parameters is as follows:


- *name* - which AVPs will be deleted
				from memory.
				Parameter syntax is:
				
					*name = (matching_flags|avp_name|avp_alias)['/'flag]*
					*matching_flags = please refer to avp_db_load() function*
					*flag = 'g'|'G'*


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE, LOCAL_ROUTE and ONREPLY_ROUTE.


```c title="avp_delete usage"
...
avp_delete("$avp(678)/g");
avp_delete("$avp(email)");
avp_delete("i");
avp_delete("a3");
...
				
```


#### avp_pushto(destination,name)


Pushes the value of AVP(s) into the SIP message.


Meaning of the parameters is as follows:


- *destination* - as what will be the
				AVP value pushed into SIP message.
				Parameter syntax:
				
					*destination = '$ru' ['/'('username'|'domain')] | '$du' |
					'$br'*
					*$ru '['/'('username'|'domain')] - write the AVP in the
					request URI or in username/domain part of it*
					*$du - write the AVP in 'dst_uri' field*
					*$br - write the AVP directly as a new branch (does not
					affect RURI)*
- *name* - which AVP(s)/pseudo-variable
				should be pushed
				into the SIP message.
				Parameter syntax is:
				
					*name = ( avp_name | avp_alias | pvar_name )['/'flags]*
					*flags = 'g' - effective only with AVPs*


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE, LOCAL_ROUTE and ONREPLY_ROUTE.


```c title="avp_pushto usage"
...
avp_pushto("$ru/domain","$fd");
avp_pushto("$ru","$avp(678)");
avp_pushto("$ru/domain","$avp(backup_domains)/g");
avp_pushto("$du","$avp(679)");
avp_pushto("$br","$avp(680)");
...
				
```


#### avp_check(name,op_value)


Checks the value of the AVP(s) against an operator and value.


Meaning of the parameters is as follows:


- *name* - which AVP(s) should be
				checked.
				Parameter syntax is:
				
					*name = ( pseudo-variable )*
- *op_value* - define the operator,
				the value and flags for checking.
				Parameter syntax is:

  - *op_value = operator '/' value ['/'flags]*
  - *operator = 'eq' | 'ne' | 'lt' | 'le' | 'gt' | 'ge'
					| 're' | 'fm' | 'and' | 'or' | 'xor'*
  - *value = pseudo-variable | fix_value*
  - *fix_value = 'i:'integer | 's:'string | string*
  - *flags = 'g' | 'G' | 'i' | 'I'*
Operator meaning:

  - *eq* - equal
  - *ne* - not equal
  - *lt* - less than
  - *le* - less or equal
  - *gt* - greater than
  - *ge* - greater or equal
  - *re* - regexp (regular exression match)
  - *fm* - fast match (see: man fnmatch)
  - *and* - bitwise 'and'
  - *or* - bitwise 'or'
  - *xor* - bitwise 'xor'
Integer values can be given in hexadecimal using notation:
				'i:0xhex_number' (e.g.,: 'i:0xabcd');


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE, LOCAL_ROUTE and ONREPLY_ROUTE.


```c title="avp_check usage"
...
avp_check("$avp(678)", "lt/345/g");
avp_check("$fd","eq/$td/I");
avp_check("$avp(foo)","gt/$avp($bar)/g");
avp_check("$avp(foo)","re/sip:.*@bar.net/g");
avp_check("$avp(foo)","fm/$avp(fm_avp)/g");
...
				
```


#### avp_copy(old_name,new_name)


Copy / move an avp under a new name.


Meaning of the parameters is as follows:


- *name1* - which AVP(s) should be
				copied/moved.
				Parameter syntax is:
				
					*name = ( avp_name | avp_alias )*
- *name2* - the new name of the
				copied/moved AVP(s).
				Parameter syntax is:
				
					*name = ( avp_name | avp_alias ) ['/'flags]*
					*flags = 'g' | 'G' | 'd' | 'D' | 'n' | 'N' | 's' | 'S'*


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE, LOCAL_ROUTE and ONREPLY_ROUTE.


```c title="avp_copy usage"
...
avp_copy("$avp(678)", "$avp(345)/g");
avp_copy("$avp(old)","$avp(new)/gd");
...
				
```


#### avp_subst(avps, subst)


Perl/sed-like subst applied to AVPs having string value.


Meaning of the parameters is as follows:


- *avps* - source AVP, destination AVP
				and flags. Parameter syntax is:
				
					*avps = src_avp [ '/' dst_avp [ '/' flags ] ]*
					*src_avp = ( avp_name | avp_alias )*
					*dst_avp = ( avp_name | avp_alias ) - if dst_avp is missing
					then the value of src_avp will be replaced*
					*flags = ( d | D | g | G ) -- (d, D - delete source avp;
					g, G - apply to all avps matching src_avp name)*
- *subst* - perl/sed-like reqular expression.
				Parameter syntax is:
				
					*subst = "/regexp/replacement/flags"*
					*regexp - regular expression*
					*replacement - replacement string, can include
					pseudo-variables and \1, ..., \9 for matching tokens,
					\0 for whole matching text*
					*flags = 'g' | 'G' | 'i' | 'i' (g, G - replace all
					matching tokens; i, I - match ignore case)*


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE, LOCAL_ROUTE and ONREPLY_ROUTE.


```c title="avp_subst usage"
...
# if avp 678 has a string value in e-mail format, replace the
# domain part with the value of domain part from R-URI
avp_subst("$avp(678)", "/(.*)@(.*)/\1@$rd/");

# if any avp 678 has a string value in e-mail format, replace the
# domain part with the value of domain part from R-URI
# and place the result in avp 679
avp_subst("$avp(678)/$avp(679)/g", "/(.*)@(.*)/\1@$rd/");
...
				
```


IMPORTANT NOTE: if the replacement string includes src_avp
			or dst_avp you will get something that you may not expect.
			In case you have many src_avp and you make the substitution
			to be applied to all of them, after the first src_avp is
			processed, it will be added in avp list and next
			processing will use it.


#### avp_op(name,op_value)


Different integer operations with avps.


Meaning of the parameters is as follows:


- *name*
				- 'source_avp/destination_avp' - which AVP(s) should be
				processed and where to store the result. If 'destination_avp'
				is missing, same name as 'source_avp' is used to store the
				result.
Parameter syntax is:

  - *name = ( source_avp[/destination_avp] )*
*source_avp = ( avp_name | avp_alias )*
*destination_avp = ( avp_name | avp_alias )*
- *op_value* - define the operation,
				the value and flags.
				Parameter syntax is:
				
					*op_value = operator '/' value ['/'flags]*
					*operator = 'add' | 'sub' | 'mul' | 'div' | 'mod'
					| 'and' | 'or' | 'xor' | 'not'*
					*value = pseudo-variable | fix_value*
					*fix_value = 'i:'integer*
					*flags = 'g' | 'G' | 'd' | 'D'*
Integer values can be given in hexadecimal using notation
				'i:0xhex_number' (e.g.,: 'i:0xabcd');


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE, LOCAL_ROUTE and ONREPLY_ROUTE.


```c title="avp_op usage"
...
avp_op("$avp(678)", "add/345/g");
avp_op("$avp(number)","sub/$avp(number2)/d");
...
				
```


#### is_avp_set(name)


Check if any AVP with *name* is set.


Meaning of the parameters is as follows:


- *name* - name of AVP to look for.
				Parameter syntax is:
				
					*name = avp_name|avp_alias [ '/' flags ])*
					*flags = ('e'|'s'|'n') - e = empty value; s = value string;
					n = value number (int)*


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE, LOCAL_ROUTE and ONREPLY_ROUTE.


```c title="is_avp_set usage"
...
if(is_avp_set("$avp(678)"))
    log("AVP with integer id 678 exists\n");
...
				
```


#### avp_print()


Prints the list with all the AVPs from memory. This is only a
			helper/debug function.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE, LOCAL_ROUTE and ONREPLY_ROUTE.


```c title="avp_print usage"
...
avp_print();
...
				
```


#### avp_insert(avp_name, value, index)


This function inserts an avp value at a certain position specified
				by the last parameter. If the index is greater than the count of values
				the value will be inserted at the end.


```c title="avp_print usage"
...
avp_insert("avp(20)", "$hdr(From)", 2);
...
				
```


### Exported Asynchronous Functions


#### avp_db_query(query[[,dest],db_id])


Make a database query and store the result in AVPs.


The meaning and usage of the parameters:


- *query* - must be a valid SQL
				query. The parameter can contain pseudo-variables.
You must escape any pseudo-variables manually to prevent
				SQL injection attacks. You can use the existing transformations
				*escape.common* and
				*unescape.common*
				to escape and unescape the content of any pseudo-variable.
				Failing to escape the variables used in the query makes you
				vulnerable to SQL injection, e.g. make it possible for an
				outside attacker to alter your database content.
				The function returns true if the query was successful, -2 in case
				the query returned an empty result set, and -1 for all other types
				of errors
- *dest* - a list with AVP names where
				to store the result. The format is
				"$avp(name1);$avp(name2);...". If this parameter
				is ommited, the result is stored in
				"$avp(1);$avp(2);...". If the result gives
				many rows, then multiple AVPs with corresponding name will
				be added. The value type of the AVP (string or integer) will
				be derived from the type of the columns.
- *db_id* - reference to a defined
				DB URL (a numerical id) - see the "db_url"
				module parameter.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE, LOCAL_ROUTE and ONREPLY_ROUTE.


```c title="async avp_db_query usage"
...
{
...
/* Example of a slow MySQL query - it should take around 5 seconds */
async(
	avp_db_query(
		"SELECT table_name, table_version, SLEEP(0.1) from version",
		"$avp(tb_name); $avp(tb_ver); $avp(retcode)"),
	my_resume_route);
/* script execution is halted right after the async() call */
}

/* We will be called when data is ready - meanwhile, the worker is free */
route [my_resume_route]
{
	xlog("Results: \n$(avp(tb_name)[*])\n
-------------------\n$(avp(tb_ver)[*])\n
-------------------\n$(avp(retcode)[*])\n");
}
...
				
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
