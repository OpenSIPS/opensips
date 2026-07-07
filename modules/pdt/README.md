---
title: "pdt Module"
description: "This module translates a numerical prefix into a domain and updates accordingly the request URI."
---

## Admin Guide


### Overview


This module translates a numerical prefix into a domain and updates
		accordingly the request URI.


The module looks up at the R-URI part of a message and if the user
		part begins with an established prefix it will update the URI.
		Updating the uri consists of: remove the prefix from the user part of
		the uri and keep the rest as the user part of the new uri. The host
		and port are changed with the domain matched for the leading prefix and
		the domain in From URI.


<prefix><userid><:password>@<mydomain.com> ...


and the result will be:


<userid><:password>@<domain[:port]>...


```c title="prefix-domain translation"
prefix=123, domain(FROM)=siphub.org

entry in database:
 sdomain=siphub.org
    domain[123]=alpha.org
    domain[124]=beta.org
    domain[125]=gamma.org
	
The RURI will be updated in the following way"
sip:12391001@mydomain.com  => sip:91001@alpha.org    
```


The prefix could be prefixed by other digits. These digits
	    will not be used to look up the domain (the classic example, 00 used
		for international calls, then follows the country prefix). For more
		information on this, see 'prefix' parameter.


- A sample config file is located in './doc/'.
- MySQL script to create the database needed by
			PDT is located in '../../scripts/mysql/pdt-create.sql'
The database is loaded by OpenSIPS only at start up time and 
			only cache is used to lookup domains. Check the MI Functions for
			adding/deleting prefix-domain pairs or reloading from database
			at runtime.
- Sample shell scripts to manage prefix-domain pairs are also located
			in './doc/' (pdt_fifo_add.sh, pdt_fifo_delete.sh, pdt_fifo_list.sh).


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *A OpenSIPS database module (e.g., mysql,
				dbtext)*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### db_url (string)


URL of the database table to be used.


*Default value is "mysql://opensips:opensipsrw@localhost/osips".*


```opensips title="Set db_url parameter"
...
modparam("pdt", "db_url", "dbdriver://username:password@dbhost/dbname")
...
```


#### db_table (string)


Table name.


*Default value is "pdt".*


```opensips title="Set db_table parameter"
...
modparam("pdt", "db_table", "pdt")
...
```


#### sdomain_column (string)


Name of 'sdomain' column.


*Default value is "sdomain".*


```opensips title="Set sdomain_column parameter"
...
modparam("pdt", "domain_column", "source_domain")
...
```


#### prefix_column (string)


Name of 'prefix' column.


*Default value is "prefix".*


```opensips title="Set prefix_column parameter"
...
modparam("pdt", "prefix_column", "prefix")
...
```


#### domain_column (string)


Name of 'domain' column.


*Default value is "domain".*


```opensips title="Set domain_column parameter"
...
modparam("pdt", "domain_column", "hostname")
...
```


#### prefix (string)


Default leading prefix who denotes what URI needs to be translated
		- if it is NULL the module will not check the R-URI against it and
		the PDT prefix is considered starting from the first digit. Otherwise,
		the module will check first if the R-URI starts with it and will
		skip it to look up the domain.


*Default value is NULL.*


```opensips title="Set prefix parameter"
...
modparam("pdt", "prefix", "00")
...
```


#### fetch_rows (integer)


Number of rows to be loaded in one step from database.


*Default value is 1000.*


```opensips title="Set fetch_rows parameter"
...
modparam("pdt", "fetch_rows", 4000)
...
```


#### char_list (string)


The list with characters allowed in prefix.


*Default value is "0123456789".*


```opensips title="Set char_list parameter"
...
modparam("pdt", "char_list", "0123456789*+")
...
```


#### check_domain (integer)


Module will check if destination domain is duplicated for same
		source domain (1 - check; 0 - don't check).


*Default value is 1.*


```opensips title="Set check_domain parameter"
...
modparam("pdt", "check_domain", 0)
...
```


### Exported Functions


#### prefix2domain(rewrite_mode, multidomain_mode)


Build a new URI if it is necessary. Returns 1 when the translation
		was made or there was nothing to translate (user part of the URI is
		empty, it does not match the prefix parameter or there is no domain
		associated with a possible prefix from user part).
		Returns -1 in error cases.


The translation is done based on lookup up for a entry in the database
		where the sdomain equals the domain in FROM uri, and the prefix matches
		the beginning of the user part of the RURI. If such an entry is found,
		then the domain in RURI is updated with the domain of this entry
		(sdomain, prefix, domain).


There is also the possibility to have the translation of URI regardless of
		source domain. This can be achieved inserting in the database entries where
		sdomain has the value "*".


The "rewrite_mode" parameter specifies whether to strip or not
		the prefix from user part. The possible values are:


- 0: the prefix is removed along with the leading prefix.
- 1: only the leading prefix is removed.
- 2: the user part of the URI is not changed.
- $PV : any PV holding one of the above values.


The "multidomain_mode" parameter specifies the kind of multidomain
		support to use. The possible values are:


- 0 : Translation of URI regardless of source domain.
- 1 :  Translation of URI using as source domain the domain
					in From-URI.
- 2 :  Translation of URI using as source domain the domain
				in From-URI. In case there is no entry for the required sdomain,
				it tries the translation using "*" as sdomain.
- $PV : any PV holding one of the above values.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```opensips title="prefix2domain usage"
...
prefix2domain("2", "2");
...
$var(a) = 1;
prefix2domain("$var(a)", "2");
...
```


#### prefix2domain(rewrite_mode)


The same as prefix2domain(rewrite_mode, "0"), that is without 
		multidomain support, translation of  URI being done regardless of 
		the source domain.


```opensips
...
prefix2domain("2");
...
```


#### prefix2domain()


The same as prefix2domain("0", "0").


```opensips
...
prefix2domain();
...
```


### Exported MI Functions


The database is loaded by OpenSIPS at start up time.
		The module uses only the cache to look up domains. If you want to
		add or delete a new prefix-domain pair at runtime you have to use
		MI FIFO commands. All changes made via these commands are applied to
		database and the cache is updated correspondingly.


#### pdt_add


Adds a new sdomain-prefix-domain entry.


Name: *pdt_add*


Parameters:


- _sdomain_ : source domain
- _prefix_: prefix
- _domain_: domain corresponding to a pair of source domain and prefix


MI FIFO Command Format:


```c
		:pdt_add:_reply_fifo_file_
		_sdomain_
		_prefix_
		_domain_
		_empty_line_
		
```


#### pdt_delete


Removes a sdomain-prefix-domain entry.


Name: *pdt_delete*


Parameters:


- _sdomain_ : a source domain
- _domain_: a domain associated via a prefix with the source domain


MI FIFO Command Format:


```c
		:pdt_delete:_reply_fifo_file_
		_sdomain_
		_domain_
		_empty_line_
		
```


#### pdt_list


Produces a listing of the entries prefixes/domains/sdomains.


Name: *pdt_list*


Parameters:


- _sdomain_ : a source domain value.
- _prefix_ : a prefix value
- _domain_: a domain value


"." (dot) means NULL value


The comparison operation is 'START WITH' -- if domain is 'a' then all domains 
		starting with 'a' are listed.


MI FIFO Command Format:


```c
		:pdt_list:_reply_fifo_file_
		_sdomain_
		_prefix_
		_domain_
		_empty_line_
		
```


Examples:


- "pdt_list siph 2 ."  : Lists the entries where sdomain is 
			starting with 'siph', prefix is starting with '2' and domain is anything
- "pdt_list siph 2"  : Lists the entries where sdomain is 
			starting with 'siph', prefix is starting with '2' and domain is anything
- "pdt_list . 2 open"  : Lists the entries where sdomain 
			 is anything, prefix starts with '2' and domain starts with 'open'.


#### pdt_reload


Reload all sdomain-prefix-domain records from database.


Name: *pdt_reload*


Parameters:


- none


MI FIFO Command Format:


```c
		:pdt_reload:_reply_fifo_file_
		_empty_line_
		
```


### Installation and Running


Example shell scripts for MI FIFO commands are placed in './doc/'
	(pdt_fifo_add.sh, pdt_fifo_delete.sh, pdt_fifo_list.sh).
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
