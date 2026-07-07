---
title: "Auth_db Module"
description: "This module contains all authentication related functions that need the access to the database. This module should be used together with auth module, it cannot be used independently because it depends on the module. Select this module if you want to use database to store authentication in..."
---

## Admin Guide


### Overview


This module contains all authentication related functions that need
		the access to the database. This module should be used together with
		auth module, it cannot be used independently because it depends on
		the module. Select this module if you want to use database to store
		authentication information like subscriber usernames and passwords. If
		you want to use radius authentication, then use auth_radius instead.


#### RFC 8760 Support (Strenghtened Authentication)


Starting with OpenSIPS 3.2, the [auth](../auth),
			[auth_db](../auth_db) and
			[uac_auth](../uac_auth)
			modules include support for two new digest authentication algorithms
			("SHA-256" and "SHA-512-256"), according to the
	        [RFC 8760](https://datatracker.ietf.org/doc/html/rfc8760)
	        specs.


### Dependencies


#### OpenSIPS Modules


The module depends on the following modules (in the other words
			the listed modules must be loaded before this module):


- *auth* -- Generic authentication
				functions
- *database* -- Any database module
				(currently mysql, postgres, dbtext)


#### External Libraries or Applications


The following libraries or applications must be installed
			before running OpenSIPS with this module loaded:


- *none*


### Exported Parameters


#### db_url (string)


This is URL of the database to be used. Value of the parameter depends
		on the database module used. For example for mysql and postgres modules
		this is something like mysql://username:password@host:port/database.
		For dbtext module (which stores data in plaintext files) it is
		directory in which the database resides.


*Default value is "mysql://opensipsro:opensipsro@localhost/opensips".*


```opensips title="db_url parameter usage"
modparam("auth_db", "db_url", "dbdriver://username:password@dbhost/dbname")
```


#### calculate_ha1 (integer)


This parameter tells the server whether it should considered the
		loaded password (for authentification) as plaintext passwords or
		a pre-calculated HA1 string.


Possible meanings of this parameter are:


- *1 (calculate HA1)* - the loaded
			password is a plaintext password, so OpenSIPS will internally
			calculate the HA1. As the passwords will be loaded from the column
			specified in the [password column](#param_password_column) parameter,
			be sure this parameter points to a column holding a plaintext password
			(by default, this parameter points to the "ha1" column);
- *0 (do **not**
			calculate HA1)* - the loaded password is a pre-computed
			HA1 hash (no calculation needed).  The module will load all hashes
			stored in the [password column](#param_password_column),
			[hash column sha256](#param_hash_column_sha256) and
			[hash column sha512t256](#param_hash_column_sha512t256) columns, then use
			the hash corresponding to the hashing algorithm selected for a
			given digest authentication challenge.
The content of the hash columns can be generated as follows:
			
			password_column: MD5(username:realm:password)
			hash_column_sha256: SHA-256(username:realm:password)
			hash_column_sha512t256: SHA-512-256(username:realm:password)


Default value of this parameter is
			*0 (use hashed passwords)*.


```opensips title="calculate_ha1 parameter usage"
modparam("auth_db", "calculate_ha1", 1)
```


#### use_domain (boolean)


If true (not 0), domain will be also used when looking up in the
		subscriber table. If you have a multi-domain setup, it is strongly
		recommended to keep this parameter enabled, to avoid username
		overlapping between domains.


Default value is *true* (enabled).


```opensips title="use_domain parameter usage"
modparam("auth_db", "use_domain", true)
		
```


#### load_credentials (string)


This parameter specifies credentials to be fetched from database when
		the authentication is performed. The loaded credentials will be stored
		in AVPs. If the AVP name is not specificaly given, it will be used a
		NAME AVP with the same name as the column name.


Parameter syntax:


- *load_credentials = credential (';' credential)**
- *credential = (avp_specification '=' column_name) |
							(column_name)*
- *avp_specification = '$avp(' + NAME + ')'*


Default value of this parameter is empty / """" list.


```opensips title="load_credentials parameter usage"
# load rpid column into $avp(13) and email_address column
# into $avp(email_address)
modparam("auth_db", "load_credentials", "$avp(13)=rpid;email_address")
```


#### skip_version_check (int)


This parameter specifies not to check the auth table version. This
		parameter should be set when a custom authentication table is used.


Default value is "0 (false)".


```opensips title="skip_version_check parameter usage"
modparam("auth_db", "skip_version_check", 1)
		
```


#### user_column (string)


This is the name of the column in a 'SUBSCRIBER' like table holding
		the usernames. Default value is fine for most people.
		Use the parameter if you really need to change it.


Default value is "username".


```opensips title="user_column parameter usage"
modparam("auth_db", "user_column", "user")
```


#### domain_column (string)


This is the name of the column in a 'SUBSCRIBER' like table holding
		the domains of users. Default value is fine for most people.
		Use the parameter if you really need to
		change it.


Default value is "domain".


```opensips title="domain_column parameter usage"
modparam("auth_db", "domain_column", "domain")
```


#### password_column (string)


This is the name of the column in a *"subscriber"*
		like table holding MD5 HA1 hash strings or plaintext passwords.  An MD5 HA1
		hash is an MD5 hash of username, password and realm.  Storing hashes in the
		DB (as opposed to passwords directly) is much more secure, because the
		server does not need to know plaintext passwords and because it is
		computationally infeasible for an attacker to reverse-obtain a password
		from an HA1 string.


Default value is "ha1".


```opensips title="password_column parameter usage"
modparam("auth_db", "password_column", "password")
```


#### hash_column_sha256 (string)


The name of the column holding SHA-256 HA1 hashes
		([RFC 8760](https://datatracker.ietf.org/doc/html/rfc8760) support).


Default value is "ha1_sha256".


```opensips title="password_column parameter usage"
modparam("auth_db", "hash_column_sha256", "ha1_sha256")
```


#### hash_column_sha512t256 (string)


The name of the column holding SHA-512/256 HA1 hashes.
		([RFC 8760](https://datatracker.ietf.org/doc/html/rfc8760) support).


Default value is "ha1_sha512t256".


```opensips title="password_column parameter usage"
modparam("auth_db", "hash_column_sha512t256", "ha1_sha512t256")
```


#### uri_user_column (string)


Column holding usernames in an 'URI' like table.


*Default value is "username".*


```opensips title="Set uri_user_column parameter"
...
modparam("auth_db", "uri_user_column", "username")
...
```


#### uri_domain_column (string)


Column holding domain in an 'URI' like table.


*Default value is "domain".*


```opensips title="Set uri_domain_column parameter"
...
modparam("auth_db", "uri_domain_column", "domain")
...
```


#### uri_uriuser_column (string)


Column holding URI username in an 'URI' like table.


*Default value is "uri_user".*


```opensips title="Set uriuser_column parameter"
...
modparam("auth_db", "uri_uriuser_column", "uri_user")
...
```


### Exported Functions


#### www_authorize(realm, table)


The function verifies the received credentials against a
		"SUBSCRIBER"-like table according to digest authentication as per
		[RFC2617](http://www.ietf.org/rfc/rfc2617.txt).
		If the credentials are verified successfully then the function will
		succeed and mark the credentials as authorized (marked credentials
		can be later used by some other functions). If the function was
		unable to verify the
		credentials for some reason then it will fail and the script should
		call `www_challenge` which will
		challenge the user again.


Negative codes may be interpreted as follows:


- *-5 (generic error)* - some generic error
			occurred and no reply was sent out;
- *-4 (no credentials)* - credentials were not
			found in request;
- *-3 (stale nonce)* - stale nonce;
- *-2 (invalid password)* - valid user, but
			wrong password;
- *-1 (invalid user)* - authentication user does
			not exist.


Meaning of the parameters is as follows:


- *realm (string)* - Realm is an opaque string that
			the user agent should present to the user so it can decide what
			username and password to use. Usually this is domain of the host
			the server is running on.
If an empty string "" is used then the server will
			generate it from the request. In case of REGISTER requests To
			header field domain will be used (because this header field
			represents a user being registered), for all other messages From
			header field domain will be used.
The string may contain pseudo variables.
- *table (string)* - Table to be used to lookup
			usernames and passwords (usually subscribers table).


This function can be used from REQUEST_ROUTE.


```opensips title="www_authorize usage"
...
if (!www_authorize("siphub.net", "subscriber"))
	www_challenge("siphub.net", "auth");
...
```


#### proxy_authorize(realm, table)


The function verifies the received credentials against a
		"SUBSCRIBER"-like table according to digest authentication as per
		[RFC2617](http://www.ietf.org/rfc/rfc2617.txt). If
		the credentials are verified successfully then the function will
		succeed and mark the credentials as authorized (marked credentials can
		be later used by some other functions). If the function was unable to
		verify the credentials for some reason then it will fail and
		the script should call
		`proxy_challenge` which will
		challenge the user again.


Negative codes may be interpreted as follows:


- *-5 (generic error)* - some generic
					error occurred and no reply was sent out;
- *-4 (no credentials)* - credentials
					were not found in request;
- *-3 (stale nonce)* - stale nonce;
- *-2 (invalid password)* - valid user,
					but wrong password;
- *-1 (invalid user)* - authentication
					user does not exist.


Meaning of the parameters is as follows:


- *realm (string)* - Realm is an opaque string that
			the user agent should present to the user so it can decide what
			username and password to use. Usually this is domain of the host
			the server is running on.
If an empty string "" is used then the server will
			generate it from the request. From header field domain will be
			used as realm.
The string may contain pseudo variables.
- *table (string)* - Table to be used to lookup
			usernames and passwords (usually subscribers table).


This function can be used from REQUEST_ROUTE.


```opensips title="proxy_authorize usage"
...
if (!proxy_authorize("", "subscriber"))
	proxy_challenge("", "auth");  # Realm will be autogenerated
...
```


#### db_is_to_authorized(table)


The function checks against a  'URI' like table to see if the
		username extracted from the To header URI is allowed/authorized to
		use the credentials (authentication username) validated by
		[www authorize](#func_www_authorize).


The function is part of the mechanism that allows to create
		mapping between the SIP users (from the FROM/TO headers) and the
		authentication users (from a SUBSCRIBER-like table) that they use. The
		mapping is stored into an URI-like table.


Meaning of the parameters is as follows:


- *table (string)* - Table to be used to lookup
			for the URI/AUTH mappings (usually the URI table).


This function can be used from REQUEST_ROUTE.


```opensips title="db_is_to_authorized usage"
...
if (!db_is_to_authorized("uri")) {
	xlog("User $tu is not authorized to authenticate with $au credential\n");
}
...
```


#### db_is_from_authorized(table)


Similar to [db is to authorized](#func_db_is_to_authorized) but instead of
		checking the TO header URI, the FROM header URI is checked.


#### db_does_uri_exist(uri, table)


Checks if the username@domain from the given URI is an existing
		user in a 'SUBSCRIBER' like table.


Meaning of the parameters is as follows:


- *uri (string)* - The SIP URI to be tested. It must
			hold a username part for a valid check. Variables are allowed.
- *table (string)* - Table to be used to search
			for the URI (usually the SUBSCRIBER table).


This function can be used from REQUEST_ROUTE.


```opensips title="db_does_uri_exist usage"
...
if (db_does_uri_exist($ru, "subscriber")) {
	...
}
...
```


#### db_get_auth_id(table, uri, auth, realm)


Checks given uri-string username against an 'URI' like table.
		Returns true if the user exists in the database, and sets the given
		variables to the authentication id and realm corresponding to
		the given uri.


Meaning of the parameters is as follows:


- *table (string)* - Table to be used to search
			for the URI (usually the URI table).
- *uri (string)* - The input SIP URI to be tested.
			It must hold a username part for a valid check.
			Variables are allowed.
- *auth (var)* - an output variable to store the
			found authentication id matching the given SIP URI.
- *realm (var)* - an output variable to store the
			found authentication realm matching the given SIP URI.


This function can be used from REQUEST_ROUTE ,FAILURE_ROUTE and
		LOCAL_ROUTE.


```opensips title="db_get_auth_id usage"
...
if (db_get_auth_id("uri", $ru, $avp(auth_id), $avp(auth_realm))) {
	...
}
...
```

### Tips & FAQ

#### How to recalculate ha1 and ha1b

When you change the `domain` column in the subscriber table, you have to recalculate `ha1` and `ha1b` fields. In order to do that you must have the password of each subscriber.

HA1 is a MD5 hash of "username:domain:password". For example, if you have created a SIP account "1000@mydomain.com" using password "123456", then HA1 is the MD5 hash of "1000:mydomain.com:123456" (without quotes). On the other hand HA1B is the MD5 hash of "username@domain:domain:password"; so using the same example above, HA1B would be the MD5 hash of "1000@mydomain.com:mydomain.com:123456" (without quotes).

To recalculate and update ha1 and ha1b columns in the subscriber table, just execute the following sql statement in mysql:

```sql
update subscriber
set ha1 = md5(concat(username, ':', domain, ':', password)),
ha1b = md5(concat(username, '@', domain, ':', domain, ':', password))
```

> \[!NOTE]
> the above is only true if you have `use_domain` enabled *and* you do not use a static challenge parameter for `www_authorize()`.

If you use a static challenge for `www_authorize()` (i.e. the first parameter of `www_authorize()` is not the empty string), then HA1 is MD5("username:challenge:password") and HA1B is MD5("username@challenge:challenge:password"). If the challenge parameter of `www_authorize()` is empty, OpenSIPS automatically selects the domain as the challenge value, which gives the solution presented above.

If `use_domain` is false, then the HA1B field must be computed based on "username@:domain:password" or "username@:challenge:password", depending on whether challenge is empty or defined, respectively.


<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
