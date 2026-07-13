---
title: "Auth_db Module"
description: "This module contains all authentication related functions that need the access to the database. This module should be used together with auth module, it cannot be used independently because it depends on the module."
---

## Admin Guide


### Overview


This module contains all authentication related functions that need 
the access to the database. This module should be used together with 
auth module, it cannot be used independently because it depends on 
the module. Select this module if you want to use database to store 
authentication information like subscriber usernames and passwords. If
you want to use radius authentication, then use auth_radius instead.


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


#### user_column (string)


This is the name of the column holding usernames. Default value is 
fine for most people. Use the parameter if you really need to change it.


Default value is "username".


```opensips title="user_column parameter usage"
modparam("auth_db", "user_column", "user")
```


#### domain_column (string)


This is the name of the column holding domains of users. Default value 
is fine for most people. Use the parameter if you really need to 
change it.


Default value is "domain".


```opensips title="domain_column parameter usage"
modparam("auth_db", "domain_column", "domain")
```


#### password_column (string)


This is the name of the column holding passwords. Passwords can be 
either stored as plain text or pre-calculated HA1 strings. HA1 strings 
are MD5 hashes of username, password, and realm. HA1 strings are more 
safe because the server doesn't need to know plaintext passwords and 
they cannot be obtained from HA1 strings.


Default value is "ha1".


```opensips title="password_column parameter usage"
modparam("auth_db", "password_column", "password")
```


#### password_column_2 (string)


As described in the previous section this parameter contains name of 
column holding pre-calculated HA1 string that were calculated including 
the domain in the username. This parameter is used only when 
`calculate_ha1` is set to 0 and user agent send a 
credentials containing the domain in the username.


Default value of the parameter is ha1b.


```opensips title="password_column_2 parameter usage"
modparam("auth_db", "password_column_2", "ha1_2")
```


#### calculate_ha1 (integer)


This parameter tells the server whether it should considered the
loaded password (for authentification) as plaintext passwords or 
a pre-calculated HA1 string.


Possible meanings of this parameter are:


- *1 (calculate HA1)* - the loaded
password is a plaintext password, so OpenSIPS will internally
calculate the HA1. As the passwors will be loaded from the column 
specified in the "password_column" parameter, be sure
this parameter points to a column holding a plaintext password
(by default, this parameter points to "ha1" column);
- *0 (do NOT calculate HA1)* - the
loaded password is an already computed HA1 value, so OpenSIPS does 
not have do any further computing (for HA1 value). Depending on 
the presence of a "@domain" part (some user agents 
append the domain to the username credentials parameter too),
the modules will load the password (pre-computed HA1) from the 
"password_column_2" column (if domain present) or from
the "password_column" column (if domain not present).
Usually, most of the UAs do NOT include a domain part in the 
username credentials parameter.


The "password_column_2" column contains also HA1 strings
but they should be calculated including the domain in the username
parameter (as opposed to password_column which (when containing HA1
strings) should always contain HA1 strings calculated without domain
in username.


This ensures that the authentication will always work when using
pre-calculated HA1 strings, not depending on the presence of the
domain in username.


Default value of this parameter is 0.


```opensips title="calculate_ha1 parameter usage"
modparam("auth_db", "calculate_ha1", 1)
```


#### use_domain (integer)


If true (not 0), domain will be also used when looking up in the 
subscriber table. If you have a multi-domain setup, it is strongly
recommended to turn on this parameter to avoid username overlapping
between domains.


IMPORTANT: before turning on this parameter, be sure that the 
`domain` column in `subscriber` 
table is properly populated.


Default value is "0 (false)".


```opensips title="use_domain parameter usage"
modparam("auth_db", "use_domain", 1)
		
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


Default value of this parameter is "rpid".


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


### Exported Functions


#### www_authorize(realm, table)


The function verifies credentials according to 
[RFC2617](http://www.ietf.org/rfc/rfc2617.txt). If the 
credentials are verified successfully then the function will succeed 
and mark the credentials as authorized (marked credentials can be later 
used by some other functions). If the function was unable to verify the 
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


- *realm* - Realm is an opaque string that 
the user agent should present to the user so it can decide what 
username and password to use. Usually this is domain of the host 
the server is running on.
If an empty string "" is used then the server will 
generate it from the request. In case of REGISTER requests To 
header field domain will be used (because this header field 
represents a user being registered), for all other messages From 
header field domain will be used.
The string may contain pseudo variables.
- *table* - Table to be used to lookup 
usernames and passwords (usually subscribers table).


This function can be used from REQUEST_ROUTE.


```opensips title="www_authorize usage"
...
if (!www_authorize("siphub.net", "subscriber")) {
	www_challenge("siphub.net", "1");
};
...
```


#### proxy_authorize(realm, table)


The function verifies credentials according to 
[RFC2617](http://www.ietf.org/rfc/rfc2617.txt). If 
the credentials are verified successfully then the function will 
succeed and mark the credentials as authorized (marked credentials can 
be later used by some other functions). If the function was unable to 
verify the credentials for some reason then it will fail and
the script should call 
`proxy_challenge` which will
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


- *realm* - Realm is an opaque string that 
the user agent should present to the user so it can decide what 
username and password to use. Usually this is domain of the host 
the server is running on.
If an empty string "" is used then the server will 
generate it from the request. From header field domain will be 
used as realm.
The string may contain pseudo variables.
- *table* - Table to be used to lookup 
usernames and passwords (usually subscribers table).


This function can be used from REQUEST_ROUTE.


```opensips title="proxy_authorize usage"
...
if (!proxy_authorize("", "subscriber)) {
	proxy_challenge("", "1");  # Realm will be autogenerated
};
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

> [!NOTE]
> The above is only true if you have `use_domain` enabled *and* you do not use a static challenge parameter for `www_authorize()`.

If you use a static challenge for `www_authorize()` (i.e. the first parameter of `www_authorize()` is not the empty string), then HA1 is MD5("username:challenge:password") and HA1B is MD5("username@challenge:challenge:password"). If the challenge parameter of `www_authorize()` is empty, OpenSIPS automatically selects the domain as the challenge value, which gives the solution presented above.

If `use_domain` is false, then the HA1B field must be computed based on "username@:domain:password" or "username@:challenge:password", depending on whether challenge is empty or defined, respectively.


<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
