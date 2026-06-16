---
title: "AUTH_JWT Module"
description: "The module implements authentication over JSON Web Tokens. In some cases ( ie. WebRTC ) the user authenticates on another layer ( other than SIP ), so it makes no sense to double-authenticate it on the SIP layer. Thus, the SIP client will simply present the JWT auth token it received from the..."
---

## Admin Guide


### Overview


The module implements authentication over JSON Web Tokens.
		In some cases ( ie. WebRTC ) the user authenticates on another layer ( other than SIP ), so it makes no sense to double-authenticate it on the SIP layer.
		Thus, the SIP client will simply present the JWT auth token it received from the server, and pass it on to OpenSIPS which will use that for authentication purposes.

		It relies on two DB tables, one containing JWT profiles ( a profile name and it's SIP username associated to it ) and one containing JWT secrets. Each secret has a corresponding profile, the KEY used for signing the JWT and two timestamps describing a validation interval. Multiple JWT secrets can point to the same JWT profile.


### Dependencies


#### OpenSIPS Modules


The module depends on the following modules (in the other words
			the listed modules must be loaded before this module):


- *database* -- Any database module
				(currently mysql, postgres, dbtext) , in case the db_url parameter is set


#### External Libraries or Applications


The following libraries or applications must be installed
			before running OpenSIPS with this module loaded:


- *libjwt-dev*
- *openssl-dev* or
					*libssl-dev*


### Exported Parameters


#### db_mode (int)


If set to 0, the module won't connect to the Database for reading the Keys for decoding JWTs - only jwt_script_authorize will be usable from the script.


*Default value is "0".*


```c title="db_mode parameter usage"
modparam("auth_jwt", "db_mode", 0)
```


#### db_url (string)


This is URL of the database to be used. Value of the parameter depends
		on the database module used. For example for mysql and postgres modules
		this is something like mysql://username:password@host:port/database.
		For dbtext module (which stores data in plaintext files) it is
		directory in which the database resides.


*Default value is "mysql://opensipsro:opensipsro@localhost/opensips".*


```c title="db_url parameter usage"
modparam("auth_jwt", "db_url", "dbdriver://username:password@dbhost/dbname")
```


#### profiles_table (string)


Name of the DB table containing the jwt profiles


Default value of this parameter is jwt_profiles.


```c title="profiles_table parameter usage"
modparam("auth_jwt", "profiles_table", "my_profiles")
```


#### secrets_table (string)


Name of the DB table containing the jwt secrets


Default value of this parameter is jwt_secrets.


```c title="secrets_table parameter usage"
modparam("auth_jwt", "secrets_table", "my_secrets")
```


#### tag_column (string)


Column holding the JWT profile tag.


*Default value is "tag".*


```c title="Set tag_column parameter"
...
modparam("auth_jwt", "tag_column", "my_tag_column")
...
```


#### username_column (string)


Column holding the JWT profile associated SIP username.


*Default value is "sip_username".*


```c title="Set username_column parameter"
...
modparam("auth_jwt", "username_column", "my_username_column")
...
```


#### secret_tag_column (string)


Column holding the JWT secret associated tag.


*Default value is "corresponding_tag".*


```c title="Set secret_tag_column parameter"
...
modparam("auth_jwt", "secret_tag_column", "my_secret_tag_column")
...
```


#### secret_column (string)


Column holding the actual jwt signing secret.


*default value is "secret".*


```c title="set secret_column parameter"
...
modparam("auth_jwt", "secret_column", "my_secret_column")
...
```


#### start_ts_column (string)


Column holding the JWT secret start UNIX timestamp.


*default value is "start_ts".*


```c title="set start_ts parameter"
...
modparam("auth_jwt", "start_ts", "my_start_ts_column")
...
```


#### end_ts_column (string)


column holding the jwt secret end unix timestamp.


*default value is "end_ts".*


```c title="set end_ts parameter"
...
modparam("auth_jwt", "end_ts", "my_end_ts_column")
...
```


#### tag_claim (string)


The JWT claim which will be used to identify the JWT profile


*default value is "tag".*


```c title="set tag_claim parameter"
...
modparam("auth_jwt", "tag_claim", "my_tag_claim")
...
```


#### load_credentials (string)


This parameter specifies credentials to be fetched from the JWT profiles table when
		the authentication is performed. The loaded credentials will be stored
		in AVPs. If the AVP name is not specificaly given, it will be used a
		NAME AVP with the same name as the column name.


Parameter syntax:


- *load_credentials = credential (';' credential)**
- *credential = (avp_specification '=' column_name) |
							(column_name)*
- *avp_specification = '$avp(' + NAME + ')'*


Default value of this parameter is "none ( empty )".


```c title="load_credentials parameter usage"
# load my_extra_column into $avp(extra_jwt_info)
modparam("auth_jwt", "load_credentials", "$avp(extra_jwt_info)=my_extra_column")
```


### Exported Functions


#### jwt_db_authorize(jwt_token,out_decoded_token,out_sip_username)


The function will read the first param ( jwt_token ), extract the tag claim and then try to authenticate it against the DB secrets for the respective profile tag. In case of success, it populates the out_decoded_token pvar with the decoded JWT ( in plaintext format header_json.payload_json ) and the out_sip_username with the SIP username corresponding to that JWT profile.


Negative codes may be interpreted as follows:


- *-1 ( error)* - JWT authentication failed


Meaning of the parameters is as follows:


- *jwt_token (string)* - The JWT token to perform auth on
The string may contain pseudo variables.
- *out_decoded_token (pvar)* - PVAR used to store the decoded JWT upon succesful auth
- *out_sip_username (pvar)* - PVAR used to store the SIP username corresponding to the JWT profile, upon succesful auth


This function can be used from REQUEST_ROUTE.


```c title="jwt_db_authorize usage"
...
if (!jwt_db_authorize("$avp(my_jwt_token)", $avp(decoded_token), $avp(sip_username) )) {
	send_reply(401,"Unauthorized");
	exit;
} else {
	xlog("Succesful JWT auth - $avp(decoded_token) \n");
	if ($fU != $avp(sip_username)) {
		send_reply(403,"Forbidden AUTH ID");
		exit;
	}	
}
...
```


#### jwt_script_authorize(jwt_token,key, out_decoded_token)


The function will read the first param ( jwt_token ), decode it and then try to validate it against the provided key. If the JWT decoding is succesful, the out_decoded_token pvar will be populated.
			Return codes are :


- -2 : Failure in decoding the JWT ( out_decoded_token will not be populated )
- -1 : Failure in validating the JWT ( out_decoded_token will be populated )
- 1 : JWT succesfully validated with the key ( out_decoded_token will be populated )


Meaning of the parameters is as follows:


- *jwt_token (string)* - The JWT token to perform auth on
The string may contain pseudo variables.
- *key (string)* - The key to be used for validating the JWT.
- *out_decoded_token (pvar)* - PVAR used to store the decoded JWT


This function can be used from REQUEST_ROUTE.


```c title="jwt_script_authorize usage"
...
if (!jwt_script_authorize("$avp(my_jwt_token)",$avp(pub_key), $avp(decoded_token))) {
	send_reply(401,"Unauthorized");
	exit;
} else {
	xlog("Succesful JWT auth - $avp(decoded_token) \n");
}
...
```


#### extract_pub_key_from_cert(certificate,out_public_key)


The function will read the first param ( certificate ), decode it and then try to extract the public key with the certificate. If the extraction is succesful, the out_public_key will be populated. Useful to be used in conjuction with the jwt_script_authorize function, since most providers make their certificates public, but the JWTs are signed with the actual public key embeded in the certificate.
			Return codes are :


- -1 : Failure in extracting the pub key
- 1 : out_public_key succesfully populated


Meaning of the parameters is as follows:


- *certificate (string)* - The certificate to read and from which to extract the public key
The string may contain pseudo variables.
- *out_public_key (pvar)* - PVAR used to store the extracted public key


This function can be used from REQUEST_ROUTE.


```c title="extract_pub_key_from_cert usage"
...
if (extract_pub_key_from_cert("$avp(my_certificate)",$avp(my_pub_key))) {
    xlog("Succesfully extracted public key - $avp(my_pub_key) \n");
}
...
```


#### extract_pub_key_from_exp_mod(e,n,out_public_key)


The function reads a base64url-encoded RSA exponent (*e*) and modulus (*n*), then builds a PEM public key and stores it into *out_public_key*.
			Return codes are :


- -1 : Failure in extracting the pub key
- 1 : out_public_key succesfully populated


Meaning of the parameters is as follows:


- *e (string)* - Base64url-encoded RSA exponent
The string may contain pseudo variables.
- *n (string)* - Base64url-encoded RSA modulus
The string may contain pseudo variables.
- *out_public_key (pvar)* - PVAR used to store the extracted public key


This function can be used from REQUEST_ROUTE.


```c title="extract_pub_key_from_exp_mod usage"
...
if (extract_pub_key_from_exp_mod("$avp(my_exp)", "$avp(my_mod)", $avp(my_pub_key))) {
    xlog("Succesfully extracted public key - $avp(my_pub_key) \n");
}
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
