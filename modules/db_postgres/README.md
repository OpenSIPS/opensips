---
title: "db_postgres Module"
description: "Module description"
---

## Admin Guide


### Overview


Module description


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *PostgreSQL library* - e.g., libpq5.
- *PostgreSQL devel library* - to compile
				the module (e.g., libpq-dev).


### Exported Parameters


#### exec_query_threshold (integer)


If queries take longer than 'exec_query_threshold' microseconds, warning
		messages will be written to logging facility.


*Default value is 0 - disabled.*


```c title="Set exec_query_threshold parameter"
...
modparam("db_postgres", "exec_query_threshold", 60000)
...
```


#### max_db_queries (integer)


The maximum number of database queries to be executed. 
                If this parameter is set improperly, it is set to default value.


*Default value is 2.*


```c title="Set max_db_queries parameter"
...
modparam("db_postgres", "max_db_queries", 2)
...
```


#### timeout (integer)


The number of seconds the PostgreSQL library waits to connect and query
			the server. If the connection does not succeed within the given timeout,
			the connection fails.


*Note:*If the timeout is a negative value and
			connection does not succeed, OpenSIPS will block until the connection
			becomes back available and gets successfully established. This is the
			default behavior of the library and is the behavior prior to the
			adition of this parameter.


*Default value is 5.*


```c title="Set timeout parameter"
...
modparam("db_postgres", "timeout", 2)
...
```


#### use_tls (integer)


Parameter to control the way the SSL support is used when connecting
		to the Postgres server, as follows:


- *use_tls=0* (default) - the SSL support
				is disabled and there is no attempt to use it;
- *use_tls=1* with "tls_domain" present
				in the DB URL - the SSL support is enabled, either 
				"require", either "verify-ca", depending on the certificate
				settings;
- *use_tls=1* with no "tls_domain" present
				in the DB URL - the SSL support is enabled in best effort mode
				(or "prefer"); if supported by the server, it will be used,
				otherwise it will fall back to non-SSL.


Warning: the *tls_openssl* module cannot be used
		when setting this parameter. Use the *tls_wolfssl*
		module instead if a TLS/SSL Library is required.


Setting this parameter will allow you to use TLS for PostgreSQL connections.
		In order to enable TLS for a specific connection, you can use the
		"tls_domain=*dom_name*" URL parameter in the db_url of
		the respective OpenSIPS module. This should be placed at the end of the
		URL after the '?' character.


When using this parameter, you must also ensure that
		*tls_mgm* is loaded and properly configured. Refer to
		the the module for additional info regarding TLS client domains.


Note that if you want to use this feature, the TLS domain must be
		provisioned in the configuration file, *NOT* in
		the database. In case you are loading TLS certificates from the
		database, you must at least define one domain in the
		configuration script, to use for the initial connection to the DB.


Also, you can *NOT* enable TLS for the connection
		to the database of the *tls_mgm* module itself.


*Default value is **0** (not enabled)*


```c title="Set the use_tls parameter"
...
modparam("tls_mgm", "client_domain", "dom1")
modparam("tls_mgm", "certificate", "[dom1]/etc/pki/tls/certs/opensips.pem")
modparam("tls_mgm", "private_key", "[dom1]/etc/pki/tls/private/opensips.key")
modparam("tls_mgm", "ca_list",     "[dom1]/etc/pki/tls/certs/ca.pem")
...
modparam("db_postgres", "use_tls", 1)
...
modparam("usrloc", "db_url", "postgres://root:1234@localhost/opensips?tls_domain=dom1")
...
```


### Exported Functions


NONE


### Installation and Running


Notes about installation and running.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
