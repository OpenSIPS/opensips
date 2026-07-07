---
title: "mysql Module"
description: "This is a module which provides MySQL connectivity for OpenSIPS. It implements the DB API defined in OpenSIPS."
---

## Admin Guide


### Overview


This is a module which provides MySQL connectivity for OpenSIPS.
		It implements the DB API defined in OpenSIPS.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *If a [use tls](#param_use_tls) is defined, the **tls_mgm** module will need to be loaded as well*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *libmysqlclient-dev* - the development libraries of mysql-client.


### Exported Parameters


#### exec_query_threshold (integer)


If queries take longer than 'exec_query_threshold' microseconds, warning
		messages will be written to logging facility.


*Default value is 0 - disabled.*


```opensips title="Set exec_query_threshold parameter"
...
modparam("db_mysql", "exec_query_threshold", 60000)
...
```


#### timeout_interval (integer)


Time interval after which a connection attempt (read or write request)
		is aborted. The value counts three times, as several retries are done
		from the driver before it gives up.


The read timeout parameter is ignored on driver versions prior to
		"5.1.12", "5.0.25" and "4.1.22".
		The write timeout parameter is ignored on version prior to "5.1.12"
		and "5.0.25", the "4.1" release don't support it at all.


*Default value is 2 (6 sec).*


```opensips title="Set timeout_interval parameter"
...
modparam("db_mysql", "timeout_interval", 2)
...
```


#### max_db_queries (integer)


The maximum number of retries to execute a failed query due to connections problems.
            If this parameter is set improperly, it is set to default value.


*Default value is 2.*


```opensips title="Set max_db_queries parameter"
...
modparam("db_mysql", "max_db_queries", 2)
...
```


#### max_db_retries (integer)


The maximum number of database connection retries. If this parameter
                is set improperly, it is set to default value.


*Default value is 3.*


```opensips title="Set max_db_retries parameter"
...
modparam("db_mysql", "max_db_retries", 2)
...
```


#### ps_max_col_size (integer)


The maximum size of a column's data, when fetched using prepared
		statements.  Particularly relevant for variable-length data, such as
		CHAR, BLOB, etc.


NOTE: Should a column's data exceed this limit, the value will be
		silently truncated to fit the buffer, without reporting any errors!


*Default value is *1024 (bytes)*.*


```opensips title="Set ps_max_col_size parameter"
...
modparam("db_mysql", "ps_max_col_size", 4096)
...
```


#### use_tls (integer)


Setting this parameter will allow you to use TLS for MySQL connections.
		In order to enable TLS for a specific connection, you can use the
		"**tls_domain=**dom_name" URL parameter in the db_url of
		the respective OpenSIPS module. This should be placed at the end of the
		URL after the **'?'** character. Additionally,
		the query string may include the "**tls_opts=**
		PKEY,CERT,CA,CA_DIR,CIPHERS" CSV parameter, in order to control/limit the
		amount of TLS options passed to the TLS library.


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


```opensips title="Set the use_tls parameter"
...
modparam("tls_mgm", "client_domain", "dom1")
modparam("tls_mgm", "certificate", "[dom1]/etc/pki/tls/certs/opensips.pem")
modparam("tls_mgm", "private_key", "[dom1]/etc/pki/tls/private/opensips.key")
modparam("tls_mgm", "ca_list",     "[dom1]/etc/pki/tls/certs/ca.pem")
...
modparam("db_mysql", "use_tls", 1)
...
modparam("usrloc", "db_url", "mysql://root:1234@localhost/opensips?tls_domain=dom1")
...
modparam("usrloc", "db_url", "mysql://root:1234@localhost/opensips?tls_domain=dom1&tls_opts=PKEY,CERT,CA,CA_DIR,CIPHERS")
...
```


### Exported Functions


No function exported to be used from configuration file.


### Installation


Because it dependes on an external library, the mysql module is not
		compiled and installed by default. You can use one of the next options.


- - edit the "Makefile" and remove "db_mysql" from "excluded_modules"
			list. Then follow the standard procedure to install OpenSIPS:
			"make all; make install".
- - from command line use: 'make all include_modules="db_mysql";
			make install include_modules="db_mysql"'.


### Exported Events


#### E_MYSQL_CONNECTION


This event is raised when a MySQL connection is lost or recovered.


Parameters:


- *url* - the URL of the connection as specified by the *db_url* parameter.
- *status* - *connected* if the connection recovered, or 
				*disconnected* if the connection was lost.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
