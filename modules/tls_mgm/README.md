---
title: "TLS_MGM module"
description: "This module is a management module for TLS certificates and parameters. It provides an interface for all the modules that use the TLS protocol. It also exports pseudo variables with certificate and TLS parameters."
---

## Admin Guide


### Overview


This module is a management module for TLS certificates and
			parameters. It provides an interface for all the modules that
			use the TLS protocol. It also exports pseudo variables with
			certificate and TLS parameters.


### Usage


This module is used to provision TLS certificates and parameters
			for all the modules that use TLS transport (like
			*proto_tls* or *proto_wss*).
			The module supports multiple
			virtual domains that can be assigned to different listeners
			(servers) or new connections (clients). Each TLS module that uses
			this management module should assign itself to one or more domains.


The module allows the definition of the TLS domains both via 
			module parameters (script level) and via an SQL table.


A script example which details this module's usage can be found in
		[tls example](#opensips_with_tls_script_example).


### TLS libraries


Besides TLS certificates and parameters, this module also acts as
			an inteface between the actual TLS implemenation (provided by
			*openSSL* or *wolfSSL* libraries)
			and transport protocol modules like *proto_tls* or
			*proto_wss*. The *tls_mgm* module
			transparently exposes the TLS operations implemented by
			*tls_openssl* and *tls_wolfssl* modules
			to the higher-level OpenSIPS transport modules.


The TLS library selection ca be configured through the
			[tls library](#param_tls_library) module parameter.


### TLS domains


The wording 'TLS domain' means that this TLS connection will have different
		parameters than another TLS connection (from another TLS domain). Thus, TLS
		domains are not directly related to different SIP domains, although they
		are often used in conjunction. Depending on the direction of the TLS handshake, a
		TLS domain is called 'client domain' (=outgoing TLS connection) or 'server domain'
		(= incoming TLS connection).


If you run several SIP domains you can specify some parameters for each of them
		separately (regardless if you have only one or multiple socket=tls:ip:port entries
		in the config file).


For example, TLS domains can be used in virtual hosting scenarios with TLS.
		OpenSIPS offers SIP service for multiple domains, e.g. atlanta.com and biloxi.com. Altough
		both domains will be hosted on a single SIP proxy, the SIP proxy needs 2 certificates: One
		for atlanta.com and one for biloxi.com. For incoming TLS connections, the SIP proxy
		has to present the respective certificate during the TLS handshake. As the SIP proxy
		does not have a received SIP message yet (this is done after the TLS handshake), the SIP
		proxy can not retrieve the target domain from SIP (which would have been usually retrieved 
		from the domain in the request URI). Thus, distinction for these domains must be done by using multiple listening sockets or by having clients that send the Servername TLS extension(SNI) in the
		handshake process.


For outgoing TLS connections, the TLS domain is chosen based on the destination socket of the underlying outgoing TCP connection and/or by taking a decision at script level via an AVP. For example, you can inspect headers like RURI or From and match the domain in the SIP header with filters that you have set up for the TLS domains.


NOTE: Except tls_handshake_timeout and tls_send_timeout all TLS parameters can be set
		per TLS domain.


### Defining TLS domains


TLS domains can be defined in two ways:


- by setting the *server_domain* or *client_domain* module parameters
- by provisioning in DB


For the domains defined in the DB, the certificate, private key, list of trusted CAs and Diffie-Hellman parameters are provisioned as BLOB values while for script defined domains you must provide path to files.


You can define domains both in the DB and script at the same time.


For any TLS domain (defined through script or DB) if not specified otherwise, the default settings are:


- method - *SSLv23*
- verify_cert - *1*
- require_cert - *1*
- certificate - *CFG_DIR/tls/cert.pem*
- private_key - *CFG_DIR/tls/ckey.pem*
- crl_check_all - *0*
- crl_dir - none
- ca_list - none
- ca_dir - */etc/pki/CA/*
- cipher_list -  the OpenSSL default ciphers
- dh_params -  none
- ec_curve -  none


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *tls_openssl* or *tls_wolfssl*,
				unless [tls library](#param_tls_library) is set to 'none'.


#### Dependencies of external libraries


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *None*.


### Exported Functions


#### is_peer_verified


Returns 1 if the message is received via TLS and the peer was verified
		during TLS connection handshake, otherwise it returns -1


This function can be used from REQUEST_ROUTE.


```opensips title="is_peer_verified usage"
...
if (is_peer_verified()) {
        xlog("L_INFO","request from verified TLS peer\n");
} else {
        xlog("L_INFO","request not verified\n");
}
...
```


### Exported MI Functions


#### tls_mgm:list


Replaces obsolete MI command: *tls_list*.


List all domains information.


#### tls_mgm:reload


Replaces obsolete MI command: *tls_reload*.


Reloads the TLS domains information from the database.
                The previous DB defined domains are discarded but the
                script defined domains are preserved.


### Exported Parameters


All these parameters can be used from the opensips.cfg file,
		to configure the behavior of OpenSIPS-TLS.


#### listen=interface


Not specific to TLS. Allows to specify the protocol
			(udp, tcp, tls), the IP address and the port where the
			listening server will be.


```opensips title="Set listen variable"
...
socket= tls:1.2.3.4:5061
...
				
```


#### tls_library (string)


Selects which TLS library to use. Possible values are:


- *auto* - auto-detect which TLS library
				module (*tls_openssl* or *tls_wolfssl*)
				was loaded. OpenSIPS will not start if no module, or both modules are
				found.
- *none* - do not use any TLS library; this
				is useful when the *tls_mgm* module is required only
				for the management of TLS certificates and parameters by modules like
				*db_mysql*, *rabbitmq* etc. (
				and not for TLS operations by transport modules like
				*proto_tls* etc.)
- *openssl* - use the *openSSL*
				library through the *tls_openssl* module.
- *wolfssl* - use the *wolfSSL*
				library through the *tls_wolfssl* module.


Default value is *auto*.


```opensips title="Set tls_library variable"
...
modparam("tls_mgm", "tls_library", "none")
...
				
```


#### tls_method ([domain]string)


Sets the TLS protocol. The domain part represents the name of
				the TLS domain. The supported TLS methods are:


- *TLSv1_3* - means OpenSIPS will
				accept only TLSv1.3 connections. This version is only
				available starting with OpenSSL 1.1.1 version.
- *TLSv1_2* - means OpenSIPS will
				accept only TLSv1.2 connections (rfc3261 conformant).
- *TLSv1* - means OpenSIPS will
				accept only TLSv1 connections (rfc3261 conformant).
- *SSLv23* - means OpenSIPS will
				accept any of the above methods, but the initial SSL
				hello must be v2 (in the initial hello all the supported
				protocols are advertised enabling switching to a higher
				and more secure version). The initial v2 hello means it
				will not accept connections from SSLv3 or TLSv1 only
				clients.


*If you are using an OpenSSL library newer than 1.1.0, you can
				also specify a range of accepted TLS versions as [VLOW]-[VHIGH].
				If VLOW is not specified it will use the minimum supported
				protocol version and if VHIGH is not specified it will use
				the maximum supported protocol version. This means that using
				a range where both the low and high values are missing, will
				accept all the supported methods, but unlike SSLv23 will not
				require the initial hello to be SSLv2.*


*Default value is SSLv23.*


> [!WARNING]
> For extended compatibility with older system, best use SSLv23.


If you want RFC3261 conformance and all your clients support
			TLSv1 (or you are planning to use encrypted "tunnels" only
			between different OpenSIPS proxies) use TLSv1. If you want to
			support older clients use SSLv23 (in fact most of the
			applications with SSL support use the SSLv23 method).


```opensips title="Set tls_method variable"
...
modparam("tls_mgm", "tls_method", "[dom]TLSv1")
...
				
```


```opensips title="Set tls_method range variable"
...
modparam("tls_mgm", "tls_method", "[dom]TLSv1-TLSv1_3")  # between v1 and v1.3
modparam("tls_mgm", "tls_method", "[dom]TLSv1-")         # v1 or higher
modparam("tls_mgm", "tls_method", "[dom]-TLSv1_2")       # up to v1.2
modparam("tls_mgm", "tls_method", "[dom]-")              # all supported
...
				
```


#### certificate ([domain](string)


Public certificate file for OpenSIPS. It will be used as
			server-side certificate for incoming TLS connections, and as
			a client-side certificate for outgoing TLS connections. The domain
			part represents the name of the TLS domain.


*Default value is "CFG_DIR/tls/cert.pem".*


```opensips title="Set certificate variable"
...
modparam("tls_mgm", "certificate", "[dom]/mycerts/certs/opensips_server_cert.pem")
...
				
```


#### private_key ([domain](string)


Private key of the above certificate. I must be kept in a
			safe place with tight permissions! The domain part
			represents the name of the TLS omain.


*Default value is "CFG_DIR/tls/ckey.pem".*


```opensips title="Set private_key variable"
...
modparam("tls_mgm", "private_key", "[dom]/mycerts/private/prik.pem")
...
				
```


#### ca_list ([domain](string)


List of trusted CAs. The file contains the certificates
			accepted, one after the other. It MUST be a file, not
			a folder. The domain part represents the name
			of the TLS domain.


*Default value is "".*


```opensips title="Set ca_list variable"
...
modparam("tls_mgm", "ca_list", "[dom]/mycerts/certs/ca_list.pem")
...
				
```


#### ca_dir ([domain](string)


Directory storing trusted CAs. The certificates in the directory
			must be in hashed form, as described in the
			[openssl documentation](https://www.openssl.org/docs/manmaster/man3/X509_LOOKUP_hash_dir.html) for the
			*Hashed Directory Method*. The domain part
			represents the name of the TLS domain.


*Default value is "/etc/pki/CA/".*


```opensips title="Set ca_dir variable"
...
modparam("tls_mgm", "ca_dir", "[dom]/mycerts/certs")
...
				
```


#### crl_dir ([domain](string)


Directory storing certificate revocation lists (CRLs). The domain
			part represents the name of the TLS domain.


*If this parameter is not set, no CRLs will be used.*


```opensips title="Set crl_dir variable"
...
modparam("tls_mgm", "crl_dir", "[dom]/mycerts/crls")
...
				
```


#### crl_check_all ([domain](string)


Setting this parameter with a non-zero integer value enables CRL
			checking for the entire certificate chain.


*By default, only the leaf certificate in the certificate chain
				is checked.*


```opensips title="Set crl_check_all variable"
...
modparam("tls_mgm", "crl_check_all", "[dom]1")
...
				
```


#### ciphers_list ([domain](string)


You can specify the list of algorithms for authentication
			and encryption that you allow. The domain part
			represents the name of the TLS domain. To obtain a list of ciphers
			and then choose, use the openssl application:


- openssl ciphers 'ALL:eNULL:!LOW:!EXPORT'


> [!WARNING]
> Do not use the NULL algorithms (no encryption) ... only for testing!!!


*It defaults to the OpenSSL default ciphers.*


```opensips title="Set ciphers_list variable"
...
modparam("tls_mgm", "ciphers_list", "[dom]NULL")
...
				
```


#### dh_params ([domain](string)


You can specify a file which contains Diffie-Hellman
			parameters as a PEM-file. This is needed if you would like
			to specify ciphers including Diffie-Hellman mode. The 
			domain part represents the name of the TLS domain.


*It defaults to not set a dh param file.*


```opensips title="Set dh_params variable"
...
modparam("tls_mgm", "dh_params", "[dom]/etc/pki/CA/dh1024.pem")
...
				
```


#### ec_curve ([domain](string)


You can specify an elliptic curve which should be used for
			ciphers which demand an elliptic curve. The domain part
			represents the name of the TLS domain.


It's usable only if TLS v1.1/1.2 support was compiled.
			A list of curves which can be used you can get by


```bash
				openssl ecparam -list_curves
			
```


*It defaults to not set a elliptic curve.*


#### verify_cert ([domain](string)


Activates SSL_VERIFY_PEER in the ssl_context. For a detailed
			explanation, check the *openssl* documentation.


The domain part represents the name of the TLS domain.


Default value is *1*.


```opensips title="Set verify_cert variable"
...
modparam("tls_mgm", "verify_cert", "[dom]0")
...
				
```


#### require_cert ([domain](string)


Activates SSL_VERIFY_FAIL_IF_NO_PEER_CERT in the ssl_context. For a
			detailed explanation, check the *openssl*
			documentation. This parameter only makes sense for server domains
			and if the [verify cert](#param_verify_cert) parameter is also set.


The domain part represents the name of the TLS domain.


Default value is *1*.


```opensips title="Set require_cert variable"
...
modparam("tls_mgm", "require_cert", "[dom]0")
...
				
```


#### client_tls_domain_avp (string)


Name of the AVP used for enforcing the selection of a specific TLS
			client domain. Setting this AVP to the name of a TLS client domain will
			result in using that specific domain regardless of the standard matching
			mechanism.


Note: If there is already an existing TLS connection to the remote target,
			it will be reused and setting this AVP has no effect.


Note: You can force a particular domain to be used just for a particular
			branch by setting the *$bavp* variable with the same
			name. When both *$bavp* and *$avp*
			variables are set, the first one takes precedence.


*No default value.*


```opensips title="Set client_tls_domain_avp variable"
...
modparam("tls_mgm", "client_tls_domain_avp", "tls_match_dom")
...
				
```


#### client_sip_domain_avp (string)


Name of the AVP that sets the SIP domain used in the TLS client
			domain matching process.


Note: If there is already an existing TLS connection to the remote target,
			it will be reused and setting this AVP has no effect.


Note: You can force a particular SIP domain to be used just for a particular
			branch by setting the *$bavp* variable with the same
			name. When both *$bavp* and *$avp*
			variables are set, the first one takes precedence.


For the AVP usage example, refer to  [domains param](#param_server_domain_client_domain).


*No default value.*


```opensips title="Set client_sip_domain_avp variable"
...
modparam("tls_mgm", "client_sip_domain_avp", "sip_match_dom")
...
				
```


#### db_url (string)


The database url. It cannot be NULL.


You cannot use the "tls_domain=*dom_name*" URL parameter
			for a TLS connection to the database for the tls_mgm module itself.


```opensips title="Usage of db_url block"
modparam("tls_mgm", "db_url", "mysql://root:admin@localhost/opensips")
				
```


#### db_table (string)


Sets the database table name.


Default value is "tls_mgm".


```opensips title="Usage of db_table block"
modparam("tls_mgm", "db_table", "tls_mgm")
                                
```


#### domain_col (string)


Sets the name for the TLS domain column.


Default value is "domain".


```opensips title="Usage of domain_col block"
modparam("tls_mgm", "domain_col", "tls_domain")
                                
```


#### match_ip_address_col (string)


Sets the IP address matching column name.


Default value is "match_ip_address".


```opensips title="Usage of match_ip_address_col block"
modparam("tls_mgm", "match_ip_address_col", "addr")
                                
```


#### match_sip_domain_col (string)


Sets the SIP domain matching column name.


Default value is "match_sip_domain".


```opensips title="Usage of match_sip_domain_col block"
modparam("tls_mgm", "match_sip_domain_col", "addr")
                                
```


#### tls_method_col (string)


Sets the method column name.


Default value is "method".


```opensips title="Usage of tls_method_col block"
modparam("tls_mgm", "tls_method_col", "method")
                                
```


#### verify_cert_col (string)


Sets the verrify certificate column name.


Default value is "verify_cert".


```opensips title="Usage of vertify_cert_col block"
modparam("tls_mgm", "verify_cert_col", "verify_cert")
                                
```


#### require_cert_col (string)


Sets the require certificate column name.


Default value is "require_cert".


```opensips title="Usage of require_cert_col block"
modparam("tls_mgm", "require_cert_col", "req")
                                
```


#### certificate_col (string)


Sets the certificate column name.


Default value is "certificate".


```opensips title="Usage of certificate_col block"
modparam("tls_mgm", "certificate_col", "certificate")
                                
```


#### private_key_col (string)


Sets the private key column name.


Default value is "private_key".


```opensips title="Usage of private_key_col block"
modparam("tls_mgm", "private_key_col", "pk")
                                
```


#### crl_check_all_col (string)


Sets the crl_check_all column name.


Default value is "crl_check_all".


```opensips title="Usage of crl_check_all block"
modparam("tls_mgm", "crl_check_all_col", "crl_check")
                                
```


#### crl_dir_col (string)


Sets the crl directory column name.


Default value is "crl_dir".


```opensips title="Usage of crl_dir_col block"
modparam("tls_mgm", "crl_dir_col", "crl_dir")
                                
```


#### ca_list_col (string)


Sets the CA list column name.


Default value is "ca_list".


```opensips title="Usage of ca_list_col block"
modparam("tls_mgm", "ca_list_col", "ca_list")
                                
```


#### ca_dir_col (string)


Sets the CA directory column name.


Default value is "ca_dir".


```opensips title="Usage of ca_dir_col block"
modparam("tls_mgm", "ca_dir_col", "ca_dir")
                                
```


#### cipher_list_col (string)


Sets the cipher list column name.


Default value is "cipher_list".


```opensips title="Usage of cipher_list_col block"
modparam("tls_mgm", "cipher_list_col", "cipher_list")
                                
```


#### dh_params_col (string)


Sets the Diffie-Hellmann parameters column name.


Default value is "dh_params".


```opensips title="Usage of dh_params_col block"
modparam("tls_mgm", "dh_params_col", "dh_parms")
                                
```


#### ec_curve_col (string)


Sets the ec_curve column name.


Default value is "ec_curve".


```opensips title="Usage of ec_curve_col block"
modparam("tls_mgm", "ec_curve_col", "ec_curve")
                                
```


#### match_ip_address (string)


The IP addresses and ports used to match a TLS connection with a
			virtual TLS domain. For TLS server domains, these values will be
			mathced against the socket on which the connection is received. For
			TLS client domains, the values will be compared with the destination
			socket of the connection.


The parameter accepts a list of values, and the special value "*"
				means: match any address.


*Default value is "*" (match any address).*


```opensips title="Set match_ip_address variable"
...
modparam("tls_mgm", "match_ip_address", "[dom1]10.0.0.10:5061, 10.0.0.11:5061")
...
				
```


#### match_sip_domain (string)


The SIP domains used to match a TLS connection with a
			virtual TLS domain. For TLS server domains, these values will be
			matched against the hostname provided in the TLS Servername extension(SNI).
			For TLS client domains, the values will be compared with the value of
			the [client sip domain avp](#param_client_sip_domain_avp) AVP.


The parameter accepts a list of FQDNs or the special values:


- *** - match any sip domain(
					including no SNI provided, in case of TLS server domains);
- *none* - match the TLS domain
					when there is no SNI provided (make sense only for TLS server
					domains). Note that if a SNI is provided, but does not match any
					other SIP domain filter, the connection will be rejected.


The FQDNs can be specified as with Unix shell-style wildcards. If
				there are multiple potential matches, the most specific domain will
				be selected(eg. a request for "foo.bar.com" is matched with the domain
				specified with "foo.bar.com" versus the one with "*.bar.com").


*Default value is "*" (match any sip domain).*


```opensips title="Set match_sip_domain variable"
...
modparam("tls_mgm", "match_sip_domain", "[dom1]foo.com, bar.com, *.baz.com")
modparam("tls_mgm", "match_sip_domain", "[default_dom]*")
...
				
```


#### server_domain, client_domain (string)


You can define virtual TLS domains through these parameters.


The value of these parameters represents the virtual tls domain's
				name which is only used for identification.


```opensips title="Usage of tls_client_domain and tls_server_domain block"
...
socket=tls:10.0.0.10:5061
...
# set the TLS client domain AVP
modparam("tls_mgm", "client_sip_domain_avp", "tls_sip_dom")
...

# 'atlanta' server domain
modparam("tls_mgm", "server_domain", "dom1")
modparam("tls_mgm", "match_ip_address", "[dom1]10.0.0.10:5061")
modparam("tls_mgm", "match_sip_domain", "[dom1]atlanta.com")

modparam("tls_mgm", "certificate", "[dom1]/certs/atlanta.com/cert.pem")
modparam("tls_mgm", "private_key", "[dom1]/certs/atlanta.com/privkey.pem")
modparam("tls_mgm", "ca_list", "[dom1]/certs/wellknownCAs")
modparam("tls_mgm", "tls_method", "[dom1]tlsv1")
modparam("tls_mgm", "verify_cert", "[dom1]1")
modparam("tls_mgm", "require_cert", "[dom1]1")

#'biloxi' server domain
modparam("tls_mgm", "server_domain", "dom2")
modparam("tls_mgm", "match_ip_address", "[dom2]10.0.0.10:5061")
modparam("tls_mgm", "match_sip_domain", "[dom2]biloxi.com")

modparam("tls_mgm", "certificate", "[dom2]/certs/biloxi.com/cert.pem")
modparam("tls_mgm", "private_key", "[dom2]/certs/biloxi.com/privkey.pem")
modparam("tls_mgm", "ca_list", "[dom2]/certs/wellknownCAs")
modparam("tls_mgm", "tls_method", "[dom2]tlsv1")
modparam("tls_mgm", "verify_cert", "[dom2]1")
modparam("tls_mgm", "require_cert", "[dom2]1")

# generic TLS server domain, if the client does not provide SNI
modparam("tls_mgm", "server_domain", "dom3")
modparam("tls_mgm", "match_ip_address", "[dom3]10.0.0.10:5061")
modparam("tls_mgm", "match_sip_domain", "[dom3]none")

modparam("tls_mgm", "certificate", "[dom3]/certs/generic/cert.pem")
modparam("tls_mgm", "private_key", "[dom3]/certs/generic/privkey.pem")
modparam("tls_mgm", "ca_list", "[dom3]/certs/wellknownCAs")
modparam("tls_mgm", "tls_method", "[dom3]tlsv1")
modparam("tls_mgm", "verify_cert", "[dom3]1")
modparam("tls_mgm", "require_cert", "[dom3]1")

# 'atlanta' client domain
modparam("tls_mgm", "client_domain", "dom4")
modparam("tls_mgm", "match_ip_address", "[dom4]*")
modparam("tls_mgm", "match_sip_domain", "[dom4]atlanta.com")


modparam("tls_mgm", "certificate", "[dom4]/certs/atlanta.com/cert.pem")
modparam("tls_mgm", "private_key", "[dom4]/certs/atlanta.com/privkey.pem")
modparam("tls_mgm", "ca_list", "[dom4]/certs/wellknownCAs")
modparam("tls_mgm", "tls_method", "[dom4]tlsv1")
modparam("tls_mgm", "verify_cert", "[dom4]1")
modparam("tls_mgm", "require_cert", "[dom4]1")

# 'biloxi' client domain
modparam("tls_mgm", "client_domain", "dom5")
modparam("tls_mgm", "match_ip_address", "[dom5]*")
modparam("tls_mgm", "match_sip_domain", "[dom5]biloxi.com")

modparam("tls_mgm", "certificate", "[dom5]/certs/biloxi.com/cert.pem")
modparam("tls_mgm", "private_key", "[dom5]/certs/biloxi.com/privkey.pem")
modparam("tls_mgm", "ca_list", "[dom5]/certs/wellknownCAs")
modparam("tls_mgm", "tls_method", "[dom5]tlsv1")
modparam("tls_mgm", "verify_cert", "[dom5]1")
modparam("tls_mgm", "require_cert", "[dom5]1")

# TLS client domain for GW provider
modparam("tls_mgm", "client_domain", "dom6")
modparam("tls_mgm", "match_ip_address", "[dom6]1.2.3.4:6677")
modparam("tls_mgm", "match_sip_domain", "[dom6]*")

modparam("tls_mgm", "certificate", "[dom6]/certs/gw/cert.pem")
modparam("tls_mgm", "private_key", "[dom6]/certs/gw/privkey.pem")
modparam("tls_mgm", "ca_list", "[dom6]/certs/wellknownCAs")
modparam("tls_mgm", "tls_method", "[dom6]tlsv1")
modparam("tls_mgm", "verify_cert", "[dom6]0")

...
route{
...
    # we match the TLS client domain using the SIP domain in the RURI
    $avp(tls_sip_dom) = $rd;
    t_relay();
    exit;
...
    # calls to the PSTN GW, will match the correct TLS domain by IP
    t_relay("tls:1.2.3.4:6677");
    exit;
...
				
```


### Variables


This module exports the follong variables:


Some variables are available for both, the peer'S certificate and
	the local certificate. Further, some parameters can be read from the
	"Subject" field or the "Issuer" field.


#### $tls_version


*$tls_version* - the TLS/SSL version which is
			used on the TLS connection from which the message was received.
			String type.


#### $tls_description


*$tls_description* - the TLS/SSL description
			of the TLS connection from which the message was received. String
			type.


#### $tls_cipher_info


*$tls_cipher_info* - the TLS/SSL cipher which
			is used on the TLS connection from which the message was received.
			String type.


#### $tls_cipher_bits


*$tls_cipher_bits* - the number of cipher bits
			which are used on the TLS connection from which the message was
			received. String and Integer type.


#### $tls_[peer|my]_version


*$tls_[peer|my]_version* - the version of the
			certificate. String type.


#### $tls_[peer|my]_serial


*$tls_[peer|my]_serial* - the serial number
			of the certificate. String and Integer type.


#### $tls_[peer|my]_[subject|issuer]


*$tls_[peer|my]_[subject|issuer]* - ASCII dump
			of the fields in the issuer/subject section of the certificate.
			String type.


```c title="Example of $tls_[peer|my]_[subject|issuer]"
/C=AT/ST=Vienna/L=Vienna/O=enum.at/CN=enum.at
```


#### $tls_[peer|my]_[subject|issuer]_cn


*$tls_[peer|my]_[subject|issuer]_cn* -
			commonName in the issuer/subject section of the certificate.
			String type.


#### $tls_[peer|my]_[subject|issuer]_locality


*$tls_[peer|my]_[subject|issuer]_locality* -
			localityName in the issuer/subject section of the certificate.
			String type.


#### $tls_[peer|my]_[subject|issuer]_country


*$tls_[peer|my]_[subject|issuer]_country* -
			countryName in the issuer/subject section of the certificate.
			String type.


#### $tls_[peer|my]_[subject|issuer]_state


*$tls_[peer|my]_[subject|issuer]_state* -
			stateOrProvinceName in the issuer/subject section of the
			certificate. String type.


#### $tls_[peer|my]_[subject|issuer]_organization


*$tls_[peer|my]_[subject|issuer]_organization* -
			organizationName in the issuer/subject section of the certificate.
			String type.


#### $tls_[peer|my]_[subject|issuer]_unit


*$tls_[peer|my]_[subject|issuer]_unit* -
			organizationalUnitName in the issuer/subject section of the
			certificate. String type.


#### $tls_[peer|my]_san_email


*$tls_[peer|my]_san_email* - email address in
			the "subject alternative name" extension. String type.


#### $tls_[peer|my]_san_hostname


*$tls_[peer|my]_san_hostname* - hostname (DNS)
			in the "subject alternative name" extension. String
			type.


#### $tls_[peer|my]_san_uri


*$tls_[peer|my]_san_uri* - URI in the
			"subject alternative name" extension.
			String type.


#### $tls_[peer|my]_san_ip


*$tls_[peer|my]_san_ip* - ip address in the
			"subject alternative name" extension.
			String type.


#### $tls_peer_verified


*$tls_peer_verified* - Returns 1 if the peer's
			certificate was successful verified. Otherwise it returns 0.
			String and Integer type.


#### $tls_peer_revoked


*$tls_peer_revoked* - Returns 1 if the peer's
			certificate was revoked. Otherwise it returns 0.
			String and Integer type.


#### $tls_peer_expired


*$tls_peer_expired* - Returns 1 if the peer's
			certificate is expired. Otherwise it returns 0.
			String and Integer type.


#### $tls_peer_selfsigned


*$tls_peer_selfsigned* - Returns 1 if the
			peer's certificate is selfsigned. Otherwise it returns 0.
			String and Integer type.


#### $tls_peer_notBefore


*$tls_peer_notBefore* - Returns the notBefore
			validity date of the peer's certificate.
			String type.


#### $tls_peer_notAfter


*$tls_peer_notAfter* - Returns the notAfter
			validity date of the peer's certificate.
			String type.


### OpenSIPS with TLS - script example


IMPORTANT: The TLS support is based on TCP, and for allowing OpenSIPS
		to use TCP, it must be started in multi-process mode. So, there is
		a must to have the "fork" parameter set to "yes":


NOTE: Since the TLS engine is quite memory consuming, increase the
		used memory by the run time parameter "-m" (see OpenSIPS -h for more
		details).


- fork = yes


```opensips title="Script with TLS support"
  # ----------- global configuration parameters ------------------------
  log_level=3
  stderror_enabled=no
  syslog_enabled=yes

  check_via=no
  dns=no
  rev_dns=no
  socket=udp:your_serv_IP:5060
  socket=tls:your_serv_IP:5061
  udp_workers=4

  # ------------------ module loading ----------------------------------

  loadmodule "proto_tls.so"
  loadmodule "proto_udp.so"

  #TLS specific settings
  loadmodule "tls_mgm.so"

  modparam("tls_mgm", "certificate", "/path/opensipsX_cert.pem")
  modparam("tls_mgm", "private_key", "/path/privkey.pem")
  modparam("tls_mgm", "ca_list", "/path/calist.pem")
  modparam("tls_mgm", "ca_list", "/path/calist.pem")
  modparam("tls_mgm", "require_cert", "1")
  modparam("tls_mgm", "verify_cert", "1")

  alias=_DNS_ALIAS_


  loadmodule "sl.so"
  loadmodule "rr.so"
  loadmodule "maxfwd.so"
  loadmodule "mysql.so"
  loadmodule "usrloc.so"
  loadmodule "registrar.so"
  loadmodule "tm.so"
  loadmodule "auth.so"
  loadmodule "auth_db.so"
  loadmodule "textops.so"
  loadmodule "sipmsgops.so"
  loadmodule "signaling.so"
  loadmodule "uri_db.so"

  # ----------------- setting module-specific parameters ---------------

  # -- auth_db params --
  modparam("auth_db", "db_url", "sql_url")
  modparam("auth_db", "password_column", "password")
  modparam("auth_db", "calculate_ha1", 1)

  # -- registrar params --
  # no multiple registrations
  modparam("registrar", "append_branches", 0)

  # -------------------------  request routing logic -------------------

  # main routing logic

  route{

  # initial sanity checks
  if (!mf_process_maxfwd_header("10")) {
      send_reply(483,"Too Many Hops");
      exit;
  };

  # if somene claims to belong to our domain in From,
  # challenge him (skip REGISTERs -- we will chalenge them later)
  if (is_myself("$fd")) {
      setflag(1);
      if ( is_method("INVITE|SUBSCRIBE|MESSAGE")
      && !(is_myself("$si")) ) {
          if  (!(proxy_authorize( "domA.net", "subscriber" ))) {
              proxy_challenge("domA.net","0"/*no-qop*/);
              exit;
          };
          if ($au!=$fU) {
              xlog("FROM hdr Cheating attempt in INVITE\n");
              send_reply(403,
                  "That is ugly -- use From=id next time (OB)");
              exit;
          };
      }; # non-REGISTER from other domain
  } else if ( is_method("INVITE") && !is_myself("$rd") ) {
      send_reply(403, "No relaying");
      exit;
  };

  /* ********   do record-route and loose-route ******* */
  if (!is_method("REGISTER"))
      record_route();

  if (loose_route()) {
      append_hf("P-hint: rr-enforced\r\n");
      t_relay();
      exit;
  };

  /* ******* check for requests targeted out of our domain ******* */
  if ( !is_myself("$rd") ) {
      append_hf("P-hint: OUTBOUND\r\n");
      if ($rd=="domB.net") {
          t_relay("tls:domB.net:5061");
      } else if ($rd=="domC.net") {
          t_relay("tls:domC.net:5061");
      } else {
          t_relay();
      };
      exit;
  };

  /* ******* divert to other domain according to prefixes ******* */
  if (!is_method("REGISTER")) {
      if ( $ru=~"sip:201") {
          strip(3);
          $rd = "domB.net";
          t_relay("tls:domB.net:5061");
          exit;
      } else if ( $ru=~"sip:202" ) {
          strip(3);
          $rd = "domC.net";
          t_relay("tls:domC.net:5061");
          exit;
      };
  };

  /* ************ requests for our domain ********** */
  if (is_method("REGISTER")) {
      if (!www_authorize( "domA.net", "subscriber" )) {
          # challenge if none or invalid credentials
          www_challenge( "domA.net" /* realm */,
              "0" /* no qop -- some phones can't deal with it */);
          exit;
      };
      if ($au!=$tU) {
          xlog("TO hdr Cheating attempt\n");
          send_reply(403, "That is ugly -- use To=id in REGISTERs");
          exit;
      };
      # it is an authenticated request, update Contact database now
      if (!save("location")) {
          sl_reply_error();
      };
      exit;
  };

  # native SIP destinations are handled using USRLOC DB
  if (!lookup("location")) {
      # handle user which was not found
      send_reply(404, "Not Found");
      exit;
  };

  # remove all present Alert-info headers
  remove_hf("Alert-Info");

  if (is_method("INVITE") && ($rP=="TLS" || isflagset(1))) {
      append_hf("Alert-info: 1\r\n");                     # cisco 7960
      append_hf("Alert-info: Bellcore-dr4\r\n");          # cisco ATA
      append_hf("Alert-info: http://foo.bar/x.wav\r\n");  # snom
  };

  # do forwarding
  if (!t_relay()) {
      sl_reply_error();
  };

  #end of script
  }
		
```


### Debug TLS connections


If you want to debug TLS connections, put the following log
	statements into your OpenSIPS.cfg.
	This will dump all available TLS pseudo variables.


```opensips title="Example of TLS logging"
xlog("L_INFO","================= start TLS pseudo variables ===============\n");
xlog("L_INFO","$$tls_version                   = '$tls_version'\n");
xlog("L_INFO","$$tls_description               = '$tls_description'\n");
xlog("L_INFO","$$tls_cipher_info               = '$tls_cipher_info'\n");
xlog("L_INFO","$$tls_cipher_bits               = '$tls_cipher_bits'\n");
xlog("L_INFO","$$tls_peer_subject              = '$tls_peer_subject'\n");
xlog("L_INFO","$$tls_peer_issuer               = '$tls_peer_issuer'\n");
xlog("L_INFO","$$tls_my_subject                = '$tls_my_subject'\n");
xlog("L_INFO","$$tls_my_issuer                 = '$tls_my_issuer'\n");
xlog("L_INFO","$$tls_peer_version              = '$tls_peer_version'\n");
xlog("L_INFO","$$tls_my_version                = '$tls_my_version'\n");
xlog("L_INFO","$$tls_peer_serial               = '$tls_peer_serial'\n");
xlog("L_INFO","$$tls_my_serial                 = '$tls_my_serial'\n");
xlog("L_INFO","$$tls_peer_subject_cn           = '$tls_peer_subject_cn'\n");
xlog("L_INFO","$$tls_peer_issuer_cn            = '$tls_peer_issuer_cn'\n");
xlog("L_INFO","$$tls_my_subject_cn             = '$tls_my_subject_cn'\n");
xlog("L_INFO","$$tls_my_issuer_cn              = '$tls_my_issuer_cn'\n");
xlog("L_INFO","$$tls_peer_subject_locality     = '$tls_peer_subject_locality'\n");
xlog("L_INFO","$$tls_peer_issuer_locality      = '$tls_peer_issuer_locality'\n");
xlog("L_INFO","$$tls_my_subject_locality       = '$tls_my_subject_locality'\n");
xlog("L_INFO","$$tls_my_issuer_locality        = '$tls_my_issuer_locality'\n");
xlog("L_INFO","$$tls_peer_subject_country      = '$tls_peer_subject_country'\n");
xlog("L_INFO","$$tls_peer_issuer_country       = '$tls_peer_issuer_country'\n");
xlog("L_INFO","$$tls_my_subject_country        = '$tls_my_subject_country'\n");
xlog("L_INFO","$$tls_my_issuer_country         = '$tls_my_issuer_country'\n");
xlog("L_INFO","$$tls_peer_subject_state        = '$tls_peer_subject_state'\n");
xlog("L_INFO","$$tls_peer_issuer_state         = '$tls_peer_issuer_state'\n");
xlog("L_INFO","$$tls_my_subject_state          = '$tls_my_subject_state'\n");
xlog("L_INFO","$$tls_my_issuer_state           = '$tls_my_issuer_state'\n");
xlog("L_INFO","$$tls_peer_subject_organization = '$tls_peer_subject_organization'\n");
xlog("L_INFO","$$tls_peer_issuer_organization  = '$tls_peer_issuer_organization'\n");
xlog("L_INFO","$$tls_my_subject_organization   = '$tls_my_subject_organization'\n");
xlog("L_INFO","$$tls_my_issuer_organization    = '$tls_my_issuer_organization'\n");
xlog("L_INFO","$$tls_peer_subject_unit         = '$tls_peer_subject_unit'\n");
xlog("L_INFO","$$tls_peer_issuer_unit          = '$tls_peer_issuer_unit'\n");
xlog("L_INFO","$$tls_my_subject_unit           = '$tls_my_subject_unit'\n");
xlog("L_INFO","$$tls_my_issuer_unit            = '$tls_my_issuer_unit'\n");
xlog("L_INFO","$$tls_peer_san_email            = '$tls_peer_san_email'\n");
xlog("L_INFO","$$tls_my_san_email              = '$tls_my_san_email'\n");
xlog("L_INFO","$$tls_peer_san_hostname         = '$tls_peer_san_hostname'\n");
xlog("L_INFO","$$tls_my_san_hostname           = '$tls_my_san_hostname'\n");
xlog("L_INFO","$$tls_peer_san_uri              = '$tls_peer_san_uri'\n");
xlog("L_INFO","$$tls_my_san_uri                = '$tls_my_san_uri'\n");
xlog("L_INFO","$$tls_peer_san_ip               = '$tls_peer_san_ip'\n");
xlog("L_INFO","$$tls_my_san_ip                 = '$tls_my_san_ip'\n");
xlog("L_INFO","$$tls_peer_verified             = '$tls_peer_verified'\n");
xlog("L_INFO","$$tls_peer_revoked              = '$tls_peer_revoked'\n");
xlog("L_INFO","$$tls_peer_expired              = '$tls_peer_expired'\n");
xlog("L_INFO","$$tls_peer_selfsigned           = '$tls_peer_selfsigned'\n");
xlog("L_INFO","$$tls_peer_notBefore            = '$tls_peer_notBefore'\n");
xlog("L_INFO","$$tls_peer_notAfter             = '$tls_peer_notAfter'\n");
xlog("L_INFO","================= end TLS pseudo variables ===============\n");
```


## Developer Guide


### API Functions


#### find_server_domain


struct tls_domain *find_server_domain(struct ip_addr *ip,
                    unsigned short port);


Find a TLS server domain with given ip and port
                    (local listening socket).


#### find_client_domain


struct tls_domain *find_client_domain(struct ip_addr *ip,
                     unsigned short port);


Find TLS client domain.


#### get_handshake_timeout


int get_handshake_timeout(void);


Returns the handshanke timeout.


#### get_send_timeout


int get_send_timeout(void);


Returns the send timeout.


### TLS_CONFIG


It contains configuration variables for OpenSIPS's TLS (timeouts,
		file paths, etc).


### TLS_INIT


Initialization related functions and parameters.


#### ssl context


extern SSL_CTX *default_client_ctx;


The ssl context is a member of the TLS domain strcuture. Thus, every
			TLS domain, default and virtual - servers and clients, have its own SSL context.


#### pre_init_tls


int init_tls(void);


Called once to pre_initialize the tls subsystem, from the main().
			Called before parsing the configuration file.


#### init_tls


int init_tls(void);


Called once to initialize the tls subsystem, from the main().
			Called after parsing the configuration file.


#### destroy_tls


void destroy_tls(void);


Called once, just before cleanup.


#### tls_init


int tls_init(struct socket_info *c);


Called once for each tls socket created, from main.c


### TLS_DOMAIN


#### tls_domains


extern struct tls_domain *tls_default_server_domain;


The default TLS server domain.


extern struct tls_domain *tls_default_client_domain;


The default TLS client domain.


extern struct tls_domain *tls_server_domains;


List with defined server domains.


extern struct tls_domain *tls_client_domains;


List with defined client domains.


#### tls_find_server_domain


struct tls_domain *tls_find_server_domain(struct ip_addr *ip,
			unsigned short port);


Find a TLS server domain with given ip and port
			(local listening socket).


#### tls_find_client_domain


struct tls_domain *tls_find_client_domain(struct ip_addr *ip,
			unsigned short port);


Find TLS client domain.


#### tls_find_client_domain_addr


struct tls_domain *tls_find_client_domain_addr(struct ip_addr *ip,
			unsigned short port);


Find TLS client domain with given ip and port
			(socket of the remote destination).


#### tls_find_client_domain_name


struct tls_domain *tls_find_client_name(str name);


Find TLS client domain with given name.


#### tls_new__domain


struct tls_domain *tls_new_domain(int type);


Creates new TLS: allocate memory, set the type and initialize members


#### tls_new_server_domain


int tls_new_server_domain(struct ip_addr *ip, unsigned short port);


Creates and adds to the list of TLS server domains a new domain.


#### tls_new_client_domain


int tls_new_client_domain(struct ip_addr *ip, unsigned short port);


Creates and adds to the list of TLS client domains a new socket based domain.


#### tls_new_client_domain_name


int tls_new_client_domain_name(char *s, int len);


Creates and adds to the list of TLS client domains a new name based domain.


#### tls_free_domains


void tls_free_domains(void);


Cleans up the entire domain lists.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
