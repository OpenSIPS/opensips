---
title: "TLS_MGM module"
description: "This module is a management module for TLS certificates and parameters. It provides an interfaces for all the modules that use the TLS protocol. It also implements TLS related functions to use in the routing script, and exports pseudo variables with certificate and TLS parameters."
---

## Admin Guide


### Overview


This module is a management module for TLS certificates and
			parameters. It provides an interfaces for all the modules that
			use the TLS protocol. It also implements TLS related functions
			to use in the routing script, and exports pseudo variables with
			certificate and TLS parameters.


### History


The TLS support was originally developed by Peter Griffiths and posted
		as a patch on SER development mailing list. Thanks to Cesc
		Santasusana, several problems were fixed and some improvements were
		added.


The TLS support was simultaneously added in both projects. In SER,
		the support was committed in a separate "experimental"
		CVS tree, as patch to the main CVS tree. In OpenSIPS, the support was
		integrated directly into the CVS tree, as a built-in component, and is
		part of stable OpenSIPS since release >=1.0.0.


Starting from OpenSIPS 2.2, the certificates managemnet has been
			decoupled from the TLS communication in two different modules:
			*dh_params* which handles the TLS communication
			and *tls_mgm* which handles TLS handshake
			(certificates and parameters).


### Usage


This module is used to provision TLS certificates and parameters
			for all the modules that use TLS transport (currently only
			*proto_tls*). The module supports multiple
			virtual domains that can be assigned to different listeners
			(servers) or new connections (clients). Each TLS module that uses
			this management module should assign itself to one or more domains.


A script example which details this module's usage can be found in
		[tls example](#opensips_with_tls_script_example).


### Dependencies of external libraries


OpenSIPS TLS v1.0 support requires the following packages:


- *openssl* or
					*libssl* >= 0.9.6
- *openssl-dev* or
					*libssl-dev*


OpenSIPS TLS v1.1/1.2 support requires the following packages:


- *openssl* or
					*libssl* >= 1.0.1e
- *openssl-dev* or
					*libssl-dev*


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


#### tls_list


List all domains information.


#### tls_reload


Reloads information from the database.


### Exported Parameters


All these parameters can be used from the opensips.cfg file,
		to configure the behavior of OpenSIPS-TLS.


#### listen=interface


Not specific to TLS. Allows to specify the protocol
			(udp, tcp, tls), the IP address and the port where the
			listening server will be.


```opensips title="Set listen variable"
...
listen = tls:1.2.3.4:5061
...
				
```


#### tls_method [(string):](string)


Sets the TLS protocol. The first parameter, if set, represents
				the id of the domain. TLS method which can be:


- *TLSv1_2* - means OpenSIPS will
				accept only TLSv1.2 connections (rfc3261 conformant).
- *TLSv1* - means OpenSIPS will
				accept only TLSv1 connections (rfc3261 conformant).
- *SSLv3* - means OpenSIPS will
				accept only SSLv3 connections
- *SSLv2* - means OpenSIPS will
				accept only SSLv2 connections (almost all old clients
				support this).
- *SSLv23* - means OpenSIPS will
				accept any of the above methods, but the initial SSL
				hello must be v2 (in the initial hello all the supported
				protocols are advertised enabling switching to a higher
				and more secure version). The initial v2 hello means it
				will not accept connections from SSLv3 or TLSv1 only
				clients.


*Default value is SSLv23.*


> [!WARNING]
> Best is to use SSLv23, for extended compatibility. Using any
			of the other will restrict the version to just that one
			version. In fact, SSLv2 is disabled in the source code; to
			use it, you need to edit tls/tls_init.c


If you want RFC3261 conformance and all your clients support
			TLSv1 (or you are planning to use encrypted "tunnels" only
			between different OpenSIPS proxies) use TLSv1. If you want to
			support older clients use SSLv23 (in fact most of the
			applications with SSL support use the SSLv23 method).


```opensips title="Set tls_method variable"
...
modparam("tls_mgm", "tls_method", "TLSv1")
modparam("tls_mgm", "tls_method", "dom:TLSv1")
...
				
```


#### certificate [(string):](string)


Public certificate file for OpenSIPS. It will be used as
			server-side certificate for incoming TLS connections, and as
			a client-side certificate for outgoing TLS connections. The first
			parameter, if set, represents the id of the domain.


*Default value is "CFG_DIR/cert.pem".*


```opensips title="Set certificate variable"
...
modparam("tls_mgm", "certificate", "/mycerts/certs/opensips_server_cert.pem")
modparam("tls_mgm", "certificate", "dom:/mycerts/certs/opensips_server_cert.pem")
...
				
```


#### private_key [(string):](string)


Private key of the above certificate. I must be kept in a
			safe place with tight permissions! The first parameter, if set,
			represents the id of the domain.


*Default value is "CFG_DIR/cert.pem".*


```opensips title="Set private_key variable"
...
modparam("tls_mgm", "private_key", "/mycerts/private/prik.pem")
modparam("tls_mgm", "private_key", "dom:/mycerts/private/prik.pem")
...
				
```


#### ca_list [(string):]((string)


List of trusted CAs. The file contains the certificates
			accepted, one after the other. It MUST be a file, not
			a folder. The first parameter, if set, represents the id
			of the domain.


*Default value is "".*


```opensips title="Set ca_list variable"
...
modparam("tls_mgm", "ca_list", "/mycerts/certs/ca_list.pem")
modparam("tls_mgm", "ca_list", "dom:/mycerts/certs/ca_list.pem")
...
				
```


#### ca_dir [(string):](string)


Directory storing trusted CAs. The path contains the
			certificates accepted, each as hash which is linked to
			certificate file. The first parameter, if set, represents
			the id of the domain.


*Default value is "".*


```opensips title="Set ca_dir variable"
...
modparam("tls_mgm", "ca_dir", "/mycerts/certs")
modparam("tls_mgm", "ca_dir", "dom:/mycerts/certs")
...
				
```


#### ciphers_list [(string):](string)


You can specify the list of algorithms for authentication
			and encryption that you allow. The first parameter, if set,
			represents the id of the domain. To obtain a list of ciphers
			and then choose, use the openssl application:


- openssl ciphers 'ALL:eNULL:!LOW:!EXPORT'


> [!WARNING]
> Do not use the NULL algorithms (no encryption) ... only for testing!!!


*It defaults to the OpenSSL default ciphers.*


```opensips title="Set ciphers_list variable"
...
modparam("tls_mgm", "ciphers_list", "NULL")
modparam("tls_mgm", "ciphers_list", "dom:NULL")
...
				
```


#### dh_params [(string):](string)


You can specify a file which contains Diffie-Hellman
			parameters as a PEM-file. This is needed if you would like
			to specify ciphers including Diffie-Hellman mode. The first
			parameter, if set, represents the id of the domain.


*It defaults to not set a dh param file.*


```opensips title="Set dh_params variable"
...
modparam("tls_mgm", "dh_params", "/etc/pki/CA/dh1024.pem")
modparam("tls_mgm", "dh_params", "dom:/etc/pki/CA/dh1024.pem")
...
				
```


#### ec_curve[(string):](string)


You can specify an elliptic curve which should be used for
			ciphers which demand an elliptic curve. The first parameter,
			if set, represents the id of the domain.


It's usable only if TLS v1.1/1.2 support was compiled.
			A list of curves which can be used you can get by


```bash
				openssl ecparam -list_curves
			
```


*It defaults to not set a elliptic curve.*


#### verify_cert [(string):](string) and require_cert[(string):](string)


Technically, verify_cert activates SSL_VERIFY_PEER in the
			ssl_context. 'require_cert' does the same with
			SSL_VERIFY_FAIL_IF_NO_PEER_CERT, which is only possible if
			SSL_VERIFY_PEER is also turned on. Since version 2.1, these parameters
			act have been reduced to only one. They act both on client side and
			server side if no domain specified, elseway they act on a specific domain,
			depending on the first parameter.


These two parameters are used for incoming TLS connections, where
			OpenSIPS acts as server.


It's usable only if TLS support was compiled.


*Default value for both is 1.*


```opensips title="Set verify_cert & require_cert variable"
...
# turn on the strictest and strongest authentication possible
modparam("tls_mgm", "require_cert", "1")
modparam("tls_mgm", "require_cert", "1:1")
modparam("tls_mgm", "verify_cert", "0")
modparam("tls_mgm", "verify_cert", "1:1")
...
				
```


#### tls_handshake_timeout (integer)


Sets the timeout (in milliseconds) for the handshake sequence to complete.
				It may be necessary to increase this value when using a CPU intensive cipher
				for the connection to allow time for keys to be generated and processed.


The timeout is invoked during acceptance of a new connection (inbound) and
				during the wait period when a new session is being initiated (outbound).


*Default value is 100.*


```opensips title="Set tls_handshake_timeout variable"
...
modparam("tls_mgm", "tls_handshake_timeout", 200) # number of milliseconds
...
				
```


#### tls_send_timeout (integer)


Sets the timeout (in milliseconds) for the send operations to complete


The send timeout is invoked for all TLS write operations, excluding
				the handshake process (see: tls_handshake_timeout)


*Default value is 100.*


```opensips title="Set tls_send_timeout variable"
...
modparam("tls_mgm", "tls_send_timeout", 200) # number of milliseconds
...
				
```


#### client_domain_avp (integer)


This sets the interger AVP used for name based TLS server domains (please see
			tls_client_domain for more details). Setting the value to 0 disables name based
			TLS client domains.


It's usable only if TLS support was compiled.


*Default value is 0.*


```opensips title="Set client_domain_avp variable"
...
modparam("tls_mgm", "client_domain_avp", "400")
...
				
```


#### db_mode (integer)


When db_mode is enabled (1), this module cannot accept new domains
                        configuration from the script.


Default value is 0. (not enabled)


```opensips title="Usage of db_mode block"
modparam("tls_mgm", "db_mode", 1)
                                
```


#### db_url (string)


The database url. It cannot be NULL.


```opensips title="Usage of db_url block"
modparam("tls_mgm", "db_url", "mysql://root:admin@localhost/opensips")
                                
```


#### db_table (string)


Sets the database table name.


Default value is "tls_mgm".


```opensips title="Usage of db_table block"
modparam("tls_mgm", "db_table", "tls_mgm")
                                
```


#### id_col (string)


Sets the id column name.


Default value is "id".


```opensips title="Usage of id_col block"
modparam("tls_mgm", "id_col", "id")
                                
```


#### address_col (string)


Sets the address column name.


Default value is "address".


```opensips title="Usage of address_col block"
modparam("tls_mgm", "address_col", "addr")
                                
```


#### address_col (string)


Sets the address column name.


Default value is "address".


```opensips title="Usage of address_col block"
modparam("tls_mgm", "address_col", "addr")
                                
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


#### server_domain, client_domain (string)


If you only run one domain, the main one is enough. If you
			are running several TLS servers (that is, you have more than
			one listen=tls:ip:port entry in the config file), you can
			specify some parameters for each of them separately (not all
			the above).


The wording 'TLS domain' means that this TLS connection will have different
			parameters than another TLS connection (from another TLS domain). Thus, TLS
			domains must are not directly related to different SIP domains, although they
			are often used in common. Depending on the direction of the TLS handshake, a
			TLS domain is called 'client domain' (=outgouing TLS connection) or 'server domain'
			(= incoming TLS connection).


For example, TLS domains can be used in virtual hosting scenarios with TLS.
			OpenSIPS offers SIP service for multiple domains, e.g. atlanta.com and biloxi.com. Altough
			both domains will be hosted a single SIP proxy, the SIP proxy needs 2 certificates: One
			for atlanta.com and one for biloxi.com. For incoming TLS connections, the SIP proxy
			has to present the respective certificate during the TLS handshake. As the SIP proxy
			does not have received a SIP message yet (this is done after the TLS handshake), the SIP
			proxy can not retrieve the target domain (which will be usually retrieved from the domain in
			the request URI). Thus, distinction for these domains must be done by using multiple sockets.
			The socket on which the TLS connection is received, identifies the respective domain. Thus
			the SIP proxy is able to present the proper certificate.


For outgoing TLS connections, the SIP proxy usually has to provide a client certificate. In
			this scenario, socket based distinction is not possible as there is no dedicated outgoing socket.
			Thus, the certificate selection (selection of the proper TLS client domain) will be name based.
			For this purpose, TLS client domains can be associated with a name (e.g. the domain can be
			used as name). If the SIP proxy establishes a new outgoing TLS connection, it checks
			for the TLS client domain AVP (parameter client_domain_avp). If this AVP is set (e.g.
			in OpenSIPS.cfg), OpenSIPS searches for a TLS client domain with the same name and uses
			the certificates defined in the respective tls_client_domain section.


TLS client domains can also be socket based. If name based domains are disabled or no
			name based AVP is found, OpenSIPS searches for socket based TLS client domains. In this case
			the mapping between to the TLS client domain is done based on the destination socket of the
			underlying outgoing TCP connection.


Note: If there is already an existing TLS connection to the remote target, it will be reused
			wether the TLS client domain AVP matches or not.


NOTE: Make sure to also configure OpenSIPS to listen on the specified
			IP:port.


NOTE: Except tls_handshake_timeout and tls_send_timeout all TLS parameters can be set
			per TLS domain. If a parameter is not explicit set, the default value will be used.


It's usable only if TLS support was compiled.


```opensips title="Usage of tls_client_domain and tls_server_domain block"
...
listen=tls:IP_2:port2
listen=tls:IP_3:port3
...
# set the TLS client domain AVP
modparam("proto_tls", "client_domain_avp", "400")
...

# 'atlanta' server domain
modparam("tls_mgm", "server_domain", "1=IP_2:port2")

modparam("tls_mgm", "certificate", "1:/certs/atlanta.com/cert.pem")
modparam("tls_mgm", "private_key", "1:/certs/atlanta.com/privkey.pem")
modparam("tls_mgm", "ca_list", "1:/certs/wellknownCAs")
modparam("tls_mgm", "tls_method", "1:tlsv1")
modparam("tls_mgm", "verify_cert", "1:1")
modparam("tls_mgm", "require_cert", "1:1")

#'biloxy' server domain

modparam("tls_mgm", "server_domain", "2=IP_3:port3")

modparam("tls_mgm", "certificate", "2:/certs/biloxy.com/cert.pem")
modparam("tls_mgm", "private_key", "2:/certs/biloxy.com/privkey.pem")
modparam("tls_mgm", "ca_list", "2:/certs/wellknownCAs")
modparam("tls_mgm", "tls_method", "2:tlsv1")
modparam("tls_mgm", "verify_cert", "2:1")
modparam("tls_mgm", "require_cert", "2:1")

# 'atlanta' client domain
modparam("tls_mgm", "client_domain", "3=IP_2:port2")

modparam("tls_mgm", "certificate", "3:/certs/atlanta.com/cert.pem")
modparam("tls_mgm", "private_key", "3:/certs/atlanta.com/privkey.pem")
modparam("tls_mgm", "ca_list", "3:/certs/wellknownCAs")
modparam("tls_mgm", "tls_method", "3:tlsv1")
modparam("tls_mgm", "verify_cert", "3:1")
modparam("tls_mgm", "require_cert", "3:1")

#'biloxy' client domain
modparam("tls_mgm", "client_domain", "4=IP_3:port3")

modparam("tls_mgm", "certificate", "4:/certs/biloxy.com/cert.pem")
modparam("tls_mgm", "private_key", "4:/certs/biloxy.com/privkey.pem")
modparam("tls_mgm", "ca_list", "4:/certs/wellknownCAs")
modparam("tls_mgm", "tls_method", "4:tlsv1")
modparam("tls_mgm", "verify_cert", "4:1")
modparam("tls_mgm", "require_cert", "4:1")




# socket based TLS server domains (for TLS based downstream from GW provider)
modparam("tls_mgm", "client_domain", "5=IP_5:port5")

modparam("tls_mgm", "certificate", "5:/certs/atlanta.com/cert.pem")
modparam("tls_mgm", "private_key", "5:/certs/atlanta.com/privkey.pem")
modparam("tls_mgm", "ca_list", "5:/certs/wellknownCAs")
modparam("tls_mgm", "tls_method", "5:tlsv1")
modparam("tls_mgm", "verify_cert", "5:0")

# socket based TLS client domains (for TLS based upstream to GW provider)
# GW IP: 1.2.3.4, GW port: 6677
modparam("tls_mgm", "client_domain", "6=1.2.3.4:6677")

modparam("tls_mgm", "certificate", "6:/certs/biloxy.com/cert.pem")
modparam("tls_mgm", "private_key", "6:/certs/biloxy.com/privkey.pem")
modparam("tls_mgm", "ca_list", "6:/certs/wellknownCAs")
modparam("tls_mgm", "tls_method", "6:tlsv1")
modparam("tls_mgm", "verify_cert", "6:0")

...
route{
...
    # calls to other SIP domains
    # set the proper SSL context (certificate) for local hosted domains
    avp_write("$fd","$avp(fd)");
    t_relay(); # uses NAPTR and SRV lookups
    exit;
...
    # calls to the PSTN GW
    t_relay("tls:1.2.3.4:6677");
    exit;
...
				
```


### Pseudo-Variables


This module exports the follong pseudo-variables:


Some pseudo variables are available for both, the peer'S certificate and
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
  log_stderror=no

  check_via=no
  dns=no
  rev_dns=no
  listen=_your_serv_IP_
  port=5060
  children=4
  fifo="/tmp/opensips_fifo"

  # ------------------ module loading ----------------------------------

  #TLS specific settings
  loadmodule "tls_mgm.so"
  loadmodule "proto_tls.so"

  modparam("tls_mgm", "certificate", "/path/opensipsX_cert.pem")
  modparam("tls_mgm", "private_key", "/path/privkey.pem")
  modparam("tls_mgm", "ca_list", "/path/calist.pem")
  modparam("tls_mgm", "ca_list", "/path/calist.pem")
  modparam("tls_mgm", "require_cert", "1")
  modparam("tls_mgm", "verify_cert", "1")

  alias=_DNS_ALIAS_


  loadmodule "modules/sl/sl.so"
  loadmodule "modules/rr/rr.so"
  loadmodule "modules/maxfwd/maxfwd.so"
  loadmodule "modules/mysql/mysql.so"
  loadmodule "modules/usrloc/usrloc.so"
  loadmodule "modules/registrar/registrar.so"
  loadmodule "modules/tm/tm.so"
  loadmodule "modules/auth/auth.so"
  loadmodule "modules/auth_db/auth_db.so"
  loadmodule "modules/textops/textops.so"
  loadmodule "modules/uri_db/uri_db.so"

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
      sl_send_reply("483","Too Many Hops");
      break;
  };

  # if somene claims to belong to our domain in From,
  # challenge him (skip REGISTERs -- we will chalenge them later)
  if (from_uri==myself) {
      setflag(1);
      if ( (method=="INVITE" || method=="SUBSCRIBE" || method=="MESSAGE")
      &&  !(src_ip==myself) ) {
          if  (!(proxy_authorize( "domA.net", "subscriber" ))) {
              proxy_challenge("domA.net","0"/*no-qop*/);
              break;
          };
          if (!db_check_from()) {
              log("LOG: From Cheating attempt in INVITE\n");
              sl_send_reply("403",
                  "That is ugly -- use From=id next time (OB)");
              break;
          };
      }; # non-REGISTER from other domain
  } else if ( method=="INVITE" && uri!=myself ) {
      sl_send_reply("403", "No relaying");
      break;
  };

  /* ********   do record-route and loose-route ******* */
  if (!(method=="REGISTER"))
      record_route();

  if (loose_route()) {
      append_hf("P-hint: rr-enforced\r\n");
      route(1);
      break;
  };

  /* ******* check for requests targeted out of our domain ******* */
  if ( uri!=myself ) {
      append_hf("P-hint: OUTBOUND\r\n");
      if (uri=~".*@domB.net") {
          t_relay_to_tls("domB.net","5061");
      } else if (uri=~".*@domC.net") {
          t_relay_to_tls("domC.net","5061");
      } else {
          route(1);
      };
      break;
  };

  /* ******* divert to other domain according to prefixes ******* */
  if (method!="REGISTER") {
      if ( uri=~"sip:201") {
          strip(3);
          sethost("domB.net");
          t_relay_to_tls("domB.net","5061");
          break;
      } else if ( uri=~"sip:202" ) {
          strip(3);
          sethost("domC.net");
          t_relay_to_tls("domC.net","5061");
          break;
      };
  };

  /* ************ requests for our domain ********** */
  if (method=="REGISTER") {
      if (!www_authorize( "domA.net", "subscriber" )) {
          # challenge if none or invalid credentials
          www_challenge( "domA.net" /* realm */,
              "0" /* no qop -- some phones can't deal with it */);
          break;
      };
      if (!db_check_to()) {
          log("LOG: To Cheating attempt\n");
          sl_send_reply("403", "That is ugly -- use To=id in REGISTERs");
          break;
      };
      # it is an authenticated request, update Contact database now
      if (!save("location")) {
          sl_reply_error();
      };
      break;
  };

  # native SIP destinations are handled using USRLOC DB
  if (!lookup("location")) {
      # handle user which was not found
      sl_send_reply("404", "Not Found");
      break;
  };

  # remove all present Alert-info headers
  remove_hf("Alert-Info");

  if (method=="INVITE" && (proto==tls || isflagset(1))) {
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


#### os_malloc, os_realloc, os_free


Wrapper functions around the shm_* functions. OpenSSL uses
			non-shared memory to create its objects, thus it would not
			work in OpenSIPS. By creating these wrappers and configuring
			OpenSSL to use them instead of its default memory functions,
			we have all OpenSSL objects in shared memory, ready to use.


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


*doc copyrights:*
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
