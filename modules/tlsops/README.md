---
title: "tlsops Module"
description: "This module implements TLS related functions to use in the routing script, and exports pseudo variables with certificate and TLS parameters."
---

## Admin Guide


### Overview


This module implements TLS related functions to use in the routing script, and exports 
		pseudo variables with certificate and TLS parameters.


### Dependencies


#### OpenSIPS core


OpenSIPS must be compiled with TLS=1.


#### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *openssl (libssl)*.


### Exported Parameters


None!


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


### Debug TLS connections


If you want to debug TLS connections, put the following log 
	statements into your OpenSIPS.cfg.
	This will dump all available TLS pseudo variables.


```opensips title="Example of TLS logging"
xlog("L_INFO","==================== start TLS pseudo variables =================='\n");
xlog("L_INFO","$$tls_version                    = '$tls_version'\n");
xlog("L_INFO","$$tls_description                = '$tls_description'\n");
xlog("L_INFO","$$tls_cipher_info                = '$tls_cipher_info'\n");
xlog("L_INFO","$$tls_cipher_bits                = '$tls_cipher_bits'\n");
xlog("L_INFO","$$tls_peer_subject               = '$tls_peer_subject'\n");
xlog("L_INFO","$$tls_peer_issuer                = '$tls_peer_issuer'\n");
xlog("L_INFO","$$tls_my_subject                 = '$tls_my_subject'\n");
xlog("L_INFO","$$tls_my_issuer                  = '$tls_my_issuer'\n");
xlog("L_INFO","$$tls_peer_version               = '$tls_peer_version'\n");
xlog("L_INFO","$$tls_my_version                 = '$tls_my_version'\n");
xlog("L_INFO","$$tls_peer_serial                = '$tls_peer_serial'\n");
xlog("L_INFO","$$tls_my_serial                  = '$tls_my_serial'\n");
xlog("L_INFO","$$tls_peer_subject_cn            = '$tls_peer_subject_cn'\n");
xlog("L_INFO","$$tls_peer_issuer_cn             = '$tls_peer_issuer_cn'\n");
xlog("L_INFO","$$tls_my_subject_cn              = '$tls_my_subject_cn'\n");
xlog("L_INFO","$$tls_my_issuer_cn               = '$tls_my_issuer_cn'\n");
xlog("L_INFO","$$tls_peer_subject_locality      = '$tls_peer_subject_locality'\n");
xlog("L_INFO","$$tls_peer_issuer_locality       = '$tls_peer_issuer_locality'\n");
xlog("L_INFO","$$tls_my_subject_locality        = '$tls_my_subject_locality'\n");
xlog("L_INFO","$$tls_my_issuer_locality         = '$tls_my_issuer_locality'\n");
xlog("L_INFO","$$tls_peer_subject_country       = '$tls_peer_subject_country'\n");
xlog("L_INFO","$$tls_peer_issuer_country        = '$tls_peer_issuer_country'\n");
xlog("L_INFO","$$tls_my_subject_country         = '$tls_my_subject_country'\n");
xlog("L_INFO","$$tls_my_issuer_country          = '$tls_my_issuer_country'\n");
xlog("L_INFO","$$tls_peer_subject_state         = '$tls_peer_subject_state'\n");
xlog("L_INFO","$$tls_peer_issuer_state          = '$tls_peer_issuer_state'\n");
xlog("L_INFO","$$tls_my_subject_state           = '$tls_my_subject_state'\n");
xlog("L_INFO","$$tls_my_issuer_state            = '$tls_my_issuer_state'\n");
xlog("L_INFO","$$tls_peer_subject_organization  = '$tls_peer_subject_organization'\n");
xlog("L_INFO","$$tls_peer_issuer_organization   = '$tls_peer_issuer_organization'\n");
xlog("L_INFO","$$tls_my_subject_organization    = '$tls_my_subject_organization'\n");
xlog("L_INFO","$$tls_my_issuer_organization     = '$tls_my_issuer_organization'\n");
xlog("L_INFO","$$tls_peer_subject_unit          = '$tls_peer_subject_unit'\n");
xlog("L_INFO","$$tls_peer_issuer_unit           = '$tls_peer_issuer_unit'\n");
xlog("L_INFO","$$tls_my_subject_unit            = '$tls_my_subject_unit'\n");
xlog("L_INFO","$$tls_my_issuer_unit             = '$tls_my_issuer_unit'\n");
xlog("L_INFO","$$tls_peer_san_email             = '$tls_peer_san_email'\n");
xlog("L_INFO","$$tls_my_san_email               = '$tls_my_san_email'\n");
xlog("L_INFO","$$tls_peer_san_hostname          = '$tls_peer_san_hostname'\n");
xlog("L_INFO","$$tls_my_san_hostname            = '$tls_my_san_hostname'\n");
xlog("L_INFO","$$tls_peer_san_uri               = '$tls_peer_san_uri'\n");
xlog("L_INFO","$$tls_my_san_uri                 = '$tls_my_san_uri'\n");
xlog("L_INFO","$$tls_peer_san_ip                = '$tls_peer_san_ip'\n");
xlog("L_INFO","$$tls_my_san_ip                  = '$tls_my_san_ip'\n");
xlog("L_INFO","$$tls_peer_verified              = '$tls_peer_verified'\n");
xlog("L_INFO","$$tls_peer_revoked               = '$tls_peer_revoked'\n");
xlog("L_INFO","$$tls_peer_expired               = '$tls_peer_expired'\n");
xlog("L_INFO","$$tls_peer_selfsigned            = '$tls_peer_selfsigned'\n");
xlog("L_INFO","$$tls_peer_notBefore             = '$tls_peer_notBefore'\n");
xlog("L_INFO","$$tls_peer_notAfter              = '$tls_peer_notAfter'\n");
xlog("L_INFO","==================== end TLS pseudo variables =================='\n");	
```


## Frequently Asked Questions


**Q: What is the difference between the TLS directory and the 
		TLSOPS module directory?**


The code in the TLS directory implements the TLS transport layer. 
			The TLSOPS module implements TLS related functions which 
			can be used in the routing script.


**Q: Where can I find more about OpenSIPS?**


Take a look at [http://www.opensips.org/](http://www.opensips.org/).


**Q: Where can I post a question about this module?**


First at all check if your question was already answered on one of
			our mailing lists:

E-mails regarding any stable OpenSIPS release should be sent to 
			users@lists.opensips.org and e-mails regarding development versions
			should be sent to devel@lists.opensips.org.

If you want to keep the mail private, send it to 
			users@lists.opensips.org.


**Q: How can I report a bug?**


Please follow the guidelines provided at:
			[https://github.com/OpenSIPS/opensips/issues](https://github.com/OpenSIPS/opensips/issues).
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
