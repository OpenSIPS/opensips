---
title: "Identity Module"
description: "This module adds support for SIP Identity (see RFC 4474)."
---

## Admin Guide


### Overview


This module adds support for SIP Identity (see RFC 4474).


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *openssl (libssl)*.


### Exported Parameters


#### privKey (string)


Filename of private RSA-key of authentication service. This file must be in PEM format.


```opensips title="Set privKey parameter"
...
modparam("identity", "privKey", "/etc/openser/privkey.pem")
...
```


#### authCert (string)


Filename of certificate which belongs to `privKey`. This file must be in PEM format.


```opensips title="Set authCert parameter"
...
modparam("identity", "authCert", "/etc/openser/cert.pem")
...
```


#### certUri (string)


URI from which the certificate of the authentication service can be acquired. This string will be placed in the Identity-Info header.


```opensips title="Set certUri parameter"
...
modparam("identity", "certUri", "http://www.myserver.com/cert.pem")
...
```


#### verCert (string)


Path containing certificates for the verifier. Certificates must be in PEM format. The URI in the Identity-Info header field is used to find the corresponding certificate for the request. For this purpose the verifier replaces every character which is not alphanumeric, no "_" and no "." with a "-". A "." at the beginning of the URI is forbidden. If the URI is "http://www.test.com/cert.pem" the verifier will look for the file "http---www.test.com-cert.pem", for example.
		It is also possible to store a whole certificate chain in a file. In this case certificates must be in right order, end certificate first.


```opensips title="Set verCert parameter"
...
modparam("identity", "verCert", "/etc/openser/verCert/")
...
```


#### caList (string)


File containing all trusted (root) certificates for the verifier. Certificates must be in PEM format.


```opensips title="Set caList parameter"
...
modparam("identity", "caList", "/etc/openser/caList.pem")
...
```


#### crlList (string)


File containing certificate revocation lists (crls) for the verifier. Setting this parameter is only necessary if `useCrls` is set to "1".


```opensips title="Set crlList parameter"
...
modparam("identity", "crlList", "/etc/openser/crls.pem")
...
```


#### useCrls (integer)


Switch to decide whether to use revocation lists ("1") or not ("0").


*Default value is "0".*


```opensips title="Set privKey parameter"
...
modparam("identity", "useCrls", 1)
...
```


### Exported Functions


#### authservice()


This function performs the steps of an authentication service. Before you call this function, you have to ensure
		that


- the server is responsible for this request (from URI matches local SIP domain)
- the sender of the request is authorized to claim the identity given in the From header field.


- -3: Date header field does not match validity period of cert. Identity header has not been added.
- -2: message out of time (e.g. message to old), Identity header has not been added.
- -1: An error occurred.
- 1: everything OK, Identity header has been added.


```opensips title="authservice() usage"
...
# CANCEL and ACK cannot be challenged
if (($rm=="CANCEL") || ($rm"ACK"))
{
    route(1); # forward
    exit;
}

# some clients (e.g. Kphone) do not answer, when a BYE is challenged
if ($rm=="BYE")
{
    route(1); # forward
    exit;
}

### Authentication Service ###

# check whether I am authoritative
if($fd!="mysipdomain.de")
{
    route(1); # forward
    exit;
}

if(!proxy_authorize("mysipdomain.de","subscriber"))
{
    proxy_challenge("mysipdomain.de",0);
    exit;
}

if ($au!=$fU)
{
    sl_send_reply(403, "Use From=ID");
    exit;
}
consume_credentials();
        
authservice();
switch($retcode)
{
    case -3:
        xlog("L_DBG" ,"authservice: Date header field does not match validity period of cert\n");
        break;
    case -2:
        xlog("L_DBG" ,"authservice: msg out of time (max. +- 10 minutes allowed)\n");
        break;
    case -1:
        xlog("L_DBG" ,"authservice: ERROR, returnvalue: -1\n");
        break;
    case 1:
        xlog("L_DBG" ,"authservice: everything OK\n");
        break;
    default:
        xlog("L_DBG" ,"unknown returnvalue of authservice\n");
        
}

route(1); #forward with ($retcode=1) or without ($retcode!=1) Identity header
...
```


#### verifier()


This function performs the steps of an verifier. The returned code tells you the result of the verification:


- -438: Signature does not correspond to the message. 438-response should be send.
- -437: Certificate cannot be validated. 437-response should be send.
- -436: Certificate is not available. 436-response should be send.
- -428: Message does not have an Identity header. 428-response should be send.
- -3: Error verifying Date header field.
- -2: Authentication service is not authoritative.
- -1: An unknown error occurred.
- 1: verification OK


```opensips title="verifier() usage"
...
# we have to define the same exceptions as we did for the authentication service
if (($rm=="CANCEL") || ($rm"ACK")) 
{ 
    route(1); # forward
    exit;
}
    
if ($rm=="BYE")
{
    route(1); # forward
    exit;
}
   
verifier();
switch($retcode)
{
    case -438:
        xlog("L_DBG" ,"verifier: returnvalue: -438\n");
        sl_send_reply(438, "Invalid Identity Header");
        exit;
        break;
    case -437:
        xlog("L_DBG" ,"verifier: returnvalue: -437\n");
        sl_send_reply(437, "Unsupported Certificate");
        exit;
        break;
    case -436:
        xlog("L_DBG" ,"verifier: returnvalue: -436\n");
        sl_send_reply(436, "Bad Identity-Info");
        exit;
        break;
    case -428:
        xlog("L_DBG" ,"verifier: returnvalue: -428\n");
        sl_send_reply(428, "Use Identity Header");
        exit;
        break;
    case -3:
        xlog("L_DBG" ,"verifier: error verifying Date header field\n");
        exit;
        break;
    case -2:
        xlog("L_DBG" ,"verifier: authentication service is not authoritative\n");
        exit;
        break;
    case -1:
        xlog("L_DBG" ,"verifier: ERROR, returnvalue: -1\n");
        exit;
        break;
    case 1:
        xlog("L_DBG" ,"verifier: verification OK\n");
        route(1); # forward
        exit;
        break;
    default:
        xlog("L_DBG" ,"unknown returnvalue of verifier\n");
        exit;
}
exit;
...
```


### Known Limitations


- Certificates are not downloaded. They have to be stored locally.
- Call-IDs of valid requests containing an Identity header are not recorded. 
				Hence the verifier does not provide full replay protection.
- Authentication service and verifier use the original request. Changes resulting from message processing in OpenSER script are ignored.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
