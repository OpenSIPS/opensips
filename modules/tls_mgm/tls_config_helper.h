/* 
 * File:   tls_config_helper.h
 * Author: cristi
 *
 * Created on September 3, 2015, 6:54 PM
 */

#ifndef TLS_CONFIG_HELPER_H
#define	TLS_CONFIG_HELPER_H

enum tls_method {
	TLS_METHOD_UNSPEC = 0,
	TLS_USE_TLSv1_cli,
	TLS_USE_TLSv1_srv,
	TLS_USE_TLSv1,
	TLS_USE_SSLv23_cli,
	TLS_USE_SSLv23_srv,
	TLS_USE_SSLv23,
	TLS_USE_TLSv1_2_cli,
	TLS_USE_TLSv1_2_srv,
	TLS_USE_TLSv1_2
};

#endif	/* TLS_CONFIG_HELPER_H */

