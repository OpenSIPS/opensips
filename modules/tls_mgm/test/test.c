/*
 * Unit tests for TLS handshake outcome classification.
 */

#include <tap.h>

#include "../tls_helper.h"

int tls_mgm_test_hs_result(unsigned int proto_flags, int ret);

void mod_tests(void)
{
	ok(tls_mgm_test_hs_result(F_TLS_DO_ACCEPT, 0) == 0,
		"tls-mgm-accept-pending");
	ok(tls_mgm_test_hs_result(F_TLS_DO_CONNECT, 0) == 0,
		"tls-mgm-connect-pending");
	ok(tls_mgm_test_hs_result(F_TLS_DO_ACCEPT, -1) < 0,
		"tls-mgm-active-accept-failure");
	ok(tls_mgm_test_hs_result(F_TLS_DO_CONNECT, -1) < 0,
		"tls-mgm-active-connect-failure");

	/*
	 * A cleared state flag means the cryptographic handshake completed.
	 * A later wrapper failure must not rewrite that outcome as handshake
	 * failure (wolfSSL write-SSL duplication is one such path).
	 */
	ok(tls_mgm_test_hs_result(0, 1) > 0,
		"tls-mgm-cleared-flags-success");
	ok(tls_mgm_test_hs_result(0, -1) > 0,
		"tls-mgm-post-handshake-error-still-handshake-success");
}
