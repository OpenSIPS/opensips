/*
 * Lightweight helpers for asynchronous OpenSSL handshakes.
 *
 * These helpers intentionally do not depend on OpenSSL, so the deadline and
 * readiness logic can be regression-tested without a TLS server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _OPENSSL_ASYNC_H_
#define _OPENSSL_ASYNC_H_

#include <poll.h>

/* Both arguments are in microseconds, relative to the same start time. */
static inline unsigned int openssl_async_timeout_left(unsigned int timeout_us,
		unsigned int elapsed_us)
{
	if (elapsed_us >= timeout_us)
		return 0;

	return timeout_us - elapsed_us;
}

/* Wait only for the readiness requested by OpenSSL's WANT_* result. */
static inline short openssl_async_wait_events(int want_read)
{
	return want_read ? POLLIN : POLLOUT;
}

#endif /* _OPENSSL_ASYNC_H_ */
