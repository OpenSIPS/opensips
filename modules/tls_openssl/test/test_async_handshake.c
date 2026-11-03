/*
 * Standalone regression tests for OpenSSL async handshake timeout / polling.
 *
 * Build from modules/tls_openssl:
 *   cc -std=c99 -Wall -Wextra -Werror -pedantic \
 *      test/test_async_handshake.c -o /tmp/test_openssl_async
 *   /tmp/test_openssl_async
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <assert.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../openssl_async.h"

static void test_deadline(void)
{
	const unsigned int deadline_us = 1000000U;
	unsigned int remaining;

	assert(openssl_async_timeout_left(deadline_us, 0U) == 1000000U);
	assert(openssl_async_timeout_left(deadline_us, 200000U) == 800000U);
	assert(openssl_async_timeout_left(deadline_us, 500000U) == 500000U);

	/* Regression: the old code timed out at 600 ms after multiple retries. */
	remaining = openssl_async_timeout_left(deadline_us, 600000U);
	assert(remaining == 400000U);
	assert(remaining > 0);

	assert(openssl_async_timeout_left(deadline_us, 999999U) == 1U);
	assert(openssl_async_timeout_left(deadline_us, 1000000U) == 0U);
	assert(openssl_async_timeout_left(deadline_us, 1200000U) == 0U);
	assert(openssl_async_timeout_left(0U, 0U) == 0U);
}

static void test_poll_direction(void)
{
	int sockets[2];
	struct pollfd pfd;
	char byte = 'x';

	assert(openssl_async_wait_events(1) == POLLIN);
	assert(openssl_async_wait_events(0) == POLLOUT);

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);

	/* Demonstrate the old bug: POLLIN | POLLOUT wakes immediately. */
	pfd.fd = sockets[0];
	pfd.events = POLLIN | POLLOUT;
	pfd.revents = 0;
	assert(poll(&pfd, 1, 0) == 1);
	assert((pfd.revents & POLLOUT) != 0);

	/* Socket is writable, but WANT_READ must NOT wake on POLLOUT. */
	pfd.fd = sockets[0];
	pfd.events = openssl_async_wait_events(1);
	pfd.revents = 0;
	assert(poll(&pfd, 1, 0) == 0);

	/* The same descriptor becomes readable once its peer sends data. */
	assert(write(sockets[1], &byte, 1) == 1);
	pfd.revents = 0;
	assert(poll(&pfd, 1, 0) == 1);
	assert((pfd.revents & POLLIN) != 0);

	/* WANT_WRITE polls for writability, not readability. */
	pfd.events = openssl_async_wait_events(0);
	pfd.revents = 0;
	assert(poll(&pfd, 1, 0) == 1);
	assert((pfd.revents & POLLOUT) != 0);

	assert(close(sockets[0]) == 0);
	assert(close(sockets[1]) == 0);
}

int main(void)
{
	test_deadline();
	test_poll_direction();
	puts("OpenSSL async handshake regression tests: PASS");
	return 0;
}
