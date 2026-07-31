/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 */

#include "db_pi.h"
#include "../mem/mem.h"

struct pi_transport {
	str name;
	pi_transport_cb callback;
	pi_control_cb list_callback;
	pi_control_cb reload_callback;
	void *param;
	struct pi_transport *next;
};

static struct pi_transport *transports;

static int pi_copy_str(str *dst, const str *src)
{
	dst->s = pkg_malloc(src->len + 1);
	if (!dst->s)
		return -1;
	memcpy(dst->s, src->s, src->len);
	dst->s[src->len] = '\0';
	dst->len = src->len;
	return 0;
}

int db_pi_register_transport(const str *name, pi_transport_cb callback,
		pi_control_cb list_callback, pi_control_cb reload_callback, void *param)
{
	struct pi_transport *transport;

	if (!name || !name->s || !name->len || !callback)
		return -1;
	for (transport = transports; transport; transport = transport->next) {
		if (transport->name.len == name->len &&
				!memcmp(transport->name.s, name->s, name->len)) {
			if (transport->callback != callback)
				return -1;
			transport->list_callback = list_callback;
			transport->reload_callback = reload_callback;
			transport->param = param;
			return 0;
		}
	}

	transport = pkg_malloc(sizeof(*transport));
	if (!transport)
		return -1;
	memset(transport, 0, sizeof(*transport));
	if (pi_copy_str(&transport->name, name) < 0) {
		pkg_free(transport);
		return -1;
	}
	transport->callback = callback;
	transport->list_callback = list_callback;
	transport->reload_callback = reload_callback;
	transport->param = param;
	transport->next = transports;
	transports = transport;
	return 0;
}

static mi_response_t *pi_control(const mi_params_t *params,
		struct mi_handler *async_hdl, int reload)
{
	struct pi_transport *transport;
	mi_response_t *response = NULL;

	for (transport = transports; transport; transport = transport->next) {
		pi_control_cb callback = reload ? transport->reload_callback :
				transport->list_callback;
		if (callback) {
			response = callback(params, async_hdl, transport->param);
			if (response)
				return response;
		}
	}
	return init_mi_error(503, MI_SSTR("No PI transport is available"));
}

mi_response_t *w_mi_pi_list(const mi_params_t *params,
		struct mi_handler *async_hdl)
{
	return pi_control(params, async_hdl, 0);
}

mi_response_t *w_mi_pi_reload(const mi_params_t *params,
		struct mi_handler *async_hdl)
{
	return pi_control(params, async_hdl, 1);
}

int db_pi_dispatch(const str *transport_name, const str *method,
		const str *url, void *request_context, str *response)
{
	struct pi_transport *transport;

	if (!transport_name || !method || !url || !response)
		return -1;
	for (transport = transports; transport; transport = transport->next) {
		if (transport->name.len == transport_name->len &&
				!memcmp(transport->name.s, transport_name->s,
						transport_name->len))
			return transport->callback(method, url, request_context,
					response, transport->param);
	}
	return -1;
}
