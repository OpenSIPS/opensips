/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 */

#ifndef _DB_PI_H_
#define _DB_PI_H_

#include "../mi/mi.h"

/* A transport is independent of the wire protocol.  request_context is
 * owned by the transport and response is filled by the callback. */
typedef int (*pi_transport_cb)(const str *method, const str *url,
		void *request_context, str *response, void *param);

typedef mi_response_t *(*pi_control_cb)(const mi_params_t *params,
		struct mi_handler *async_hdl, void *param);

int db_pi_register_transport(const str *name, pi_transport_cb callback,
		pi_control_cb list_callback, pi_control_cb reload_callback,
		void *param);
int db_pi_dispatch(const str *transport, const str *method, const str *url,
		void *request_context, str *response);
mi_response_t *w_mi_pi_list(const mi_params_t *params,
		struct mi_handler *async_hdl);
mi_response_t *w_mi_pi_reload(const mi_params_t *params,
		struct mi_handler *async_hdl);

#endif /* _DB_PI_H_ */
