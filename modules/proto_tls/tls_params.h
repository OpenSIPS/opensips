/*
 * Copyright (C) 2015 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * History:
 * -------
 *  2015-02-18  first version (bogdan)
 */


#ifndef _MOD_PROTO_TLS_tls_params_h
#define _MOD_PROTO_TLS_tls_params_h

#include "../../sr_module.h"

int tlsp_add_srv_domain(modparam_t type, void *val);

int tlsp_add_cli_domain(modparam_t type, void *val);

int tlsp_set_method(modparam_t type, void *val);

int tlsp_set_verify(modparam_t type, void *val);

int tlsp_set_require(modparam_t type, void *val);

int tlsp_set_certificate(modparam_t type, void *val);

int tlsp_set_pk(modparam_t type, void *val);

int tlsp_set_calist(modparam_t type, void *val);

int tlsp_set_cadir(modparam_t type, void *val);

int tlsp_set_cplist(modparam_t type, void *val);

int tlsp_set_dhparams(modparam_t type, void *val);

int tlsp_set_eccurve(modparam_t type, void *val);

#endif

