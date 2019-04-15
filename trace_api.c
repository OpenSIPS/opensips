/*
 * Copyright (C) 2016 - OpenSIPS Solutions
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
 *  2016-09-02  first version (Ionut Ionita)
 */
#include "trace_api.h"
#include "dprint.h"

register_trace_type_f register_trace_type=NULL;
check_is_traced_f check_is_traced=NULL;
get_next_destination_f get_next_destination=NULL;
sip_context_trace_f sip_context_trace=NULL;

trace_proto_t* global_trace_api=NULL;

int trace_prot_bind(char* module_name, trace_proto_t* prot)
{
	trace_bind_api_f bind_f;

	if (!module_name || !prot) {
		LM_ERR("null argument\n");
		return -1;
	}

	bind_f = (trace_bind_api_f) find_mod_export(module_name,
						"trace_bind_api", 0);

	if (bind_f) {
		LM_DBG("using trace bind api for %s\n", module_name);

		if (bind_f(prot)) {
			LM_ERR("failed to bind proto for module %s\n", module_name);
			return -1;
		}
	} else {
		LM_DBG("<%s> has no bind api function\n", module_name);
		return -1;
	}

	return 0;
}
