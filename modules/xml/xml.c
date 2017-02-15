/*
 * Copyright (C) 2017 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2017-02-15 initial version (rvlad-patrascu)
 */


#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../pvar.h"

#include <libxml/parser.h>
#include <libxml/tree.h>


static int mod_init(void);
static int child_init(int);
static void mod_destroy(void);

/* PV functions */
static int pv_set_xml(struct sip_msg*,  pv_param_t*, int, pv_value_t*);
static int pv_get_xml(struct sip_msg*,  pv_param_t*, pv_value_t*);
static int pv_parse_xml_name(pv_spec_p , str *);


static pv_export_t mod_items[] = {
	{ {"xml", sizeof("xml")-1}, PVT_XML, pv_get_xml, pv_set_xml,
		pv_parse_xml_name, 0, 0, 0},
	  { {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

struct module_exports exports= {
	"xml",        	 /* module's name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	NULL,            /* exported functions */
	0,               /* exported async functions */
	0,      		 /* param exports */
	0,       		 /* exported statistics */
	0,         		 /* exported MI functions */
	mod_items,       /* exported pseudo-variables */
	0,               /* extra processes */
	mod_init,        /* module initialization function */
	0,               /* reply processing function */
	mod_destroy,
	child_init       /* per-child init function */
};

int pv_parse_xml_name(pv_spec_p sp, str *in)
{
	return 0;
}

int pv_get_xml(struct sip_msg* msg,  pv_param_t* pvp, pv_value_t* val)
{
	return pv_get_null( msg, pvp, val);
}

int pv_set_xml(struct sip_msg* msg,  pv_param_t* pvp, int flag, pv_value_t* val)
{
	return -1;
}

int mod_init(void)
{
	return 0;
}

int child_init(int rank)
{
	return 0;
}

void mod_destroy(void)
{
	return;
}

