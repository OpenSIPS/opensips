/*
 * PI framework database support
 *
 * Copyright (C) 2012 VoIP Embedded, Inc.
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
 *  2012-03-19  initial version (Ovidiu Sas)
 */

#include <stdio.h>
#include <stdlib.h>

#include "db.h"
#include "pi_framework.h"



int pi_connect_db(pi_framework_t *framework_data, int index)
{
	pi_db_url_t *pi_db_urls = framework_data->pi_db_urls;

	if (*pi_db_urls[index].db_handle) {
		LM_CRIT("BUG - db connection found already open\n");
		return -1;
	}
	if ((*pi_db_urls[index].db_handle =
		pi_db_urls[index].dbf.init(&pi_db_urls[index].db_url)) == NULL) {
		return -1;
	}
	return 0;
}

int pi_use_table(pi_db_table_t *db_table)
{
	pi_db_url_t *db_url;

	if(db_table==NULL){
		LM_ERR("null db_table handler\n");
		return -1;
	}
	if(db_table->db_url==NULL){
		LM_ERR("null db_url for table [%s]\n", db_table->name.s);
		return -1;
	}
	db_url = db_table->db_url;
	if(*db_url->db_handle==NULL){
		LM_ERR("null db handle for table [%s]\n", db_table->name.s);
		return -1;
	}
	db_table->db_url->dbf.use_table(*db_table->db_url->db_handle,
						&db_table->name);
	return 0;
}

int pi_init_db(pi_framework_t *framework_data, int index)
{
	pi_db_url_t *pi_db_urls = framework_data->pi_db_urls;

	if (db_bind_mod(&pi_db_urls[index].db_url,
		&pi_db_urls[index].dbf) < 0) {
		LM_ERR("Unable to bind to a database driver\n");
		return -1;
	}
	if (pi_connect_db(framework_data, index)!=0){
		LM_ERR("unable to connect to the database\n");
		return -1;
	}

	pi_db_urls[index].dbf.close(*pi_db_urls[index].db_handle);
	*pi_db_urls[index].db_handle = NULL;

	return 0;
}


void pi_destroy_db(pi_framework_t *framework_data)
{
	int i;
	pi_db_url_t *pi_db_urls = framework_data->pi_db_urls;

	/* close the DB connections */
	for(i=0;i<framework_data->pi_db_urls_size;i++){
		if (*pi_db_urls[i].db_handle) {
			pi_db_urls[i].dbf.close(*pi_db_urls[i].db_handle);
			*pi_db_urls[i].db_handle = NULL;
		}
	}
}
