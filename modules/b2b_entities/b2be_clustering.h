/*
 * Copyright (C) 2020 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 *
 */

#ifndef _B2BE_CLUSTERING_H_
#define _B2BE_CLUSTERING_H_

#include "../clusterer/api.h"
#include "dlg.h"

#define B2BE_BIN_VERSION 1

#define REPL_ENTITY_CREATE 1
#define REPL_ENTITY_UPDATE 2
#define REPL_ENTITY_PARAM_UPDATE 3
#define REPL_ENTITY_ACK 4
#define REPL_ENTITY_DELETE 5

extern struct clusterer_binds cl_api;
extern int b2be_cluster;
extern str entities_repl_cap;

int b2be_init_clustering(void);
void replicate_entity_create(b2b_dlg_t *dlg, int etype, unsigned int hash_index,
	bin_packet_t *storage);
void replicate_entity_update(b2b_dlg_t *dlg, int etype, unsigned int hash_index,
	str *b2bl_param, int event_type, bin_packet_t *storage);
void replicate_entity_delete(b2b_dlg_t *dlg, int etype, unsigned int hash_index,
	bin_packet_t *storage);

#endif /* _B2BE_CLUSTERING_H_ */
