/*
 * Copyright (C) 2022 OpenSIPS Solutions
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
 */

mi_response_t *mi_b2b_bridge(const mi_params_t *params,
	int entity_no, str *prov_media);
int b2b_script_bridge(struct sip_msg *msg, str *br_ent1_str, str *br_ent2_str,
	str *provmedia_uri, struct b2b_bridge_params *params);
int b2b_script_bridge_retry(struct sip_msg *msg, str *new_ent_str);

int send_bridge_notify(b2bl_entity_id_t *entity, unsigned int hash_index,
	struct sip_msg* msg);
int process_bridge_negreply(b2bl_tuple_t* tuple,
	unsigned int hash_index, b2bl_entity_id_t* entity, struct sip_msg* msg);
int process_bridge_bye(struct sip_msg* msg,  b2bl_tuple_t* tuple,
	unsigned int hash_index, b2bl_entity_id_t* entity);
int process_bridge_200OK(struct sip_msg* msg, str* extra_headers,
	str* body, b2bl_tuple_t* tuple, unsigned int hash_index,
	b2bl_entity_id_t* entity);

int b2bl_bridge(struct sip_msg* msg, b2bl_tuple_t* tuple,
	unsigned hash_index, b2bl_entity_id_t *old_entity,
	struct b2bl_new_entity *new_br_ent[2], str *provmedia_uri, int lifetime);
