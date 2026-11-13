/*
 * clusterer_controller - the controller's part of the module exports, as
 * clusterer_mod.c lists them
 *
 * Copyright (C) 2026 Yury Kirsanov
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 */

#ifndef CL_CTR_MOD_H
#define CL_CTR_MOD_H

#include "../../sr_module.h"
#include "../../pvar.h"
#include "../../mi/mi.h"

/* parameters */
extern char *my_ip;
extern char *my_interface;
extern int   query_time;
extern char *password;
extern int   manage_shtags;
extern int   master_stickiness;
extern int   release_tag_when_isolated;
extern char *on_config_mismatch_s;
int cl_ctr_add_cluster_param(modparam_t type, void *val);

/* one worker process per controller cluster */
extern proc_export_t cl_ctr_procs[];

/* called from clusterer's mod_init, child_init and destroy; without a
 * 'cluster' modparam the controller does nothing */
int cl_ctr_mod_init(void);
int cl_ctr_child_init(int rank);
void cl_ctr_mod_destroy(void);

/* script functions */
int w_cl_ctr_set_maintenance(struct sip_msg *msg, int *cid, str *state);
int w_cl_ctr_node_is_master(struct sip_msg *msg, int *cid, int *nid);
int w_cl_ctr_node_present(struct sip_msg *msg, int *cid, int *nid);
int w_cl_ctr_get_node_role(struct sip_msg *msg, int *cid, int *nid,
		pv_spec_t *out);
int w_cl_ctr_get_node_maint(struct sip_msg *msg, int *cid, int *nid,
		pv_spec_t *out);
int w_cl_ctr_get_node_ip(struct sip_msg *msg, int *cid, int *nid,
		pv_spec_t *out);

/* read-only $cl_ctr_* variables */
int cl_ctr_pv_parse_cluster(pv_spec_p sp, const str *in);
int cl_ctr_pv_role(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int cl_ctr_pv_is_master(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int cl_ctr_pv_master_ip(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int cl_ctr_pv_backup_ip(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int cl_ctr_pv_node_id(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int cl_ctr_pv_my_ip(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int cl_ctr_pv_members(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int cl_ctr_pv_shtag_mode(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int cl_ctr_pv_forced_node(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int cl_ctr_pv_maint(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);

/* MI */
mi_response_t *mi_cl_ctr_members(const mi_params_t *params,
		struct mi_handler *hdl);
mi_response_t *mi_cl_ctr_node_info(const mi_params_t *params,
		struct mi_handler *hdl);
mi_response_t *mi_cl_ctr_config(const mi_params_t *params,
		struct mi_handler *hdl);
mi_response_t *mi_cl_ctr_maintenance(const mi_params_t *params,
		struct mi_handler *hdl);
mi_response_t *mi_cl_ctr_maintenance_node(const mi_params_t *params,
		struct mi_handler *hdl);
mi_response_t *mi_cl_ctr_shtag_force(const mi_params_t *params,
		struct mi_handler *hdl);
mi_response_t *mi_cl_ctr_shtag_auto(const mi_params_t *params,
		struct mi_handler *hdl);

#endif /* CL_CTR_MOD_H */
