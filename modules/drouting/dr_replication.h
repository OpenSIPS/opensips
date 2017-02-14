#ifndef _DROUTING_REPLICATION_H_
#define _DROUTING_REPLICATION_H_

#include "../../sr_module.h"
#include "../../bin_interface.h"
#include "../clusterer/api.h"

#define BIN_VERSION 1

#define REPL_GW_STATUS_UPDATE 1

extern str repl_dr_module_name;
extern struct clusterer_binds clusterer_api;

void replicate_dr_gw_status_event(pgw_t *gw, int cluster_id);
int replicate_gw_status_update(struct head_db * head_db_ref);

#endif
