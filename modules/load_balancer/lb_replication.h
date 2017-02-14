#ifndef _LB_REPLICATION_H_
#define _LB_REPLICATION_H_

#include "../../sr_module.h"
#include "../../bin_interface.h"
#include "../clusterer/api.h"

#define BIN_VERSION 1

#define REPL_LB_STATUS_UPDATE 1

extern str repl_lb_module_name;
extern struct clusterer_binds clusterer_api;
extern int lb_status_replicate_cluster;

void replicate_lb_status(struct lb_dst *dst);
int replicate_lb_status_update(struct lb_data *data);

#endif
