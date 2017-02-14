#include "../../ip_addr.h"
#include "../../ut.h"
#include "prefix_tree.h"
#include "dr_partitions.h"
#include "dr_replication.h"

str repl_dr_module_name = str_init("drouting");
struct clusterer_binds clusterer_api;

void replicate_dr_gw_status_event(pgw_t *gw, int cluster_id)
{
	if (bin_init(&repl_dr_module_name, REPL_GW_STATUS_UPDATE, BIN_VERSION) != 0) {
		LM_ERR("failed to replicate this event\n");
		return;
	}

	bin_push_int(clusterer_api.get_my_id());

	bin_push_str(&gw->id);
	bin_push_int(gw->flags);

	if (clusterer_api.send_to(cluster_id, PROTO_BIN) < 0) {
		LM_ERR("replicate dr_gw_status send failed\n");
 	}
}

int replicate_gw_status_update(struct head_db * head_db_ref)
{
	static str id;
	int flags;
	pgw_t *gw;

	bin_pop_str(&id);
	bin_pop_int(&flags);

	lock_start_read(head_db_ref->ref_lock);

	gw = get_gw_by_id( (*head_db_ref->rdata)->pgw_tree, &id);
	if (gw && (gw->flags != flags))
	{
		gw->flags = flags;
		lock_stop_read(head_db_ref->ref_lock);
		return 0;
	}

	lock_stop_read(head_db_ref->ref_lock);

	return -1;
}
