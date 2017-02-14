#include "../../ut.h"
#include "../../rw_locking.h"
#include "lb_data.h"
#include "lb_bl.h"
#include "lb_replication.h"

str repl_lb_module_name = str_init("load_balancer");
struct clusterer_binds clusterer_api;

void replicate_lb_status(struct lb_dst *dst)
{
	if (bin_init(&repl_lb_module_name, REPL_LB_STATUS_UPDATE, BIN_VERSION) != 0) {
		LM_ERR("failed to replicate this event\n");
		return;
	}

	bin_push_int(clusterer_api.get_my_id());
	bin_push_int(dst->group);
	bin_push_str(&dst->uri);
	bin_push_int(dst->flags);

	if (clusterer_api.send_to(lb_status_replicate_cluster, PROTO_BIN) < 0) {
		LM_ERR("replicate lb_status send failed\n");
 	}
}

int replicate_lb_status_update(struct lb_data *data)
{
	struct lb_dst *dst;
	unsigned int group, flags;
	str uri;
	bin_pop_int(&group);
	bin_pop_str(&uri);
	bin_pop_int(&flags);

	for( dst=data->dsts; dst; dst=dst->next )
	{
		if((dst->group == group) && (strncmp(dst->uri.s, uri.s, dst->uri.len) == 0))
		{
			if (dst->flags != flags)
			{
				dst->flags = flags;
				return 0;
			}
		}
	}

	return -1;
}
