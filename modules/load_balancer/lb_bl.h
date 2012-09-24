#ifndef _LB_BL_H_
#define _LB_BL_H_

#include "../../blacklists.h"
#include "lb_data.h"
#include "../../parser/parse_uri.h"
#include "../../resolve.h"

#define LB_BL_MAX_SETS		32

extern struct lb_data **curr_data;

struct lb_bl {
	unsigned int no_groups;
	unsigned int groups[LB_BL_MAX_SETS];
	struct bl_head *bl;
	struct lb_bl *next;
};

int set_lb_bl(modparam_t type, void *val);

int init_lb_bls(void);

void destroy_lb_bls(void);

int populate_lb_bls(struct lb_dst *dst);

#endif /* _LB_BL_H_ */

