#ifndef _DS_BL_H_
#define _DS_BL_H_

#include "../../blacklists.h"

#define DS_BL_MAX_SETS		32

struct ds_bl {
	unsigned int no_sets;
	unsigned int sets[DS_BL_MAX_SETS];
	struct bl_head *bl;
	struct ds_bl *next;
};

int set_ds_bl(modparam_t type, void *val);

int init_ds_bls(void);

void destroy_ds_bls(void);

int populate_ds_bls(void);

#endif /* _DS_BL_H_ */
