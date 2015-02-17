#ifndef _TOPOH_LOGIC_H
#define _TOPOH_LOGIC_H

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../pvar.h"
#include "../../mem/mem.h"
#include "../../mod_fix.h"
#include "../../data_lump.h"
#include "../../parser/contact/parse_contact.h"
#include "../tm/tm_load.h"
#include "../tm/t_hooks.h"
#include "../rr/api.h"
#include "../dialog/dlg_load.h"

int topo_parse_passed_ct_params(str *params);
int topo_parse_passed_hdr_ct_params(str *params);
int topology_hiding(struct sip_msg *req,int extra_flags);
int topo_callid_pre_raw(str *data, struct sip_msg* req);
int topo_callid_post_raw(str *data, struct sip_msg* req);
int topology_hiding_match(struct sip_msg *req);

#endif
