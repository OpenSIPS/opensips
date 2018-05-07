#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../timer.h"
#include "../../ut.h"
#include "../../rw_locking.h"
#include "../../db/db.h"
#include "../../mod_fix.h"

/* module functions */
static int mod_init(void);
static int mod_child(int);
static void mod_destroy(void);
static int rate_cacher_load_all_info(void); 
static struct mi_root * mi_get_carrier_price(struct mi_root *cmd_tree, void *param );
static struct mi_root * mi_get_carrier_eu_price(struct mi_root *cmd_tree, void *param );
static struct mi_root * mi_get_bulk_carrier_price(struct mi_root *cmd_tree, void *param );
static struct mi_root * mi_reload_carrier_rate(struct mi_root *cmd_tree, void *param );
static struct mi_root * mi_reload_eu_carrier_rate(struct mi_root *cmd_tree, void *param );
static struct mi_root * mi_add_carrier(struct mi_root *cmd_tree, void *param );
static struct mi_root * mi_delete_carrier(struct mi_root *cmd_tree, void *param );
static struct mi_root * mi_delete_carrier_rate(struct mi_root *cmd_tree, void *param );
static struct mi_root * mi_delete_carrier_eu_rate(struct mi_root *cmd_tree, void *param );

static struct mi_root * mi_get_client_price(struct mi_root *cmd_tree, void *param );
static struct mi_root * mi_get_eu_client_price(struct mi_root *cmd_tree, void *param );
static struct mi_root * mi_get_bulk_client_price(struct mi_root *cmd_tree, void *param );
static struct mi_root * mi_reload_client(struct mi_root *cmd_tree, void *param );
static struct mi_root * mi_reload_eu_client(struct mi_root *cmd_tree, void *param );
static struct mi_root * mi_add_client(struct mi_root *cmd_tree, void *param );
static struct mi_root * mi_delete_client(struct mi_root *cmd_tree, void *param );
static struct mi_root * mi_delete_client_rate(struct mi_root *cmd_tree, void *param );
static struct mi_root * mi_delete_eu_client_rate(struct mi_root *cmd_tree, void *param );

static int fixup_cost_based_routing(void** param, int param_no);
static int script_cost_based_routing(struct sip_msg *msg, char *s_clientid, char *s_isws, char *s_iseu, 
		char *s_carrierlist,char *s_ani,char *s_dnis);


/* db connectors */
static str carriers_db_url = {NULL,0};
static str accounts_db_url = {NULL,0}; 
static str rates_db_url = {NULL,0}; 

static db_con_t *carriers_db_hdl=0;
static db_func_t carriers_dbf;   
static db_con_t *accounts_db_hdl=0;
static db_func_t accounts_dbf;   
static db_con_t *rates_db_hdl=0;
static db_func_t rates_dbf;   

static int rc_reply_avp = -1;
static str rc_reply_avp_spec = str_init("$avp(rc_reply)");

static int rc_profit_margin_avp = -1;
static str rc_profit_margin_spec = str_init("$avp(profit_margin)");

#define rc_fix_avp_definition( _pv_spec, _avp_id, _name) \
        do { \
                _pv_spec.len = strlen(_pv_spec.s); \
                if (pv_parse_spec( &_pv_spec, &avp_spec)==0 \
                || avp_spec.type!=PVT_AVP) { \
                        LM_ERR("malformed or non AVP [%.*s] for %s AVP definition\n",\
                                _pv_spec.len, _pv_spec.s, _name); \
                        return E_CFG; \
                } \
                if( pv_get_avp_name(0, &(avp_spec.pvp), &_avp_id, &dummy )!=0) { \
                        LM_ERR("[%.*s]- invalid AVP definition for %s AVP\n", \
                                _pv_spec.len, _pv_spec.s, _name); \
                        return E_CFG; \
                } \
        } while(0)

/* ratesheet description */

#define PTREE_CHILDREN 10
#define IS_DECIMAL_DIGIT(d) \
	(((d)>='0') && ((d)<= '9'))
			

#define INIT_PTREE_NODE(p, n) \
do {\
        (n) = (ptree_t*)shm_malloc(sizeof(ptree_t));\
        if(NULL == (n)) {\
		LM_ERR("Failed to allocate trie node \n"); \
		return -1;\
	} \
        memset((n), 0, sizeof(ptree_t));\
        (n)->bp=(p);\
}while(0)

typedef struct ptree_node_ {
	struct ratesheet_cell_entry *re;
	struct ptree_ *next;
} ptree_node_t;

typedef struct ptree_ {
	/* backpointer */
	struct ptree_ *bp;
	ptree_node_t ptnode[PTREE_CHILDREN];
} ptree_t;

struct ratesheet_cell_entry {
	str destination;
	double price;
	int minimum;
	int increment;
	int destination_id;
};

struct eu_ratesheet_cell_entry {
	str destination;
	double price;
	int minimum;
	int increment;
	str source_name;
};

struct eu_rate_lookup_rpl {
	struct ratesheet_cell_entry *regular;
	struct eu_ratesheet_cell_entry *ani_based;
};

/* carriers hash */
struct carrier_table{
	unsigned int       size;
	struct carrier_entry   *entries;
};

struct carrier_entry {
	struct carrier_cell *first;
	struct carrier_cell *last;
	rw_lock_t *lock;
};

struct carrier_cell {
	str carrierid;
	unsigned int rateid;
	unsigned int eu_rateid;
	unsigned int eu_type;
	str rate_table;
	str eu_rate_table;
	str rate_currency;
	str eu_rate_currency;
	ptree_t *trie;
	void *eu_ratesheet;
	int reload_pending;
	int eu_reload_pending;
	struct carrier_cell *next;
	struct carrier_cell *prev;
};

/* accounts hash */
struct accounts_table{
	unsigned int       size;
	struct account_entry   *entries;
};

struct account_entry {
	struct account_cell *first;
	struct account_cell *last;
	rw_lock_t *lock;
};

struct account_cell {
	str accountid;
	unsigned int ws_rateid;
	unsigned int rt_rateid;
	unsigned int eu_ws_rateid;
	unsigned int eu_rt_rateid;
	str ws_rate_table;
	str rt_rate_table;
	str eu_ws_rate_table;
	str eu_rt_rate_table;
	str ws_rate_currency;
	str rt_rate_currency;
	str eu_ws_rate_currency;
	str eu_rt_rate_currency;
	unsigned int eu_ws_rate_type;
	unsigned int eu_rt_rate_type;
	ptree_t *ws_trie;
	ptree_t *rt_trie;
	/* below we'll either have a regular trie, for regular EU ratesheets
	or a hash of tries, for the extended EU format */
	void *eu_ws_ratesheet;
	void *eu_rt_ratesheet;
	int ws_reload_pending;
	int rt_reload_pending;
	int eu_ws_reload_pending;
	int eu_rt_reload_pending;
	struct account_cell *next;
	struct account_cell *prev;
};

/* eu extended rate hash */
struct eu_extended_table{
	unsigned int       size;
	struct eu_extended_entry   *entries;
};

struct eu_extended_entry {
	struct eu_extended_cell *first;
	struct eu_extended_cell *last;
};

struct eu_extended_cell {
	int breakout_id;
	ptree_t *trie;
	struct eu_extended_cell *next;
	struct eu_extended_cell *prev;
};

static struct carrier_table *carr_table = NULL;
static struct accounts_table *acc_table = NULL;

static int carr_hash_size = 256;
static int acc_hash_size = 256;
static int eu_extended_hash_size=256;
static int add_carrier(str *carrier,int safe);
static int add_client(str *accountid,int safe);

static param_export_t params[] = {
	{ "carriers_db_url",		STR_PARAM,				&carriers_db_url.s},
	{ "accounts_db_url",		STR_PARAM,				&accounts_db_url.s},
	{ "rates_db_url",		STR_PARAM,				&rates_db_url.s},
	{ "carrier_hash_size",		INT_PARAM,				&carr_hash_size},
	{ "accounts_hash_size",		INT_PARAM,				&acc_hash_size},
	{ 0,				0,					0}
};

static mi_export_t mi_cmds [] = {
	/* carrier methods */
	{ "getCarrierPrice",        0, mi_get_carrier_price,      0,  0,  0},
	{ "getCarrierEuPrice",      0, mi_get_carrier_eu_price,   0,  0,  0},
	{ "getBulkCarrierPrice",    0, mi_get_bulk_carrier_price, 0,  0,  0},
	{ "reloadCarrierRate",      0, mi_reload_carrier_rate,    0,  0,  0},
	{ "reloadCarrierEuRate",    0, mi_reload_eu_carrier_rate, 0,  0,  0},
	{ "addCarrier",             0, mi_add_carrier,            0,  0,  0},
	{ "deleteCarrierRate",      0, mi_delete_carrier_rate,    0,  0,  0},
	{ "deleteCarrierEuRate",    0, mi_delete_carrier_eu_rate, 0,  0,  0},
	{ "deleteCarrier",          0, mi_delete_carrier,         0,  0,  0},
	/* client methods */
	{ "getClientPrice",         0, mi_get_client_price,       0,  0,  0},
	{ "getClientEuPrice",       0, mi_get_eu_client_price,    0,  0,  0},
	{ "getBulkClientPrice",     0, mi_get_bulk_client_price,  0,  0,  0},
	{ "reloadClientRate",       0, mi_reload_client,          0,  0,  0},
	{ "reloadClientEuRate",     0, mi_reload_eu_client,       0,  0,  0},
	{ "addClient",              0, mi_add_client,             0,  0,  0},
	{ "deleteClient",           0, mi_delete_client,          0,  0,  0},
	{ "deleteClientRate",       0, mi_delete_client_rate,     0,  0,  0},
	{ "deleteClientEuRate",     0, mi_delete_eu_client_rate,  0,  0,  0},
	{0,0,0,0,0,0}
};

static cmd_export_t cmds[]={
	{"cost_based_routing",(cmd_function)script_cost_based_routing, 6,
		fixup_cost_based_routing,0,REQUEST_ROUTE},
	{0,0,0,0,0,0}
};


struct module_exports exports= {
	"rate_cacher",
	MOD_TYPE_DEFAULT,	/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,	/* dlopen flags */
	0,			/* OpenSIPS module dependencies */
	cmds,			/* script functions */
	0,			/* exported async functions */
	params,			/* exported parameters */
	0,			/* exported statistics */
	mi_cmds,		/* exported MI functions */
	0,			/* exported pseudo-variables */
	0,			/* exported transformations */
	0,			/* extra processes */
	mod_init,		/* module initialization function */
	0,
	mod_destroy,		/* module exit function */
	mod_child		/* per-child init function */
};

static int mod_init(void)
{
	int i;
	pv_spec_t avp_spec;
	unsigned short dummy;

	LM_INFO("Rate_Cacher module - initializing ...\n");

	/* init carriers hash */
	carr_table = (struct carrier_table*)shm_malloc(
		(sizeof(struct carrier_table) + carr_hash_size*sizeof(struct carrier_entry)));
	if (carr_table == NULL) {
		LM_ERR("No SHM for carrier hash \n");
		return -1;
	}
	carr_table->size = carr_hash_size;
	carr_table->entries = (struct carrier_entry*)(carr_table+1);
	for( i=0 ; i<carr_hash_size; i++ ) {
		memset( &(carr_table->entries[i]), 0, sizeof(struct carrier_entry));
		carr_table->entries[i].lock = lock_init_rw();
		if (carr_table->entries[i].lock == NULL) {
			LM_ERR("Failed to init carrier hash lock \n");
			return -1;
		}
	}

	/* init accounts hash */
	acc_table = (struct accounts_table*)shm_malloc(
		(sizeof(struct accounts_table) + acc_hash_size*sizeof(struct account_entry)));
	if (acc_table == NULL) {
		LM_ERR("No SHM for accounts hash \n");
		return -1;
	}
	acc_table->size = acc_hash_size;
	acc_table->entries = (struct account_entry*)(acc_table+1);
	for( i=0 ; i<acc_hash_size; i++ ) {
		memset( &(acc_table->entries[i]), 0, sizeof(struct account_entry));
		acc_table->entries[i].lock = lock_init_rw();
		if (acc_table->entries[i].lock == NULL) {
			LM_ERR("Failed to init account hash lock \n");
			return -1;
		}
	}

	/* init DB connection */
	init_db_url( carriers_db_url , 0 /*cannot be null*/);
	init_db_url( accounts_db_url , 0 /*cannot be null*/);
	init_db_url( rates_db_url , 0 /*cannot be null*/);

	if (db_bind_mod( &carriers_db_url, &carriers_dbf  )) {
		LM_CRIT("cannot bind to database module! "
			"Did you forget to load a database module ?\n");
		return -1;
	}

	if (db_bind_mod(&accounts_db_url, &accounts_dbf)) {
		LM_CRIT("cannot bind to database module! "
			"Did you forget to load a database module ?\n");
		return -1;
	}

	if (db_bind_mod(&rates_db_url, &rates_dbf)) {
		LM_CRIT("cannot bind to database module! "
			"Did you forget to load a database module ?\n");
		return -1;
	}

	/* load all the data at startup, anyway we don't do any other stuff except rate caching */

	if ( (carriers_db_hdl=carriers_dbf.init(&carriers_db_url))==0 ) {
		LM_CRIT("cannot initialize carriers database connection\n");
		return -1;
	}

	if ( (accounts_db_hdl=accounts_dbf.init(&accounts_db_url))==0 ) {
		LM_CRIT("cannot initialize accounts database connection\n");
		return -1;
	}

	if ( (rates_db_hdl=rates_dbf.init(&rates_db_url))==0 ) {
		LM_CRIT("cannot initialize accounts database connection\n");
		return -1;
	}

	if (rate_cacher_load_all_info() < 0) {
		LM_ERR("Failed to load all data from the DB\n");
		return -1;
	}

	rc_fix_avp_definition( rc_reply_avp_spec, rc_reply_avp, "RC REPLY");
	rc_fix_avp_definition( rc_profit_margin_spec, rc_profit_margin_avp, "RC Profit Margin");

	carriers_dbf.close(carriers_db_hdl);
	carriers_db_hdl = NULL;
	accounts_dbf.close(accounts_db_hdl);
	accounts_db_hdl = NULL;
	rates_dbf.close(rates_db_hdl);
	rates_db_hdl = NULL;

	return 0;
}

static int mod_child(int rank)
{
	if ( (carriers_db_hdl=carriers_dbf.init(&carriers_db_url))==0 ) {
		LM_CRIT("cannot initialize carriers database connection\n");
		return -1;
	}

	if ( (accounts_db_hdl=accounts_dbf.init(&accounts_db_url))==0 ) {
		LM_CRIT("cannot initialize accounts database connection\n");
		return -1;
	}

	if ( (rates_db_hdl=rates_dbf.init(&rates_db_url))==0 ) {
		LM_CRIT("cannot initialize accounts database connection\n");
		return -1;
	}

	return 0;
}

void mod_destroy(void)
{
	/* FIXME - cleanup here ? too lazy to do it now :D */
}

struct eu_ratesheet_cell_entry* build_eu_rate_prefix_entry(str *destination,double price,
	int minimum,int increment, str *source)
{
	struct eu_ratesheet_cell_entry* new_cell = shm_malloc(sizeof(struct eu_ratesheet_cell_entry)+
		destination->len+source->len);
	if (new_cell == NULL) {
		LM_ERR("No more SHM for prefix entry\n");
		return NULL;
	}

	memset(new_cell,0,sizeof(struct eu_ratesheet_cell_entry));
	new_cell->price = price;
	new_cell->minimum = minimum;
	new_cell->increment = increment;
	new_cell->destination.s = (char *)(new_cell+1);
	new_cell->destination.len = destination->len;
	memcpy(new_cell->destination.s,destination->s,destination->len);
	new_cell->source_name.s = new_cell->destination.s + destination->len;
	new_cell->source_name.len = source->len;
	memcpy(new_cell->source_name.s,source->s,source->len);

	return new_cell; 
}

struct ratesheet_cell_entry* build_rate_prefix_entry(str *destination,double price,
	int minimum,int increment, int destination_id)
{

	struct ratesheet_cell_entry* new_cell = shm_malloc(sizeof(struct ratesheet_cell_entry)+
		destination->len);
	if (new_cell == NULL) {
		LM_ERR("No more SHM for prefix entry\n");
		return NULL;
	}

	memset(new_cell,0,sizeof(struct ratesheet_cell_entry));
	new_cell->price = price;
	new_cell->minimum = minimum;
	new_cell->increment = increment;
	new_cell->destination_id = destination_id;
	new_cell->destination.s = (char *)(new_cell+1);
	new_cell->destination.len = destination->len;
	memcpy(new_cell->destination.s,destination->s,destination->len);

	return new_cell; 
} 

struct ratesheet_cell_entry* get_rate_price_prefix(ptree_t *ptree,str* in_prefix,unsigned int *matched_len)
{
	struct ratesheet_cell_entry *rt = NULL;
	char *tmp=NULL;
	char local=0;
	int idx=0;
	str prefix;

	if(NULL == ptree)
		goto err_exit;
	if(NULL == in_prefix)
		goto err_exit;

	if (in_prefix->len == 1 && (in_prefix->s[0] == 'x' || in_prefix->s[0] == 'X'))
		goto err_exit;

	prefix = *in_prefix;
	if (prefix.s[prefix.len-1] == 'x' || prefix.s[prefix.len-1] == 'X')
		prefix.len--;

	tmp = prefix.s;
	/* dst matching, make sure it's all digits */
	while(tmp < (prefix.s+prefix.len)) {
		if( !IS_DECIMAL_DIGIT(*tmp) ) {
			LM_ERR("DST [%.*s] is not digit only \n",prefix.len,prefix.s);
			return NULL;
		}
		tmp++;
	}

	tmp = prefix.s;
	/* go the tree down to the last digit in the
	 * prefix string or down to a leaf */
	while(tmp< (prefix.s+prefix.len)) {
		if(NULL == tmp)
			goto err_exit;
		local=*tmp;
		//LM_INFO("XXX %c\n",*tmp);
		if( tmp == (prefix.s+prefix.len-1) || *tmp == 'x' ) {
			//LM_INFO("PPP - last digit \n");
			/* last digit in the prefix string */
			break;
		}
		idx = local -'0';
		if( NULL == ptree->ptnode[idx].next) {
			/* this is a leaf */
			//LM_INFO("LLL - leaf \n");
			break;
		}
		ptree = ptree->ptnode[idx].next;
		//LM_INFO("CCC - advancing ptree to %p \n",ptree);
		tmp++;
	}
	/* go in the tree up to the root trying to match the
	 * prefix */
	if (*tmp == 'x')
		tmp--;
	//LM_INFO("KKK - at start tmp = %c, ptree = %p\n",*tmp,ptree);

	while(ptree !=NULL ) {
		if(NULL == tmp)
			goto err_exit;
		/* is it a real node or an intermediate one */
		idx = *tmp-'0';
		//LM_INFO("YYY %c %d\n",*tmp,idx);
		if(NULL != ptree->ptnode[idx].re) {
			/* real node */
			rt = ptree->ptnode[idx].re;
			//LM_INFO("ZZZ - returning %p \n",rt);
			break;
		}
		tmp--;
		ptree = ptree->bp;
	}

	if (matched_len) *matched_len = tmp + 1 - prefix.s ;
	return rt;

err_exit:
	return NULL;
}

int get_eu_rate_price_prefix(void *eu_tree,ptree_t* reg_tree,unsigned int type,str *src,str *dst,unsigned int *dst_matched_len,unsigned int *src_matched_len,struct eu_rate_lookup_rpl *ret)
{
	struct ratesheet_cell_entry *rt = NULL;
	char *tmp=NULL;
	char local=0;
	int idx=0,dst_id,eu_bucket;
	str sprefix,dprefix,prefix,str_br_id;
	ptree_t *ptree;
	struct eu_extended_entry *eu_entry;
	struct eu_extended_cell *eu_cell;
	struct eu_extended_table *extended_hash;

	if(NULL == eu_tree)
		goto err_exit;
	if(NULL == dst)
		goto err_exit;

	if (dst->len == 1 && (dst->s[0] == 'x' || dst->s[0] == 'X'))
		goto err_exit;

	sprefix = *src;
	if (sprefix.s[sprefix.len-1] == 'x' || sprefix.s[sprefix.len-1] == 'X')
		sprefix.len--;

	dprefix = *dst;
	if (dprefix.s[dprefix.len-1] == 'x' || dprefix.s[dprefix.len-1] == 'X')
		dprefix.len--;

	if (type == 0) {
		/* destination only matching, make sure it's just digits */
		tmp = dprefix.s;
	        while(tmp < (dprefix.s+dprefix.len)) {
                	if( !IS_DECIMAL_DIGIT(*tmp) ) {
				LM_ERR("DST [%.*s] is not digit only \n",dprefix.len,dprefix.s);
				return -1;
			}
			tmp++;
		}

		/* regular EU format, just lookup the dst number in the regular ratesheet trie */
		prefix = dprefix;
		ptree = (ptree_t*) eu_tree;
		
		/* no ANI matching at all */
		if (*src_matched_len)
			src_matched_len = 0;
	} else {
		/* extended format, first lookup the destination in the regular trie,
		in order to get the dst breakout */

		tmp = dprefix.s;
		/* src & dst matching, make sure it's all digits */
	        while(tmp < (dprefix.s+dprefix.len)) {
                	if( !IS_DECIMAL_DIGIT(*tmp) ) {
				LM_ERR("DST [%.*s] is not digit only \n",dprefix.len,dprefix.s);
				return -1;
			}
			tmp++;
		}
		tmp = sprefix.s;
	        while(tmp < (sprefix.s+sprefix.len)) {
                	if( !IS_DECIMAL_DIGIT(*tmp) ) {
				LM_ERR("SRC [%.*s] is not digit only \n",sprefix.len,sprefix.s);
				return -1;
			}
			tmp++;
		}

		prefix = dprefix;
		ptree = reg_tree;

		if (ptree == NULL)
			return -1;

		tmp = prefix.s;
		/* go the tree down to the last digit in the
		 * prefix string or down to a leaf */
		while(tmp< (prefix.s+prefix.len)) {
			if(NULL == tmp)
				goto err_exit;
			local=*tmp;
			if( tmp == (prefix.s+prefix.len-1) || *tmp == 'x' ) {
				/* last digit in the prefix string */
				break;
			}
			idx = local -'0';
			if( NULL == ptree->ptnode[idx].next) {
				/* this is a leaf */
				break;
			}
			ptree = ptree->ptnode[idx].next;
			tmp++;
		}

		/* go in the tree up to the root trying to match the
		 * prefix */
		if (*tmp == 'x')
			tmp--;

		while(ptree !=NULL ) {
			if(NULL == tmp)
				goto err_exit;
			/* is it a real node or an intermediate one */
			idx = *tmp-'0';
			if(NULL != ptree->ptnode[idx].re) {
				/* real node */
				rt = ptree->ptnode[idx].re;
				break;
			}
			tmp--;
			ptree = ptree->bp;
		}

		if (rt==NULL) {
			return -1;
		}

		if (ret) {
			ret->regular = rt;
		}

		if (dst_matched_len) 
			*dst_matched_len = tmp + 1 - prefix.s ;

		/* find the bucket containing the breakout id, and lookup the ANI in the respective trie */
		extended_hash = (struct eu_extended_table *)eu_tree;
		dst_id = rt->destination_id;
		str_br_id.s = int2str(dst_id,&str_br_id.len);
		eu_bucket = core_hash(&str_br_id,0,extended_hash->size);
		eu_entry = &(extended_hash->entries[eu_bucket]);

		for (eu_cell=eu_entry->first;eu_cell;eu_cell=eu_cell->next) {
			if (eu_cell->breakout_id == dst_id)
				break;
		}

		if (eu_cell == NULL)
			return -1;

		/* found our trie .yay !
		failover below where we lookup the ANI */
		
		prefix = sprefix;
		ptree = eu_cell->trie;

		rt = NULL;
	} 

	tmp = prefix.s;
	/* go the tree down to the last digit in the
	 * prefix string or down to a leaf */
	while(tmp< (prefix.s+prefix.len)) {
		if(NULL == tmp)
			goto err_exit;
		local=*tmp;
		if( tmp == (prefix.s+prefix.len-1) || *tmp == 'x' ) {
			/* last digit in the prefix string */
			break;
		}
		idx = local -'0';
		if( NULL == ptree->ptnode[idx].next) {
			/* this is a leaf */
			break;
		}
		ptree = ptree->ptnode[idx].next;
		tmp++;
	}
	/* go in the tree up to the root trying to match the
	 * prefix */
	if (*tmp == 'x')
		tmp--;

	while(ptree !=NULL ) {
		if(NULL == tmp)
			goto err_exit;
		/* is it a real node or an intermediate one */
		idx = *tmp-'0';
		if(NULL != ptree->ptnode[idx].re) {
			/* real node */
			rt = ptree->ptnode[idx].re;
			break;
		}
		tmp--;
		ptree = ptree->bp;
	}

	if (rt == NULL)
		return -1;

	if (type == 0) {
		if (dst_matched_len) 
			*dst_matched_len = tmp + 1 - prefix.s;
		if (ret) {
			ret->regular = rt;	
			ret->ani_based = NULL;	
		}
	} else {
		if (src_matched_len) 
			*src_matched_len = tmp + 1 - prefix.s;

		if (ret)
			ret->ani_based = (struct eu_ratesheet_cell_entry*) rt;
	}

	return 1;

err_exit:
	return -1;
}

int add_price_prefix(ptree_t *ptree,str* prefix,struct ratesheet_cell_entry *value)
{
	char* tmp=NULL;

	if(ptree == NULL)
		goto err_exit;

	tmp = prefix->s;
	while(tmp < (prefix->s+prefix->len)) {
		if(NULL == tmp)
			goto err_exit;
		if( !IS_DECIMAL_DIGIT(*tmp) ) {
			/* unknown character in the prefix string */
			goto err_exit;
		}
		if( tmp == (prefix->s+prefix->len-1) ) {
			/* last digit in the prefix string */
			ptree->ptnode[*tmp-'0'].re = value;
			goto ok_exit;
		}
		/* process the current digit in the prefix */
		if(NULL == ptree->ptnode[*tmp - '0'].next) {
			/* allocate new node */
			INIT_PTREE_NODE(ptree, ptree->ptnode[*tmp - '0'].next);
		}
		ptree = ptree->ptnode[*tmp-'0'].next;
		tmp++;
	}

ok_exit:
	return 0;

err_exit:
	return -1;
}

static void free_trie(ptree_t* t)
{
	int i;
	if(NULL == t)
		return;

	/* delete all the children */
	for(i=0; i< PTREE_CHILDREN; i++) {
		if(t->ptnode[i].re != NULL) {
			shm_free(t->ptnode[i].re);
		}
		/* if non leaf delete all the children */
		if(t->ptnode[i].next != NULL)
			free_trie(t->ptnode[i].next);
	} 

	shm_free(t);    
}               

static void free_extended_hash(struct eu_extended_table *hash)
{
	int i;
	struct eu_extended_entry *eu_entry;
	struct eu_extended_cell *eu_cell,*next;
	
	for (i=0;i<eu_extended_hash_size;i++) {
		eu_entry=&hash->entries[i];
		eu_cell=eu_entry->first;
		while (eu_cell) {
			next = eu_cell->next;
			free_trie(eu_cell->trie);	
			shm_free(eu_cell);
			eu_cell=next;
		}
	}

	shm_free(hash);	
}

static void free_carrier_cell(struct carrier_cell *carr)
{
	if (carr->rate_table.s)
		shm_free(carr->rate_table.s);
	if (carr->rate_currency.s)
		shm_free(carr->rate_currency.s);
	free_trie(carr->trie);

	if (carr->eu_rate_table.s)
		shm_free(carr->eu_rate_table.s);
	if (carr->eu_rate_currency.s)
		shm_free(carr->eu_rate_currency.s);
	if (carr->eu_ratesheet) {
		if (carr->eu_type == 0)
			free_trie((ptree_t*)carr->eu_ratesheet);
		else
			free_extended_hash((struct eu_extended_table *)carr->eu_ratesheet);
	}

	shm_free(carr);
}

static void lock_bucket_read(rw_lock_t *lock)
{
	lock_start_read(lock);
}

static void unlock_bucket_read(rw_lock_t *lock)
{
	lock_stop_read(lock);
}

static void lock_bucket_write(rw_lock_t *lock)
{
	lock_start_write(lock);
}

static void unlock_bucket_write(rw_lock_t *lock)
{
	lock_stop_write(lock);
}

static str ratesheets_db_table = str_init("ratesheets");
static str eu_ratesheets_db_table = str_init("eu_ratesheets");
static str rs_currency_col = str_init("currency");
static str rs_table_col = str_init("ratesheettable");
static str rs_rateid_col = str_init("id");
static str rs_destination_col = str_init("destination");
static str rs_cc_col = str_init("cc");
static str rs_price_col = str_init("price");
static str rs_minimum_col = str_init("minimum");
static str rs_increment_col = str_init("increment");
static str rs_dst_id_col = str_init("destination_id");
static str rs_source_col = str_init("source");
static str eu_rs_format_col = str_init("eu_rate_format");
static int reload_carrier_rate(str *carrierid, int rate_id)
{
	struct carrier_entry *entry;
	struct ratesheet_cell_entry* rs_entry;
	struct carrier_cell *it=NULL;
	str currency,rate_table,destination,prefix;
	int bucket,i,no_rows=10;
	db_key_t columns[6];
	db_res_t* res=NULL;
	db_row_t* row;
	db_key_t key_cmp;
	db_val_t val_cmp;
	ptree_t* new_trie;

	if (rate_id == 0)
		return -1;

	currency.s = NULL;
	rate_table.s = NULL;

	bucket = core_hash(carrierid,0,carr_table->size);
	entry = &(carr_table->entries[bucket]);

	/* quickly lookup the carrier to see if it exists */
	lock_bucket_write( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->carrierid.len == carrierid->len &&
		memcmp(it->carrierid.s,carrierid->s,carrierid->len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		unlock_bucket_write( entry->lock );
		LM_ERR("Could not find carrier %.*s - cannot reload \n",carrierid->len,carrierid->s);
		return -1;
	}

	if (it->reload_pending == 1) {
		LM_WARN("Reload already triggered for carrier %.*s - aborting this attempt\n",carrierid->len,carrierid->s);
		unlock_bucket_write( entry->lock );
		return 1;
	}
		
	it->reload_pending = 1;
	unlock_bucket_write( entry->lock );

	INIT_PTREE_NODE(NULL, new_trie);

	/* load the ratesheet */
	if (rates_dbf.use_table( rates_db_hdl, &ratesheets_db_table) < 0) {
		LM_ERR("cannot use carriers table \n");
		goto err_unlock_pending;
	}

	columns[0] = &rs_currency_col;
	columns[1] = &rs_table_col;

	key_cmp = &rs_rateid_col;
	val_cmp.type = DB_INT;
	val_cmp.nul  = 0;
	val_cmp.val.int_val = rate_id;

	if ( rates_dbf.query( rates_db_hdl, &key_cmp, 0, &val_cmp, columns, 1, 2, 0, &res) < 0) {
		LM_ERR("Ratesheets DB query failed\n");
		goto err_unlock_pending;
	}

	if (RES_ROW_N(res) != 1) {
		LM_ERR("%d Rows returned for the rate of carrier %.*s\n",RES_ROW_N(res),carrierid->len,carrierid->s);
		goto err_carr_free;
	}

	row = RES_ROWS(res);

	/* duplicate to SHM now, we'll do another query to the rates DB */
	currency.s = (char *)(VAL_STRING(ROW_VALUES(row))); 

	currency.len = strlen(VAL_STRING(ROW_VALUES(row)));
	currency.s = shm_malloc(currency.len);
	if (currency.s == NULL) {
		LM_ERR("No more shm memory for currency\n");
		goto err_carr_free;
	}
	memcpy(currency.s,VAL_STRING(ROW_VALUES(row)),currency.len);

	rate_table.len = strlen(VAL_STRING(ROW_VALUES(row)+1));
	rate_table.s = shm_malloc(rate_table.len);
	if (rate_table.s == NULL) {
		LM_ERR("No more shm memory for rate table \n");
		goto err_carr_free;
	}
	memcpy(rate_table.s,VAL_STRING(ROW_VALUES(row)+1),rate_table.len);

	rates_dbf.free_result(rates_db_hdl, res);
	res = NULL;
	
	LM_INFO("Got rate in table %.*s with currency %.*s\n",rate_table.len,rate_table.s,currency.len,currency.s);

	if (rates_dbf.use_table( rates_db_hdl, &rate_table) < 0) {
		LM_ERR("cannot use carriers table \n");
		goto err_carr_free;
	}

	columns[0] = &rs_destination_col;
	columns[1] = &rs_cc_col;
	columns[2] = &rs_price_col;
	columns[3] = &rs_minimum_col;
	columns[4] = &rs_increment_col;
	columns[5] = &rs_dst_id_col;

	if (DB_CAPABILITY(rates_dbf, DB_CAP_FETCH)) {
		if ( rates_dbf.query( rates_db_hdl, 0, 0, 0, columns, 0, 6, 0, 0) < 0) {
			LM_ERR("Ratesheets DB query failed\n");
			goto err_carr_free;
		}
		no_rows=10000;
		if (no_rows==0)
			no_rows=10;
		if (rates_dbf.fetch_result(rates_db_hdl,&res,no_rows) < 0) {
			LM_ERR("Failed to fetch %d rows\n",no_rows);	
			goto err_carr_free;
		}	
	} else {
		if ( rates_dbf.query( rates_db_hdl, 0, 0, 0, columns, 0, 6, 0, &res) < 0) {
			LM_ERR("Ratesheets DB query failed\n");
			goto err_carr_free;
		}
	}

	LM_INFO("%d records found in %.*s table \n",RES_ROW_N(res),rate_table.len,rate_table.s);

	do {
		for(i=0; i < RES_ROW_N(res); i++) {
			row = RES_ROWS(res) + i;
			destination.s = (char *)VAL_STRING(ROW_VALUES(row));
			destination.len = strlen(destination.s);
			rs_entry = build_rate_prefix_entry(&destination,VAL_DOUBLE(ROW_VALUES(row)+2),VAL_INT(ROW_VALUES(row)+3),VAL_INT(ROW_VALUES(row)+4),VAL_INT(ROW_VALUES(row)+5));
			if (rs_entry == NULL) {
				LM_ERR("Failed to build prefix rule \n");
				goto err_carr_free;
			}

			prefix.s = (char *)VAL_STRING(ROW_VALUES(row)+1);
			prefix.len = strlen(prefix.s);

			if (add_price_prefix(new_trie,&prefix,rs_entry)<0) {
				LM_ERR("Failed to add prefix to carrier trie\n");
				goto err_carr_free;
			}
		}
		if (DB_CAPABILITY(rates_dbf, DB_CAP_FETCH)) {
			if (rates_dbf.fetch_result(rates_db_hdl,&res,no_rows) < 0) {
				LM_ERR("Failed to fetch %d rows\n",no_rows);	
				goto err_carr_free;
			}	
			LM_INFO("%d records more found in %.*s table \n",RES_ROW_N(res),rate_table.len,rate_table.s);
		} else {
			break;
		}
	} while(RES_ROW_N(res)>0);

	rates_dbf.free_result(rates_db_hdl, res);

	lock_bucket_write( entry->lock );

	if (it->rate_table.s)
		shm_free(it->rate_table.s);
	if (it->rate_currency.s)
		shm_free(it->rate_currency.s);
	free_trie(it->trie);

	it->rateid = rate_id;
	it->rate_table = rate_table;
	it->rate_currency = currency;
	it->trie = new_trie;
	it->reload_pending = 0;
	
	unlock_bucket_write( entry->lock );

	return 0;

err_carr_free:
	if (res)
		rates_dbf.free_result(rates_db_hdl, res);
	if (new_trie)
		free_trie(new_trie);
	if (rate_table.s)
		shm_free(rate_table.s);
	if (currency.s)
		shm_free(currency.s);
err_unlock_pending:
	lock_bucket_write( entry->lock );
	it->reload_pending = 0;
	unlock_bucket_write( entry->lock );

	return -1;
}

static int reload_carrier_eu_rate(str *carrierid, int in_eu_type, int rate_id,int trust_type)
{
	struct carrier_entry *entry;
	struct ratesheet_cell_entry* rs_entry;
	struct eu_ratesheet_cell_entry* eu_rs_entry;
	struct carrier_cell *it=NULL;
	str currency,rate_table,destination,prefix,source,str_br_id;
	int bucket,eu_bucket,i,no_rows=10,prev_breakout_id,curr_breakout_id,eu_type=0;
	db_key_t columns[7];
	db_key_t order;
	db_res_t* res=NULL;
	db_row_t* row;
	db_key_t key_cmp;
	db_val_t val_cmp;
	ptree_t* new_trie=NULL;
	struct eu_extended_table *extended_hash=NULL;
	struct eu_extended_entry *eu_entry;
	struct eu_extended_cell *eu_cell;

	if (rate_id == 0)
		return -1;

	currency.s = NULL;
	rate_table.s = NULL;

	bucket = core_hash(carrierid,0,carr_table->size);
	entry = &(carr_table->entries[bucket]);

	/* quickly lookup the carrier to see if it exists */
	lock_bucket_write( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->carrierid.len == carrierid->len &&
		memcmp(it->carrierid.s,carrierid->s,carrierid->len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		unlock_bucket_write( entry->lock );
		LM_ERR("Could not find carrier %.*s - cannot reload \n",carrierid->len,carrierid->s);
		return -1;
	}

	if (it->eu_reload_pending == 1) {
		LM_WARN("Reload EU already triggered for carrier %.*s - aborting this attempt\n",carrierid->len,carrierid->s);
		unlock_bucket_write( entry->lock );
		return 1;
	}
		
	it->eu_reload_pending = 1;
	unlock_bucket_write( entry->lock );

	/* load the ratesheet */
	if (rates_dbf.use_table( rates_db_hdl, &ratesheets_db_table) < 0) {
		LM_ERR("cannot use carriers table \n");
		goto err_unlock_pending;
	}

	columns[0] = &rs_currency_col;
	columns[1] = &rs_table_col;

	key_cmp = &rs_rateid_col;
	val_cmp.type = DB_INT;
	val_cmp.nul  = 0;
	val_cmp.val.int_val = rate_id;

	if ( rates_dbf.query( rates_db_hdl, &key_cmp, 0, &val_cmp, columns, 1, 2, 0, &res) < 0) {
		LM_ERR("Ratesheets DB query failed\n");
		goto err_unlock_pending;
	}

	if (RES_ROW_N(res) != 1) {
		LM_ERR("%d Rows returned for the rate of carrier %.*s\n",RES_ROW_N(res),carrierid->len,carrierid->s);
		goto err_carr_free;
	}

	row = RES_ROWS(res);

	/* duplicate to SHM now, we'll do another query to the rates DB */
	currency.s = (char *)(VAL_STRING(ROW_VALUES(row))); 

	currency.len = strlen(VAL_STRING(ROW_VALUES(row)));
	currency.s = shm_malloc(currency.len);
	if (currency.s == NULL) {
		LM_ERR("No more shm memory for currency\n");
		goto err_carr_free;
	}
	memcpy(currency.s,VAL_STRING(ROW_VALUES(row)),currency.len);

	rate_table.len = strlen(VAL_STRING(ROW_VALUES(row)+1));
	rate_table.s = shm_malloc(rate_table.len);
	if (rate_table.s == NULL) {
		LM_ERR("No more shm memory for rate table \n");
		goto err_carr_free;
	}
	memcpy(rate_table.s,VAL_STRING(ROW_VALUES(row)+1),rate_table.len);

	rates_dbf.free_result(rates_db_hdl, res);
	res = NULL;

	if (!trust_type) {
		/* load the ratesheet type */
		if (rates_dbf.use_table( rates_db_hdl, &eu_ratesheets_db_table) < 0) {
			LM_ERR("cannot use carriers table \n");
			goto err_carr_free;
		}

		columns[0] = &eu_rs_format_col;

		key_cmp = &rs_rateid_col;
		val_cmp.type = DB_INT;
		val_cmp.nul  = 0;
		val_cmp.val.int_val = rate_id;

		if ( rates_dbf.query( rates_db_hdl, &key_cmp, 0, &val_cmp, columns, 1, 1, 0, &res) < 0) {
			LM_ERR("EU Ratesheets DB query failed\n");
			goto err_carr_free;
		}

		if (RES_ROW_N(res) != 1) {
			LM_ERR("%d Rows returned for the EU rate of carrier %.*s\n",RES_ROW_N(res),carrierid->len,carrierid->s);
			rates_dbf.free_result(rates_db_hdl, res);
			goto err_carr_free;
		}

		row = RES_ROWS(res);
		eu_type = VAL_INT(ROW_VALUES(row));

		rates_dbf.free_result(rates_db_hdl, res);
		res = NULL;
	} else
		eu_type = in_eu_type;
	
	LM_INFO("Got rate in table %.*s with currency %.*s\n",rate_table.len,rate_table.s,currency.len,currency.s);

	if (rates_dbf.use_table( rates_db_hdl, &rate_table) < 0) {
		LM_ERR("cannot use carriers table \n");
		goto err_carr_free;
	}

	if (eu_type == 0) {
		INIT_PTREE_NODE(NULL, new_trie);

		/* regular ratesheet */
		columns[0] = &rs_destination_col;
		columns[1] = &rs_cc_col;
		columns[2] = &rs_price_col;
		columns[3] = &rs_minimum_col;
		columns[4] = &rs_increment_col;
		columns[5] = &rs_dst_id_col;

		if (DB_CAPABILITY(rates_dbf, DB_CAP_FETCH)) {
			if ( rates_dbf.query( rates_db_hdl, 0, 0, 0, columns, 0, 6, 0, 0) < 0) {
				LM_ERR("Ratesheets DB query failed\n");
				goto err_carr_free;
			}
			no_rows=10000;
			if (no_rows==0)
				no_rows=10;
			if (rates_dbf.fetch_result(rates_db_hdl,&res,no_rows) < 0) {
				LM_ERR("Failed to fetch %d rows\n",no_rows);	
				goto err_carr_free;
			}	
		} else {
			if ( rates_dbf.query( rates_db_hdl, 0, 0, 0, columns, 0, 6, 0, &res) < 0) {
				LM_ERR("Ratesheets DB query failed\n");
				goto err_carr_free;
			}
		}

		LM_INFO("%d records found in %.*s table \n",RES_ROW_N(res),rate_table.len,rate_table.s);

		do {
			for(i=0; i < RES_ROW_N(res); i++) {
				row = RES_ROWS(res) + i;
				destination.s = (char *)VAL_STRING(ROW_VALUES(row));
				destination.len = strlen(destination.s);
				rs_entry = build_rate_prefix_entry(&destination,VAL_DOUBLE(ROW_VALUES(row)+2),VAL_INT(ROW_VALUES(row)+3),VAL_INT(ROW_VALUES(row)+4),VAL_INT(ROW_VALUES(row)+5));
				if (rs_entry == NULL) {
					LM_ERR("Failed to build prefix rule \n");
					goto err_carr_free;
				}

				prefix.s = (char *)VAL_STRING(ROW_VALUES(row)+1);
				prefix.len = strlen(prefix.s);

				if (add_price_prefix(new_trie,&prefix,rs_entry)<0) {
					LM_ERR("Failed to add prefix to carrier trie\n");
					goto err_carr_free;
				}
			}
			if (DB_CAPABILITY(rates_dbf, DB_CAP_FETCH)) {
				if (rates_dbf.fetch_result(rates_db_hdl,&res,no_rows) < 0) {
					LM_ERR("Failed to fetch %d rows\n",no_rows);	
					goto err_carr_free;
				}	
				LM_INFO("%d records more found in %.*s table \n",RES_ROW_N(res),rate_table.len,rate_table.s);
			} else {
				break;
			}
		} while(RES_ROW_N(res)>0);

		rates_dbf.free_result(rates_db_hdl, res);
	} else {
		/* extended ratesheet */
		columns[0] = &rs_destination_col;
		columns[1] = &rs_cc_col;
		columns[2] = &rs_price_col;
		columns[3] = &rs_minimum_col;
		columns[4] = &rs_increment_col;
		columns[5] = &rs_dst_id_col;
		columns[6] = &rs_source_col;

		order = &rs_dst_id_col;

		if (DB_CAPABILITY(rates_dbf, DB_CAP_FETCH)) {
			if ( rates_dbf.query( rates_db_hdl, 0, 0, 0, columns, 0, 7, order, 0) < 0) {
				LM_ERR("Ratesheets DB query failed\n");
				goto err_carr_free;
			}
			no_rows=10000;
			if (no_rows==0)
				no_rows=10;
			if (rates_dbf.fetch_result(rates_db_hdl,&res,no_rows) < 0) {
				LM_ERR("Failed to fetch %d rows\n",no_rows);	
				goto err_carr_free;
			}	
		} else {
			if ( rates_dbf.query( rates_db_hdl, 0, 0, 0, columns, 0, 7, order, &res) < 0) {
				LM_ERR("Ratesheets DB query failed\n");
				goto err_carr_free;
			}
		}

		LM_INFO("%d records found in %.*s table \n",RES_ROW_N(res),rate_table.len,rate_table.s);

		/* init extended trie hash */
		extended_hash = (struct eu_extended_table*)shm_malloc(
			(sizeof(struct eu_extended_table) + eu_extended_hash_size*sizeof(struct eu_extended_entry)));
		if (extended_hash == NULL) {
			LM_ERR("No SHM for EU extended trie hash \n");
			goto err_carr_free;
		}

		extended_hash->size = eu_extended_hash_size;
		extended_hash->entries = (struct eu_extended_entry*)(extended_hash+1);
		for( i=0 ; i<eu_extended_hash_size; i++ ) {
			memset( &(extended_hash->entries[i]), 0, sizeof(struct eu_extended_entry));
		}

		/* store a trie for each breakout_id found in the ratesheet */
		prev_breakout_id = -1;
		new_trie = NULL;

		do {
			for(i=0; i < RES_ROW_N(res); i++) {
				row = RES_ROWS(res) + i;
				curr_breakout_id = VAL_INT(ROW_VALUES(row)+5);

				if (curr_breakout_id != prev_breakout_id) {
					if (new_trie != NULL && prev_breakout_id != -1) {
						/* finished a new breakout */
						str_br_id.s = int2str(prev_breakout_id,&str_br_id.len);
						eu_bucket = core_hash(&str_br_id,0,extended_hash->size);
						eu_entry = &(extended_hash->entries[eu_bucket]);

						eu_cell = (struct eu_extended_cell*)shm_malloc(sizeof(struct eu_extended_cell));
						if (eu_cell == NULL) {
							LM_ERR("Failed to allocate a new EU hash entry \n");
							goto err_carr_free;
						}

						memset(eu_cell,0,sizeof(struct eu_extended_cell));
					
						eu_cell->breakout_id = prev_breakout_id;
						eu_cell->trie = new_trie;

						/* link it to the hash */
						if (eu_entry->first == NULL) {
							eu_entry->first=eu_entry->last=eu_cell;
						} else {
							eu_entry->last->next = eu_cell;
							eu_cell->prev = eu_entry->last;
							eu_entry->last = eu_cell;
						}	
					}

					/* init a new trie for the following breakout id */
					new_trie = NULL;
					INIT_PTREE_NODE(NULL, new_trie);
				}

				prev_breakout_id = curr_breakout_id;

				destination.s = (char *)VAL_STRING(ROW_VALUES(row));
				destination.len = strlen(destination.s);
				source.s = (char *)VAL_STRING(ROW_VALUES(row)+6);
				source.len = strlen(source.s);
				eu_rs_entry = build_eu_rate_prefix_entry(&destination,VAL_DOUBLE(ROW_VALUES(row)+2),VAL_INT(ROW_VALUES(row)+3),VAL_INT(ROW_VALUES(row)+4),&source);
				if (eu_rs_entry == NULL) {
					LM_ERR("Failed to build prefix rule \n");
					goto err_carr_free;
				}

				prefix.s = (char *)VAL_STRING(ROW_VALUES(row)+1);
				prefix.len = strlen(prefix.s);

				/* hack here, cast it to a regular rs entry, will cast it back when fetching it */
				if (add_price_prefix(new_trie,&prefix,(struct ratesheet_cell_entry *)eu_rs_entry)<0) {
					LM_ERR("Failed to add prefix to eu extended trie\n");
					goto err_carr_free;
				}
			}
			if (DB_CAPABILITY(rates_dbf, DB_CAP_FETCH)) {
				if (rates_dbf.fetch_result(rates_db_hdl,&res,no_rows) < 0) {
					LM_ERR("Failed to fetch %d rows\n",no_rows);	
					goto err_carr_free;
				}	
				LM_INFO("%d records more found in %.*s table \n",RES_ROW_N(res),rate_table.len,rate_table.s);
			} else {
				break;
			}
		} while(RES_ROW_N(res)>0);

		/* final breakout handling here */
		if (new_trie != NULL && prev_breakout_id != -1) {
			/* finished a new breakout */
			str_br_id.s = int2str(prev_breakout_id,&str_br_id.len);
			eu_bucket = core_hash(&str_br_id,0,extended_hash->size);
			eu_entry = &(extended_hash->entries[eu_bucket]);

			eu_cell = (struct eu_extended_cell*)shm_malloc(sizeof(struct eu_extended_cell));
			if (eu_cell == NULL) {
				LM_ERR("Failed to allocate a new EU hash entry \n");
				goto err_carr_free;
			}

			memset(eu_cell,0,sizeof(struct eu_extended_cell));
		
			eu_cell->breakout_id = prev_breakout_id;
			eu_cell->trie = new_trie;

			/* link it to the hash */
			if (eu_entry->first == NULL) {
				eu_entry->first=eu_entry->last=eu_cell;
			} else {
				eu_entry->last->next = eu_cell;
				eu_cell->prev = eu_entry->last;
				eu_entry->last = eu_cell;
			}	
		}

		rates_dbf.free_result(rates_db_hdl, res);
	}

	/* loaded everything, perform the changes */
	lock_bucket_write( entry->lock );

	if (it->eu_rate_table.s)
		shm_free(it->eu_rate_table.s);
	if (it->eu_rate_currency.s)
		shm_free(it->eu_rate_currency.s);
	if (it->eu_ratesheet) {
		if (it->eu_type == 0)
			free_trie((ptree_t*)it->eu_ratesheet);
		else
			free_extended_hash((struct eu_extended_table *)it->eu_ratesheet);
	}

	it->eu_rate_table = rate_table;
	it->eu_rate_currency = currency;
	it->eu_rateid = rate_id;
	it->eu_type = eu_type;	
	if (eu_type == 0)
		it->eu_ratesheet = new_trie;
	else
		it->eu_ratesheet = extended_hash;

	it->eu_reload_pending = 0;
	unlock_bucket_write( entry->lock );

	return 0;

err_carr_free:
	if (res)
		rates_dbf.free_result(rates_db_hdl, res);
	if (rate_table.s)
		shm_free(rate_table.s);
	if (currency.s)
		shm_free(currency.s);
	if (eu_type == 0) {
		if (new_trie)
			free_trie(new_trie);
	} else {
		if (extended_hash)
			free_extended_hash(extended_hash);
	}
err_unlock_pending:
	lock_bucket_write( entry->lock );
	it->eu_reload_pending = 0;
	unlock_bucket_write( entry->lock );
	return -1;
}

static int reload_client_rate(str *accountid, int wholesale,int rate_id,int startup)
{
	db_key_t columns[6];
	db_res_t* res=NULL;
	db_row_t* row;
	db_key_t key_cmp;
	db_val_t val_cmp;
	str currency,rate_table,destination,prefix;
	int bucket,i,no_rows=10;
	struct account_entry *entry;
	struct account_cell *it;
	struct ratesheet_cell_entry* rs_entry;
	ptree_t* new_trie=NULL;

	if (rate_id == 0)
		return -1;

	rate_table.s = NULL;
	currency.s = NULL;

	bucket = core_hash(accountid,0,acc_table->size);
	entry = &(acc_table->entries[bucket]);

	lock_bucket_write( entry->lock );
	
	for (it=entry->first;it;it=it->next) {
		if (it->accountid.len == accountid->len &&
		memcmp(it->accountid.s,accountid->s,accountid->len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		LM_ERR("No such account %.*s\n",accountid->len,accountid->s);
		unlock_bucket_write( entry->lock );
		return -2;
	}

	if (wholesale) {
		if (it->ws_reload_pending) {
			LM_WARN("Reload already triggered for account %.*s on wholesale - aborting this attempt\n",accountid->len,accountid->s);
			unlock_bucket_write( entry->lock );
			return 1;
		}
		it->ws_reload_pending = 1;
	} else {
		if (it->rt_reload_pending) {
			LM_WARN("Reload already triggered for account %.*s on retail - aborting this attempt\n",accountid->len,accountid->s);
			unlock_bucket_write( entry->lock );
			return 1;
		}
		it->rt_reload_pending = 1;
	}

	unlock_bucket_write( entry->lock );

	if (startup) {
		/* at startup we always load wholesale first, and then retail */
		/* just set the pointers for retail to the wholesale trie, if the rates are the same */
		if (wholesale==0 && it->ws_rateid == rate_id) { 
			it->rt_rate_table = it->ws_rate_table;
			it->rt_rate_currency = it->ws_rate_currency;
			it->rt_trie = it->ws_trie;	
			it->rt_rateid = rate_id;
			it->rt_reload_pending = 0;
			return 1;
		}
	}

	INIT_PTREE_NODE(NULL, new_trie);

	/* load the ratesheet */
	if (rates_dbf.use_table( rates_db_hdl, &ratesheets_db_table) < 0) {
		LM_ERR("cannot use carriers table \n");
		goto err_unlock_pending;
	}

	columns[0] = &rs_currency_col;
	columns[1] = &rs_table_col;

	key_cmp = &rs_rateid_col;
	val_cmp.type = DB_INT;
	val_cmp.nul  = 0;
	val_cmp.val.int_val = rate_id;

	if ( rates_dbf.query( rates_db_hdl, &key_cmp, 0, &val_cmp, columns, 1, 2, 0, &res) < 0) {
		LM_ERR("Ratesheets DB query failed\n");
		goto err_unlock_pending;
	}

	if (RES_ROW_N(res) != 1) {
		LM_ERR("%d Rows returned for the rate ( type %d ) of client %.*s\n",RES_ROW_N(res),wholesale,accountid->len,accountid->s);
		goto err_account_free;
	}

	row = RES_ROWS(res);

	/* duplicate to SHM now, we'll do another query to the rates DB */
	currency.s = (char *)(VAL_STRING(ROW_VALUES(row))); 

	currency.len = strlen(VAL_STRING(ROW_VALUES(row)));
	currency.s = shm_malloc(currency.len);
	if (currency.s == NULL) {
		LM_ERR("No more shm memory for currency \n");
		goto err_account_free;
	}
	memcpy(currency.s,VAL_STRING(ROW_VALUES(row)),currency.len);

	rate_table.len = strlen(VAL_STRING(ROW_VALUES(row)+1));
	rate_table.s = shm_malloc(rate_table.len);
	if (rate_table.s == NULL) {
		shm_free(currency.s);
		LM_ERR("No more shm memory for rate table \n");
		goto err_account_free;
	}
	memcpy(rate_table.s,VAL_STRING(ROW_VALUES(row)+1),rate_table.len);

	rates_dbf.free_result(rates_db_hdl, res);
	res = NULL;

	LM_INFO("Got rate in table %.*s with currency %.*s\n",rate_table.len,rate_table.s,currency.len,currency.s);

	if (rates_dbf.use_table( rates_db_hdl, &rate_table) < 0) {
		LM_ERR("cannot use carriers table \n");
		goto err_account_free;
	}

	columns[0] = &rs_destination_col;
	columns[1] = &rs_cc_col;
	columns[2] = &rs_price_col;
	columns[3] = &rs_minimum_col;
	columns[4] = &rs_increment_col;
	columns[5] = &rs_dst_id_col;

	if (DB_CAPABILITY(rates_dbf, DB_CAP_FETCH)) {
		if ( rates_dbf.query( rates_db_hdl, 0, 0, 0, columns, 0, 6, 0, 0) < 0) {
			LM_ERR("Ratesheets DB query failed\n");
			goto err_account_free;
		}
		no_rows=10000;
		if (no_rows==0)
			no_rows=10;
		if (rates_dbf.fetch_result(rates_db_hdl,&res,no_rows) < 0) {
			LM_ERR("Failed to fetch %d rows\n",no_rows);	
			goto err_account_free;
		}	
	} else {
		if ( rates_dbf.query( rates_db_hdl, 0, 0, 0, columns, 0, 6, 0, &res) < 0) {
			LM_ERR("Ratesheets DB query failed\n");
			goto err_account_free;
		}
	}

	LM_INFO("%d records found in %.*s table \n",RES_ROW_N(res),rate_table.len,rate_table.s);

	do {
		for(i=0; i < RES_ROW_N(res); i++) {
			row = RES_ROWS(res) + i;
			destination.s = (char *)VAL_STRING(ROW_VALUES(row));
			destination.len = strlen(destination.s);
			rs_entry = build_rate_prefix_entry(&destination,VAL_DOUBLE(ROW_VALUES(row)+2),VAL_INT(ROW_VALUES(row)+3),VAL_INT(ROW_VALUES(row)+4),VAL_INT(ROW_VALUES(row)+5));
			if (rs_entry == NULL) {
				LM_ERR("Failed to build prefix rule \n");
				goto err_account_free;
			}

			prefix.s = (char *)VAL_STRING(ROW_VALUES(row)+1);
			prefix.len = strlen(prefix.s);

			if (add_price_prefix(new_trie,&prefix,rs_entry)<0) {
				LM_ERR("Failed to add prefix to carrier trie\n");
				goto err_account_free;
			}
		}
		if (DB_CAPABILITY(rates_dbf, DB_CAP_FETCH)) {
			if (rates_dbf.fetch_result(rates_db_hdl,&res,no_rows) < 0) {
				LM_ERR("Failed to fetch %d rows\n",no_rows);	
				goto err_account_free;
			}	
			LM_INFO("%d records more found in %.*s table \n",RES_ROW_N(res),rate_table.len,rate_table.s);
		} else {
			break;
		}
	} while(RES_ROW_N(res)>0);
	rates_dbf.free_result(rates_db_hdl, res);

	/* loaded everything, perform the changes */

	lock_bucket_write( entry->lock );

	if (wholesale ) {
		if (it->ws_rateid != it->rt_rateid) {
			/* free old info only if it wasn't shared */
			if (it->ws_rate_table.s)
				shm_free(it->ws_rate_table.s);
			if (it->ws_rate_currency.s)
				shm_free(it->ws_rate_currency.s);
			if (it->ws_trie)
				free_trie(it->ws_trie);
		}
		it->ws_rate_table = rate_table;
		it->ws_rate_currency = currency;
		it->ws_trie = new_trie;
		it->ws_rateid = rate_id;

		if (it->rt_rateid == rate_id) {
			/* retail used the same rate that we've assigned now for retail - free retail info and link it here */
			if (it->rt_rate_table.s)
				shm_free(it->rt_rate_table.s);
			if (it->rt_rate_currency.s)
				shm_free(it->rt_rate_currency.s);
			if (it->rt_trie)
				free_trie(it->rt_trie);

			it->rt_rate_table = it->ws_rate_table;
			it->rt_rate_currency = it->ws_rate_currency;
			it->rt_trie = it->ws_trie;	
		}
		it->ws_reload_pending = 0;
	} else {
		if (it->ws_rateid != it->rt_rateid) {
			/* free old info only if it wasn't shared */
			if (it->rt_rate_table.s)
				shm_free(it->rt_rate_table.s);
			if (it->rt_rate_currency.s)
				shm_free(it->rt_rate_currency.s);
			if (it->rt_trie)
				free_trie(it->rt_trie);
		}
		it->rt_rate_table = rate_table;
		it->rt_rate_currency = currency;
		it->rt_trie = new_trie;
		it->rt_rateid = rate_id;

		if (it->ws_rateid == rate_id) {
			/* wholesale used the same rate that we've assigned now for retail - free wholesale info and link it here */
			if (it->ws_rate_table.s)
				shm_free(it->ws_rate_table.s);
			if (it->ws_rate_currency.s)
				shm_free(it->ws_rate_currency.s);
			if (it->ws_trie)
				free_trie(it->ws_trie);
			
			it->ws_rate_table = it->rt_rate_table;
			it->ws_rate_currency = it->rt_rate_currency;
			it->ws_trie = it->rt_trie; 
		}
		it->rt_reload_pending = 0;
	}
	unlock_bucket_write( entry->lock );

	return 0;

err_account_free:
	if (res)
		rates_dbf.free_result(rates_db_hdl, res);
	if (rate_table.s)
		shm_free(rate_table.s);
	if (currency.s)
		shm_free(currency.s);
	if (new_trie)
		free_trie(it->rt_trie);
err_unlock_pending:
	lock_bucket_write( entry->lock );
	if (wholesale) {
		it->ws_reload_pending = 0;
	} else {
		it->rt_reload_pending = 0;
	}
	unlock_bucket_write( entry->lock );

	return -1;
}

static int reload_eu_client_rate(str *accountid, int wholesale,int eu_type,int rate_id,int startup)
{
	db_key_t columns[7];
	db_key_t order;
	db_res_t* res=NULL;
	db_row_t* row;
	db_key_t key_cmp;
	db_val_t val_cmp;
	str currency,rate_table,destination,prefix,source,str_br_id;
	int bucket,eu_bucket,i,no_rows=10,prev_breakout_id,curr_breakout_id;
	struct account_entry *entry;
	struct account_cell *it;
	struct ratesheet_cell_entry* rs_entry;
	struct eu_ratesheet_cell_entry* eu_rs_entry;
	ptree_t* new_trie=NULL;
	struct eu_extended_table *extended_hash=NULL;
	struct eu_extended_entry *eu_entry;
	struct eu_extended_cell *eu_cell;

	if (rate_id == 0)
		return -1;

	rate_table.s = NULL;
	currency.s = NULL;

	bucket = core_hash(accountid,0,acc_table->size);
	entry = &(acc_table->entries[bucket]);

	lock_bucket_write( entry->lock );
	
	for (it=entry->first;it;it=it->next) {
		if (it->accountid.len == accountid->len &&
		memcmp(it->accountid.s,accountid->s,accountid->len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		LM_ERR("No such account %.*s\n",accountid->len,accountid->s);
		unlock_bucket_write( entry->lock );
		return -2;
	}

	if (wholesale) {
		if (it->eu_ws_reload_pending) {
			LM_WARN("Reload already triggered for account %.*s on EU wholesale - aborting this attempt\n",accountid->len,accountid->s);
			unlock_bucket_write( entry->lock );
			return 1;
		}
		it->eu_ws_reload_pending = 1;
	} else {
		if (it->eu_rt_reload_pending) {
			LM_WARN("Reload already triggered for account %.*s on EU retail - aborting this attempt\n",accountid->len,accountid->s);
			unlock_bucket_write( entry->lock );
			return 1;
		}
		it->eu_rt_reload_pending = 1;
	}

	unlock_bucket_write( entry->lock );

	if (startup) {
		/* at startup we always load wholesale first, and then retail */
		/* just set the pointers for retail to the wholesale trie, if the rates are the same */
		if (wholesale==0 && it->eu_ws_rateid == rate_id) { 
			it->eu_rt_rate_table = it->eu_ws_rate_table;
			it->eu_rt_rate_currency = it->eu_ws_rate_currency;
			it->eu_rt_ratesheet = it->eu_ws_ratesheet;
			it->eu_rt_rateid = rate_id;
			it->eu_rt_rate_type = eu_type;
			it->eu_rt_reload_pending = 0;
			return 1;
		}
	}

	/* load the ratesheet */
	if (rates_dbf.use_table( rates_db_hdl, &ratesheets_db_table) < 0) {
		LM_ERR("cannot use ratesheets table \n");
		goto err_unlock_pending;
	}

	columns[0] = &rs_currency_col;
	columns[1] = &rs_table_col;

	key_cmp = &rs_rateid_col;
	val_cmp.type = DB_INT;
	val_cmp.nul  = 0;
	val_cmp.val.int_val = rate_id;

	if ( rates_dbf.query( rates_db_hdl, &key_cmp, 0, &val_cmp, columns, 1, 2, 0, &res) < 0) {
		LM_ERR("Ratesheets DB query failed\n");
		goto err_unlock_pending;
	}

	if (RES_ROW_N(res) != 1) {
		LM_ERR("%d Rows returned for the rate ( type %d ) of client %.*s\n",RES_ROW_N(res),wholesale,accountid->len,accountid->s);
		goto err_account_free;
	}

	row = RES_ROWS(res);

	/* duplicate to SHM now, we'll do another query to the rates DB */
	currency.s = (char *)(VAL_STRING(ROW_VALUES(row))); 

	currency.len = strlen(VAL_STRING(ROW_VALUES(row)));
	currency.s = shm_malloc(currency.len);
	if (currency.s == NULL) {
		LM_ERR("No more shm memory for currency \n");
		goto err_account_free;
	}
	memcpy(currency.s,VAL_STRING(ROW_VALUES(row)),currency.len);

	rate_table.len = strlen(VAL_STRING(ROW_VALUES(row)+1));
	rate_table.s = shm_malloc(rate_table.len);
	if (rate_table.s == NULL) {
		LM_ERR("No more shm memory for rate table \n");
		goto err_account_free;
	}
	memcpy(rate_table.s,VAL_STRING(ROW_VALUES(row)+1),rate_table.len);

	rates_dbf.free_result(rates_db_hdl, res);
	res = NULL;

	LM_INFO("Got rate in table %.*s with currency %.*s\n",rate_table.len,rate_table.s,currency.len,currency.s);

	if (rates_dbf.use_table( rates_db_hdl, &rate_table) < 0) {
		LM_ERR("cannot use carriers table \n");
		goto err_account_free;
	}

	if (eu_type == 0) {
		INIT_PTREE_NODE(NULL, new_trie);

		/* regular ratesheet */
		columns[0] = &rs_destination_col;
		columns[1] = &rs_cc_col;
		columns[2] = &rs_price_col;
		columns[3] = &rs_minimum_col;
		columns[4] = &rs_increment_col;
		columns[5] = &rs_dst_id_col;

		if (DB_CAPABILITY(rates_dbf, DB_CAP_FETCH)) {
			if ( rates_dbf.query( rates_db_hdl, 0, 0, 0, columns, 0, 6, 0, 0) < 0) {
				LM_ERR("Ratesheets DB query failed\n");
				goto err_account_free;
			}
			//no_rows=estimate_available_rows( 40 + 20 + 8 + 4 + 4 + 4 , 6);
			no_rows=10000;
			if (no_rows==0)
				no_rows=10;
			if (rates_dbf.fetch_result(rates_db_hdl,&res,no_rows) < 0) {
				LM_ERR("Failed to fetch %d rows\n",no_rows);	
				goto err_account_free;
			}	
		} else {
			if ( rates_dbf.query( rates_db_hdl, 0, 0, 0, columns, 0, 6, 0, &res) < 0) {
				LM_ERR("Ratesheets DB query failed\n");
				goto err_account_free;
			}
		}

		LM_INFO("%d records found in %.*s table \n",RES_ROW_N(res),rate_table.len,rate_table.s);

		do {
			for(i=0; i < RES_ROW_N(res); i++) {
				row = RES_ROWS(res) + i;
				destination.s = (char *)VAL_STRING(ROW_VALUES(row));
				destination.len = strlen(destination.s);
				rs_entry = build_rate_prefix_entry(&destination,VAL_DOUBLE(ROW_VALUES(row)+2),VAL_INT(ROW_VALUES(row)+3),VAL_INT(ROW_VALUES(row)+4),VAL_INT(ROW_VALUES(row)+5));
				if (rs_entry == NULL) {
					LM_ERR("Failed to build prefix rule \n");
					goto err_account_free;
				}

				prefix.s = (char *)VAL_STRING(ROW_VALUES(row)+1);
				prefix.len = strlen(prefix.s);

				if (add_price_prefix(new_trie,&prefix,rs_entry)<0) {
					LM_ERR("Failed to add prefix to carrier trie\n");
					goto err_account_free;
				}
			}
			if (DB_CAPABILITY(rates_dbf, DB_CAP_FETCH)) {
				if (rates_dbf.fetch_result(rates_db_hdl,&res,no_rows) < 0) {
					LM_ERR("Failed to fetch %d rows\n",no_rows);	
					goto err_account_free;
				}	
				LM_INFO("%d records more found in %.*s table \n",RES_ROW_N(res),rate_table.len,rate_table.s);
			} else {
				break;
			}
		} while(RES_ROW_N(res)>0);
		rates_dbf.free_result(rates_db_hdl, res);
	} else {
		/* extended ratesheet */
		columns[0] = &rs_destination_col;
		columns[1] = &rs_cc_col;
		columns[2] = &rs_price_col;
		columns[3] = &rs_minimum_col;
		columns[4] = &rs_increment_col;
		columns[5] = &rs_dst_id_col;
		columns[6] = &rs_source_col;

		order = &rs_dst_id_col;

		if (DB_CAPABILITY(rates_dbf, DB_CAP_FETCH)) {
			if ( rates_dbf.query( rates_db_hdl, 0, 0, 0, columns, 0, 7, order, 0) < 0) {
				LM_ERR("Ratesheets DB query failed\n");
				goto err_account_free;
			}
			//no_rows=estimate_available_rows( 40 + 20 + 8 + 4 + 4 + 4 + 40 , 7);
			no_rows=10000;
			if (no_rows==0)
				no_rows=10;
			if (rates_dbf.fetch_result(rates_db_hdl,&res,no_rows) < 0) {
				LM_ERR("Failed to fetch %d rows\n",no_rows);	
				goto err_account_free;
			}	
		} else {
			if ( rates_dbf.query( rates_db_hdl, 0, 0, 0, columns, 0, 7, order, &res) < 0) {
				LM_ERR("Ratesheets DB query failed\n");
				goto err_account_free;
			}
		}

		LM_INFO("%d records found in %.*s table \n",RES_ROW_N(res),rate_table.len,rate_table.s);

		/* init extended trie hash */
		extended_hash = (struct eu_extended_table*)shm_malloc(
			(sizeof(struct eu_extended_table) + eu_extended_hash_size*sizeof(struct eu_extended_entry)));
		if (extended_hash == NULL) {
			LM_ERR("No SHM for EU extended trie hash \n");
			goto err_account_free;
		}

		extended_hash->size = eu_extended_hash_size;
		extended_hash->entries = (struct eu_extended_entry*)(extended_hash+1);
		for( i=0 ; i<eu_extended_hash_size; i++ ) {
			memset( &(extended_hash->entries[i]), 0, sizeof(struct eu_extended_entry));
		}

		/* store a trie for each breakout_id found in the ratesheet */
		prev_breakout_id = -1;
		new_trie = NULL;

		do {
			for(i=0; i < RES_ROW_N(res); i++) {
				row = RES_ROWS(res) + i;
				curr_breakout_id = VAL_INT(ROW_VALUES(row)+5);

				if (curr_breakout_id != prev_breakout_id) {
					if (new_trie != NULL && prev_breakout_id != -1) {
						/* finished a new breakout */
						str_br_id.s = int2str(prev_breakout_id,&str_br_id.len);
						eu_bucket = core_hash(&str_br_id,0,extended_hash->size);
						eu_entry = &(extended_hash->entries[eu_bucket]);

						eu_cell = (struct eu_extended_cell*)shm_malloc(sizeof(struct eu_extended_cell));
						if (eu_cell == NULL) {
							LM_ERR("Failed to allocate a new EU hash entry \n");
							goto err_account_free;
						}

						memset(eu_cell,0,sizeof(struct eu_extended_cell));
					
						eu_cell->breakout_id = prev_breakout_id;
						eu_cell->trie = new_trie;

						/* link it to the hash */
						if (eu_entry->first == NULL) {
							eu_entry->first=eu_entry->last=eu_cell;
						} else {
							eu_entry->last->next = eu_cell;
							eu_cell->prev = eu_entry->last;
							eu_entry->last = eu_cell;
						}	
					}

					/* init a new trie for the following breakout id */
					new_trie = NULL;
					INIT_PTREE_NODE(NULL, new_trie);
				}

				prev_breakout_id = curr_breakout_id;

				destination.s = (char *)VAL_STRING(ROW_VALUES(row));
				destination.len = strlen(destination.s);
				source.s = (char *)VAL_STRING(ROW_VALUES(row)+6);
				source.len = strlen(source.s);
				eu_rs_entry = build_eu_rate_prefix_entry(&destination,VAL_DOUBLE(ROW_VALUES(row)+2),VAL_INT(ROW_VALUES(row)+3),VAL_INT(ROW_VALUES(row)+4),&source);
				if (eu_rs_entry == NULL) {
					LM_ERR("Failed to build prefix rule \n");
					goto err_account_free;
				}

				prefix.s = (char *)VAL_STRING(ROW_VALUES(row)+1);
				prefix.len = strlen(prefix.s);

				/* hack here, cast it to a regular rs entry, will cast it back when fetching it */
				if (add_price_prefix(new_trie,&prefix,(struct ratesheet_cell_entry *)eu_rs_entry)<0) {
					LM_ERR("Failed to add prefix to eu extended trie\n");
					goto err_account_free;
				}
			}
			if (DB_CAPABILITY(rates_dbf, DB_CAP_FETCH)) {
				if (rates_dbf.fetch_result(rates_db_hdl,&res,no_rows) < 0) {
					LM_ERR("Failed to fetch %d rows\n",no_rows);	
					goto err_account_free;
				}	
				LM_INFO("%d records more found in %.*s table \n",RES_ROW_N(res),rate_table.len,rate_table.s);
			} else {
				break;
			}
		} while(RES_ROW_N(res)>0);

		/* final breakout handling here */
		if (new_trie != NULL && prev_breakout_id != -1) {
			/* finished a new breakout */
			str_br_id.s = int2str(prev_breakout_id,&str_br_id.len);
			eu_bucket = core_hash(&str_br_id,0,extended_hash->size);
			eu_entry = &(extended_hash->entries[eu_bucket]);

			eu_cell = (struct eu_extended_cell*)shm_malloc(sizeof(struct eu_extended_cell));
			if (eu_cell == NULL) {
				LM_ERR("Failed to allocate a new EU hash entry \n");
				goto err_account_free;
			}

			memset(eu_cell,0,sizeof(struct eu_extended_cell));
		
			eu_cell->breakout_id = prev_breakout_id;
			eu_cell->trie = new_trie;

			/* link it to the hash */
			if (eu_entry->first == NULL) {
				eu_entry->first=eu_entry->last=eu_cell;
			} else {
				eu_entry->last->next = eu_cell;
				eu_cell->prev = eu_entry->last;
				eu_entry->last = eu_cell;
			}	
		}

		rates_dbf.free_result(rates_db_hdl, res);
	}

	/* loaded everything, perform the changes */

	lock_bucket_write( entry->lock );

	if (wholesale ) {
		if (it->eu_ws_rateid != it->eu_rt_rateid) {
			/* free old info only if it wasn't shared */
			if (it->eu_ws_rate_table.s)
				shm_free(it->eu_ws_rate_table.s);
			if (it->eu_ws_rate_currency.s)
				shm_free(it->eu_ws_rate_currency.s);
			if (it->eu_ws_ratesheet) {
				if (it->eu_ws_rate_type == 0)
					free_trie((ptree_t*)it->eu_ws_ratesheet);
				else
					free_extended_hash((struct eu_extended_table *)it->eu_ws_ratesheet);
			}
					
		}

		it->eu_ws_rate_table = rate_table;
		it->eu_ws_rate_currency = currency;
		it->eu_ws_rateid = rate_id;
		it->eu_ws_rate_type = eu_type;
		if (eu_type == 0)
			it->eu_ws_ratesheet = new_trie;
		else
			it->eu_ws_ratesheet = extended_hash;

		if (it->eu_rt_rateid == rate_id) {
			/* retail used the same rate that we've assigned now for retail - free retail info and link it here */
			if (it->eu_rt_rate_table.s)
				shm_free(it->eu_rt_rate_table.s);
			if (it->eu_rt_rate_currency.s)
				shm_free(it->eu_rt_rate_currency.s);
			if (it->eu_rt_ratesheet) {
				if (it->eu_rt_rate_type == 0)
					free_trie((ptree_t*)it->eu_rt_ratesheet);
				else
					free_extended_hash((struct eu_extended_table *)it->eu_rt_ratesheet);
			}

			it->eu_rt_rate_table = it->eu_ws_rate_table;
			it->eu_rt_rate_currency = it->eu_ws_rate_currency;
			it->eu_rt_rate_type = eu_type;
			it->eu_rt_ratesheet = it->eu_ws_ratesheet;
		}
		it->eu_ws_reload_pending = 0;
	} else {
		if (it->eu_ws_rateid != it->eu_rt_rateid) {
			/* free old info only if it wasn't shared */
			if (it->eu_rt_rate_table.s)
				shm_free(it->eu_rt_rate_table.s);
			if (it->eu_rt_rate_currency.s)
				shm_free(it->eu_rt_rate_currency.s);
			if (it->eu_rt_ratesheet) {
				if (it->eu_rt_rate_type == 0)
					free_trie((ptree_t*)it->eu_rt_ratesheet);
				else
					free_extended_hash((struct eu_extended_table *)it->eu_rt_ratesheet);
			}
		}
		it->eu_rt_rate_table = rate_table;
		it->eu_rt_rate_currency = currency;
		it->eu_rt_rateid = rate_id;
		it->eu_rt_rate_type = eu_type;
		if (eu_type == 0)
			it->eu_rt_ratesheet = new_trie;
		else
			it->eu_rt_ratesheet = extended_hash;

		if (it->eu_ws_rateid == rate_id) {
			/* wholesale used the same rate that we've assigned now for retail - free wholesale info and link it here */
			if (it->eu_ws_rate_table.s)
				shm_free(it->eu_ws_rate_table.s);
			if (it->eu_ws_rate_currency.s)
				shm_free(it->eu_ws_rate_currency.s);
			if (it->eu_ws_ratesheet) {
				if (it->eu_ws_rate_type == 0)
					free_trie((ptree_t*)it->eu_ws_ratesheet);
				else
					free_extended_hash((struct eu_extended_table *)it->eu_ws_ratesheet);
			}
			
			it->eu_ws_rate_table = it->eu_rt_rate_table;
			it->eu_ws_rate_currency = it->eu_rt_rate_currency;
			it->eu_ws_rate_type = eu_type;
			it->eu_ws_ratesheet = it->eu_rt_ratesheet;
		}
		it->eu_rt_reload_pending = 0;
	}
	unlock_bucket_write( entry->lock );

	return 0;

err_account_free:
	if (res)
		rates_dbf.free_result(rates_db_hdl, res);
	if (rate_table.s)
		shm_free(rate_table.s);
	if (currency.s)
		shm_free(currency.s);
	if (eu_type == 0) {
		if (new_trie)
			free_trie(new_trie);
	} else {
		if (extended_hash)
			free_extended_hash(extended_hash);
	}
err_unlock_pending:
	lock_bucket_write( entry->lock );
	if (wholesale) {
		it->eu_ws_reload_pending = 0;
	} else {
		it->eu_rt_reload_pending = 0;
	}
	unlock_bucket_write( entry->lock );
	return -1;
}

static str carr_db_table = str_init("dr_carriers");
static str carr_id_col = str_init("carrierid");
static str carr_rateid_col = str_init("rate_id");
static str carr_eurateid_col = str_init("eu_rate_id");
static str acc_db_table = str_init("accounts");
static str acc_id_col = str_init("id");
static str acc_ws_rateid_col = str_init("wholesale_rate");
static str acc_rt_rateid_col = str_init("retail_rate");
static str acc_eu_ws_rateid_col = str_init("eu_wholesale_rate");
static str acc_eu_rt_rateid_col = str_init("eu_retail_rate");
static str acc_eu_rate_format_col = str_init("eu_rate_format");
static int rate_cacher_load_all_info(void) 
{
	db_key_t columns[6];
	db_res_t* res;
	db_row_t* row;
	str carrierid,accountid;
	int i;

	/* load all the carriers */
	if (carriers_dbf.use_table( carriers_db_hdl, &carr_db_table) < 0) {
		LM_ERR("cannot use carriers table \n");
		return -1;
	}

	columns[0] = &carr_id_col;
	columns[1] = &carr_rateid_col;
	columns[2] = &carr_eurateid_col;

	if ( carriers_dbf.query( carriers_db_hdl, 0, 0, 0, columns, 0, 3, 0, &res) < 0) {
		LM_ERR("Carriers DB query failed\n");
		return -1;
	}

	LM_DBG("%d records found in dr_carriers table \n",RES_ROW_N(res));

	for(i=0; i < RES_ROW_N(res); i++) {
		row = RES_ROWS(res) + i;
		carrierid.s = (char *)(VAL_STRING(ROW_VALUES(row)));
		carrierid.len = strlen(carrierid.s);

		if (add_carrier(&carrierid,0) != 0)
			continue;

		if (reload_carrier_rate(&carrierid,VAL_NULL(ROW_VALUES(row)+1)?0:VAL_INT(ROW_VALUES(row)+1)) < 0) {
			if (!VAL_NULL(ROW_VALUES(row)+1) && VAL_INT(ROW_VALUES(row)+1) != 0)
				LM_ERR("Failed to load carrier %s with rateid %d\n",
				VAL_STRING(ROW_VALUES(row)),VAL_NULL(ROW_VALUES(row)+1)?0:VAL_INT(ROW_VALUES(row)+1));
		} else
			LM_INFO("Loaded carrier %s with rateid %d\n",
			VAL_STRING(ROW_VALUES(row)),VAL_INT(ROW_VALUES(row)+1));

		if (reload_carrier_eu_rate(&carrierid,0,VAL_NULL(ROW_VALUES(row)+2)?0:VAL_INT(ROW_VALUES(row)+2),0) < 0) {
			if (!VAL_NULL(ROW_VALUES(row)+2) && VAL_INT(ROW_VALUES(row)+2) != 0)
				LM_ERR("Failed to load carrier %s with EU rateid %d\n",
				VAL_STRING(ROW_VALUES(row)),VAL_NULL(ROW_VALUES(row)+2)?0:VAL_INT(ROW_VALUES(row)+2));
		} else {
			LM_INFO("Loaded carrier %s with EU rateid %d\n",
			VAL_STRING(ROW_VALUES(row)),VAL_INT(ROW_VALUES(row)+2));
		}
	}

	carriers_dbf.free_result(carriers_db_hdl, res);

	/* load all the accounts */
	if (accounts_dbf.use_table( accounts_db_hdl, &acc_db_table) < 0) {
		LM_ERR("cannot use accounts table \n");
		return -1;
	}
	columns[0] = &acc_id_col;
	columns[1] = &acc_ws_rateid_col;
	columns[2] = &acc_rt_rateid_col;
	columns[3] = &acc_eu_ws_rateid_col;
	columns[4] = &acc_eu_rt_rateid_col;
	columns[5] = &acc_eu_rate_format_col;

	if ( accounts_dbf.query( accounts_db_hdl, 0, 0, 0, columns, 0, 6, 0, &res) < 0) {
		LM_ERR("Accounts DB query failed\n");
		return -1;
	}

	LM_DBG("%d records found in accounts table \n",RES_ROW_N(res));

	for(i=0; i < RES_ROW_N(res); i++) {
		row = RES_ROWS(res) + i;
		accountid.s = int2str(VAL_INT(ROW_VALUES(row)),&accountid.len);
	
		if (add_client(&accountid,0) != 0) {
			LM_ERR("Failed to add account %.*s\n",accountid.len,accountid.s);
			continue;
		}

		if (reload_client_rate(&accountid,1,VAL_INT(ROW_VALUES(row)+1),1) < 0) {
			if (VAL_INT(ROW_VALUES(row)+1) != 0)
				LM_ERR("Failed to load ws rate %d for account %.*s\n",VAL_INT(ROW_VALUES(row)+1),accountid.len,accountid.s);
		} else
			LM_INFO("Loaded ws rate %d for account %.*s\n",VAL_INT(ROW_VALUES(row)+1),accountid.len,accountid.s);

		if (reload_client_rate(&accountid,0,VAL_INT(ROW_VALUES(row)+2),1) < 0) {
			if (VAL_INT(ROW_VALUES(row)+2) != 0)
				LM_ERR("Failed to load rt rate %d for account %.*s\n",VAL_INT(ROW_VALUES(row)+2),accountid.len,accountid.s);
		} else
			LM_INFO("Loaded rt rate %d for account %.*s\n",VAL_INT(ROW_VALUES(row)+2),accountid.len,accountid.s);

		if (reload_eu_client_rate(&accountid,1,VAL_INT(ROW_VALUES(row)+5),VAL_INT(ROW_VALUES(row)+3),1) < 0) {
			if (VAL_INT(ROW_VALUES(row)+3) != 0)
				LM_ERR("Failed to load eu ws rate %d for account %.*s\n",VAL_INT(ROW_VALUES(row)+3),accountid.len,accountid.s);
		} else
			LM_INFO("Loaded eu ws rate %d for account %.*s\n",VAL_INT(ROW_VALUES(row)+3),accountid.len,accountid.s);

		if (reload_eu_client_rate(&accountid,0,VAL_INT(ROW_VALUES(row)+5),VAL_INT(ROW_VALUES(row)+4),1) < 0) {
			if (VAL_INT(ROW_VALUES(row)+4) != 0)
				LM_ERR("Failed to load eu rt rate %d for account %.*s\n",VAL_INT(ROW_VALUES(row)+4),accountid.len,accountid.s);
		} else
			LM_INFO("Loaded eu rt rate %d for account %.*s\n",VAL_INT(ROW_VALUES(row)+4),accountid.len,accountid.s);
	}

	accounts_dbf.free_result(accounts_db_hdl, res);

	return 0;
}


static struct mi_root * mi_get_carrier_price(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node,*rpl;
	struct carrier_cell *it;
	struct carrier_entry *entry;
	int bucket;
	unsigned int matched_len;
	str carrier;
	str prefix;
	struct ratesheet_cell_entry *ret;
	struct mi_root *rpl_tree;

	node = cmd_tree->node.kids;

	if (node==NULL || node->next==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len)
		goto error;

	carrier = node->value;

	node = node->next;
	if ( !node->value.s || !node->value.len)
		goto error;

	prefix = node->value;

	bucket = core_hash(&carrier,0,carr_table->size);
	entry = &(carr_table->entries[bucket]);

	lock_bucket_read( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->carrierid.len == carrier.len &&
		memcmp(it->carrierid.s,carrier.s,carrier.len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		unlock_bucket_read( entry->lock );
		return init_mi_tree( 401, "No such carrier", sizeof("No such carrier")-1);
	}

	ret = get_rate_price_prefix(it->trie,&prefix,&matched_len);
	if (ret == NULL) {
		unlock_bucket_read( entry->lock );
		return init_mi_tree( 401, "No prefix match", sizeof("No prefix match")-1);
	}

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==NULL) {
		unlock_bucket_read( entry->lock );
		return NULL;
	}

	rpl = &rpl_tree->node;
	node = addf_mi_node_child( rpl, 0, MI_SSTR("Result"),
		"[\"%.*s\",\"%.*s\",%f,%d,%d,\"%.*s\"]",matched_len,prefix.s,
		ret->destination.len,ret->destination.s,ret->price,
		ret->minimum,ret->increment,it->rate_currency.len,it->rate_currency.s);

	unlock_bucket_read( entry->lock );
	return rpl_tree;

error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);

}

static struct mi_root * mi_get_carrier_eu_price(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node,*rpl;
	struct carrier_cell *it;
	struct carrier_entry *entry;
	int bucket;
	unsigned int dst_matched_len,src_matched_len;
	str carrier;
	str src,dst;
	struct mi_root *rpl_tree;
	struct eu_rate_lookup_rpl ret; 

	node = cmd_tree->node.kids;

	if (node==NULL || node->next==NULL || node->next->next==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len)
		goto error;

	carrier = node->value;

	node = node->next;
	if ( !node->value.s || !node->value.len )
		goto error;

	src = node->value;

	node = node->next;
	if ( !node->value.s || !node->value.len )
		goto error;

	dst = node->value;

	bucket = core_hash(&carrier,0,carr_table->size);
	entry = &(carr_table->entries[bucket]);

	lock_bucket_read( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->carrierid.len == carrier.len &&
		memcmp(it->carrierid.s,carrier.s,carrier.len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		unlock_bucket_read( entry->lock );
		return init_mi_tree( 401, "No such carrier", sizeof("No such carrier")-1);
	}

	if (get_eu_rate_price_prefix(it->eu_ratesheet,it->trie,it->eu_type,&src,&dst,&dst_matched_len,&src_matched_len,&ret) < 0) {
		unlock_bucket_read( entry->lock );
		return init_mi_tree( 401, "No prefix match", sizeof("No prefix match")-1);
	}

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==NULL) {
		unlock_bucket_read( entry->lock );
		return NULL;
	}

	rpl = &rpl_tree->node;
	if (ret.ani_based == NULL) {
		node = addf_mi_node_child( rpl, 0, MI_SSTR("Result"),
			"[\"%.*s\",\"%.*s\",\"\",\"\",%f,%d,%d,\"%.*s\"]",dst_matched_len,dst.s,
			ret.regular->destination.len,ret.regular->destination.s,ret.regular->price,
			ret.regular->minimum,ret.regular->increment,
			it->rate_currency.len,it->rate_currency.s);
	} else {
		node = addf_mi_node_child( rpl, 0, MI_SSTR("Result"),
			"[\"%.*s\",\"%.*s\",\"%.*s\",\"%.*s\",%f,%d,%d,\"%.*s\"]",dst_matched_len,dst.s,
			ret.regular->destination.len,ret.regular->destination.s,
			src_matched_len,src.s,ret.ani_based->source_name.len,ret.ani_based->source_name.s,
			ret.ani_based->price,
			ret.ani_based->minimum,ret.ani_based->increment,
			it->rate_currency.len,it->rate_currency.s);
	}

	unlock_bucket_read( entry->lock );
	return rpl_tree;

error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);

}

static struct mi_root * mi_get_bulk_carrier_price(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node,*rpl,*node_ret;
	struct carrier_cell *it;
	struct carrier_entry *entry;
	int bucket;
	unsigned int matched_len;
	str carrier;
	str prefix;
	struct ratesheet_cell_entry *ret;
	struct mi_root *rpl_tree;

	node = cmd_tree->node.kids;

	if (node==NULL || node->next==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len)
		goto error;

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==NULL) {
		return NULL;
	}

	rpl = &rpl_tree->node;
	node_ret = add_mi_node_child(rpl,0,MI_SSTR("RESULT"),MI_SSTR(""));

	while (node && node->next && node->value.s && node->value.len && node->next->value.s && node->next->value.len) {
		carrier = node->value;
		prefix = node->next->value;

		bucket = core_hash(&carrier,0,carr_table->size);
		entry = &(carr_table->entries[bucket]);

		lock_bucket_read( entry->lock );

		for (it=entry->first;it;it=it->next) {
			if (it->carrierid.len == carrier.len &&
			memcmp(it->carrierid.s,carrier.s,carrier.len) == 0) {
				break;
			}
		}

		if (it == NULL) {
			unlock_bucket_read( entry->lock );
			addf_mi_node_child( node_ret, 0, MI_SSTR(""),"[\"%.*s-%.*s\",False]",carrier.len,carrier.s,prefix.len,prefix.s);
			node = node->next->next;
			continue;
		}

		ret = get_rate_price_prefix(it->trie,&prefix,&matched_len);
		if (ret == NULL) {
			addf_mi_node_child( node_ret, 0, MI_SSTR(""),"[\"%.*s-%.*s\",False]",carrier.len,carrier.s,prefix.len,prefix.s);
		} else
			addf_mi_node_child( node_ret, 0, MI_SSTR(""),
			"[\"%.*s-%.*s\",\"%.*s\",\"%.*s\",%f,%d,%d,\"%.*s\"]",carrier.len,carrier.s,prefix.len,prefix.s,matched_len,prefix.s,
			ret->destination.len,ret->destination.s,ret->price,
			ret->minimum,ret->increment,it->rate_currency.len,it->rate_currency.s);

		unlock_bucket_read( entry->lock );
		node = node->next->next;
	}

	return rpl_tree;

error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
}

static struct mi_root * mi_reload_carrier_rate(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node;
	int rate_id;
	str carrier;

	node = cmd_tree->node.kids;

	if (node==NULL || node->next==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len)
		goto error;

	carrier = node->value;

	node = node->next;
	if ( !node->value.s || !node->value.len || str2sint(&node->value,&rate_id)<0)
		goto error;

	LM_INFO("XXX - reloadCarrierRate %.*s %d\n",carrier.len,carrier.s,rate_id); 

	if (reload_carrier_rate(&carrier,rate_id) < 0)
		return init_mi_tree( 500, "Failed to reload", sizeof("Failed to reload")-1);
	else
		return init_mi_tree( 200, MI_SSTR(MI_OK));
error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
}

static struct mi_root * mi_reload_eu_carrier_rate(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node;
	int eu_type,rate_id;
	str carrier;

	node = cmd_tree->node.kids;

	if (node==NULL || node->next==NULL || node->next->next == NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len)
		goto error;

	carrier = node->value;

	node = node->next;
	if ( !node->value.s || !node->value.len || str2sint(&node->value,&eu_type)<0)
		goto error;

	node = node->next;
	if ( !node->value.s || !node->value.len || str2sint(&node->value,&rate_id)<0)
		goto error;

	LM_INFO("XXX - reloadCarrierEuRate %.*s %d %d\n",carrier.len,carrier.s,eu_type,rate_id); 

	if (reload_carrier_eu_rate(&carrier,eu_type,rate_id,1) < 0)
		return init_mi_tree( 500, "Failed to reload", sizeof("Failed to reload")-1);
	else
		return init_mi_tree( 200, MI_SSTR(MI_OK));
error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
}

static int add_client(str *accountid, int safe)
{
	int bucket;
	struct account_entry *entry;
	struct account_cell *it;

	bucket = core_hash(accountid,0,acc_table->size);
	entry = &(acc_table->entries[bucket]);

	if (safe)
		lock_bucket_write( entry->lock );

	for (it=entry->first;it;it=it->next) {
		if (it->accountid.len == accountid->len &&
		memcmp(it->accountid.s,accountid->s,accountid->len) == 0) {
			break;
		}
	}

	if (it != NULL) {
		LM_ERR("Account %.*s already exists \n",accountid->len,accountid->s);
		if (safe)
			unlock_bucket_write( entry->lock );
		return 1;
	}

	it = (struct account_cell*)shm_malloc(sizeof(struct account_cell) + accountid->len);
	if (it == NULL) {
		LM_ERR("Failed to allocate shm for account cell \n");
		if (safe)
			unlock_bucket_write( entry->lock );
		return -1;
	}
		
	memset(it,0,sizeof(struct account_cell));

	it->accountid.s = (char *)(it+1);
	it->accountid.len = accountid->len;
	memcpy(it->accountid.s,accountid->s,accountid->len);

	if (entry->first==NULL) {
		entry->first = entry->last = it;
	} else {
		entry->last->next = it;
		it->prev = entry->last;
		entry->last = it;
	}

	if (safe)
		unlock_bucket_write( entry->lock );

	return 0;
}

static int add_carrier(str *carrier,int safe)
{
	int bucket;
	struct carrier_entry *entry;
	struct carrier_cell *carr_cell,*it=NULL;

	bucket = core_hash(carrier,0,carr_table->size);
	entry = &(carr_table->entries[bucket]);

	if (safe)
		lock_bucket_write( entry->lock );

	for (it=entry->first;it;it=it->next) {
		if (it->carrierid.len == carrier->len &&
		memcmp(it->carrierid.s,carrier->s,carrier->len) == 0) {
			break;
		}
	}

	if (it != NULL) {
		LM_ERR("Carrier %.*s already exists \n",carrier->len,carrier->s);
		if (safe)
			unlock_bucket_write( entry->lock );
		return 1;
	}

	carr_cell = (struct carrier_cell *)shm_malloc(sizeof(struct carrier_cell) + carrier->len);
	if (carr_cell == NULL) {
		LM_ERR("Failed to allocate shm for carrier cell \n");
		if (safe)
			unlock_bucket_write( entry->lock );
		return -1;
	}

	/* init carrier */
	memset(carr_cell,0,sizeof(struct carrier_cell));

	carr_cell->carrierid.s = (char *)(carr_cell+1);
	carr_cell->carrierid.len = carrier->len;
	memcpy(carr_cell->carrierid.s,carrier->s,carrier->len);

	/* link the new carrier */
	if (entry->first==NULL) {
		entry->first = entry->last = carr_cell;
	} else {
		entry->last->next = carr_cell;
		carr_cell->prev = entry->last;
		entry->last = carr_cell;
	}

	if (safe)
		unlock_bucket_write( entry->lock );

	return 0;
}

static struct mi_root * mi_add_carrier(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node;
	str carrier;
	int rc;

	node = cmd_tree->node.kids;

	if (node==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len)
		goto error;

	carrier = node->value;

	LM_INFO("XXX - addCarrier %.*s\n",carrier.len,carrier.s);
	rc = add_carrier(&carrier,1);
	if (rc < 0)
		return init_mi_tree( 500, "Failed to add", sizeof("Failed to add")-1);
	else if (rc > 0)
		return init_mi_tree( 402, "Carrier exists", sizeof("Carrier exists")-1);
	else
		return init_mi_tree( 200, MI_SSTR(MI_OK));
error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
}

static struct mi_root * mi_delete_carrier_rate(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node;
	struct carrier_entry *entry;
	struct carrier_cell *it;
	int bucket;
	str carrier;

	node = cmd_tree->node.kids;

	if (node==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	carrier = node->value;

	LM_INFO("XXX - deleteCarrierRate %.*s\n",carrier.len,carrier.s);

	bucket = core_hash(&carrier,0,carr_table->size);
	entry = &(carr_table->entries[bucket]);
	
	lock_bucket_write( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->carrierid.len == carrier.len &&
		memcmp(it->carrierid.s,carrier.s,carrier.len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		unlock_bucket_write( entry->lock );
		return init_mi_tree( 401, "No such carrier", sizeof("No such carrier")-1);
	}

	if (it->reload_pending) {
		unlock_bucket_write( entry->lock );
		return init_mi_tree( 401, "Pending Reload", sizeof("Pending Reload")-1);
	}

	if (it->rate_table.s)
		shm_free(it->rate_table.s);
	if (it->rate_currency.s)
		shm_free(it->rate_currency.s);
	free_trie(it->trie);
	it->trie = NULL;
	it->rateid = 0;

	unlock_bucket_write( entry->lock );
	return init_mi_tree( 200, MI_SSTR(MI_OK));
}

static struct mi_root * mi_delete_carrier_eu_rate(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node;
	struct carrier_entry *entry;
	struct carrier_cell *it;
	int bucket;
	str carrier;

	node = cmd_tree->node.kids;

	if (node==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	carrier = node->value;

	LM_INFO("XXX - deleteCarrierEuRate %.*s\n",carrier.len,carrier.s);

	bucket = core_hash(&carrier,0,carr_table->size);
	entry = &(carr_table->entries[bucket]);
	
	lock_bucket_write( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->carrierid.len == carrier.len &&
		memcmp(it->carrierid.s,carrier.s,carrier.len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		unlock_bucket_write( entry->lock );
		return init_mi_tree( 401, "No such carrier", sizeof("No such carrier")-1);
	}

	if (it->reload_pending) {
		unlock_bucket_write( entry->lock );
		return init_mi_tree( 401, "Pending Reload", sizeof("Pending Reload")-1);
	}

	if (it->eu_rate_table.s)
		shm_free(it->eu_rate_table.s);
	if (it->eu_rate_currency.s)
		shm_free(it->eu_rate_currency.s);
	it->eu_rateid = 0;
	if (it->eu_ratesheet) {
		if (it->eu_type == 0)
			free_trie((ptree_t*)it->eu_ratesheet);
		else
			free_extended_hash((struct eu_extended_table *)it->eu_ratesheet);
	}
	it->eu_ratesheet = NULL;

	unlock_bucket_write( entry->lock );
	return init_mi_tree( 200, MI_SSTR(MI_OK));
}

static struct mi_root * mi_delete_carrier(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node;
	struct carrier_entry *entry;
	struct carrier_cell *it;
	int bucket;
	str carrier;

	node = cmd_tree->node.kids;

	if (node==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len)
		goto error;

	carrier = node->value;

	LM_INFO("XXX - deleteCarrier %.*s\n",carrier.len,carrier.s);

	bucket = core_hash(&carrier,0,carr_table->size);
	entry = &(carr_table->entries[bucket]);
	
	lock_bucket_write( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->carrierid.len == carrier.len &&
		memcmp(it->carrierid.s,carrier.s,carrier.len) == 0) {
			break;
		}
	}
	if (it == NULL) {
		unlock_bucket_write( entry->lock );
		return init_mi_tree( 401, "No such carrier", sizeof("No such carrier")-1);
	}

	if (it->next)
		it->next->prev = it->prev;
	else
		entry->last = it->prev;
	if (it->prev)
		it->prev->next = it->next;
	else
		entry->first = it->next;
	it->next = it->prev = 0;
	
	unlock_bucket_write( entry->lock );

	free_carrier_cell(it);
	return init_mi_tree( 200, MI_SSTR(MI_OK));
error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
}

static struct mi_root * mi_get_client_price(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node,*rpl;
	struct account_cell *it;
	struct account_entry *entry;
	int bucket,is_wholesale;
	unsigned int matched_len;
	str accountid;
	str prefix;
	struct ratesheet_cell_entry *ret;
	struct mi_root *rpl_tree;

	node = cmd_tree->node.kids;

	if (node==NULL || node->next==NULL || node->next->next==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len)
		goto error;

	accountid = node->value;

	node = node->next;
	if ( !node->value.s || !node->value.len || str2sint(&node->value,&is_wholesale)<0 )
		goto error;

	node = node->next;
	if ( !node->value.s || !node->value.len )
		goto error;

	prefix = node->value;

	bucket = core_hash(&accountid,0,acc_table->size);
	entry = &(acc_table->entries[bucket]);

	lock_bucket_read( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->accountid.len == accountid.len &&
		memcmp(it->accountid.s,accountid.s,accountid.len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		unlock_bucket_read( entry->lock );
		return init_mi_tree( 401, "No such client", sizeof("No such client")-1);
	}

	if (is_wholesale)
		ret = get_rate_price_prefix(it->ws_trie,&prefix,&matched_len);
	else
		ret = get_rate_price_prefix(it->rt_trie,&prefix,&matched_len);

	if (ret == NULL) {
		unlock_bucket_read( entry->lock );
		return init_mi_tree( 401, "No prefix match", sizeof("No prefix match")-1);
	}

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==NULL) {
		unlock_bucket_read( entry->lock );
		return NULL;
	}

	rpl = &rpl_tree->node;
	node = addf_mi_node_child( rpl, 0, MI_SSTR("Result"),
		"[\"%.*s\",\"%.*s\",%f,%d,%d,\"%.*s\"]",matched_len,prefix.s,
		ret->destination.len,ret->destination.s,ret->price,
		ret->minimum,ret->increment,
		is_wholesale?it->ws_rate_currency.len:it->rt_rate_currency.len,
		is_wholesale?it->ws_rate_currency.s:it->rt_rate_currency.s);

	unlock_bucket_read( entry->lock );
	return rpl_tree;

error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);

}

static struct mi_root * mi_get_eu_client_price(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node,*rpl;
	struct account_cell *it;
	struct account_entry *entry;
	int bucket,is_wholesale,rc;
	unsigned int dst_matched_len,src_matched_len;
	str accountid;
	str src,dst;
	struct mi_root *rpl_tree;
	struct eu_rate_lookup_rpl ret; 

	node = cmd_tree->node.kids;

	if (node==NULL || node->next==NULL || node->next->next==NULL || node->next->next->next==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len)
		goto error;

	accountid = node->value;

	node = node->next;
	if ( !node->value.s || !node->value.len || str2sint(&node->value,&is_wholesale)<0 )
		goto error;

	node = node->next;
	if ( !node->value.s || !node->value.len )
		goto error;

	src = node->value;

	node = node->next;
	if ( !node->value.s || !node->value.len )
		goto error;

	dst = node->value;

	bucket = core_hash(&accountid,0,acc_table->size);
	entry = &(acc_table->entries[bucket]);

	lock_bucket_read( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->accountid.len == accountid.len &&
		memcmp(it->accountid.s,accountid.s,accountid.len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		unlock_bucket_read( entry->lock );
		return init_mi_tree( 401, "No such client", sizeof("No such client")-1);
	}

	ret.regular = NULL;
	ret.ani_based = NULL;
	dst_matched_len = 0;
	src_matched_len = 0;

	if (is_wholesale)
		rc = get_eu_rate_price_prefix(it->eu_ws_ratesheet,it->ws_trie,it->eu_ws_rate_type,&src,&dst,&dst_matched_len,&src_matched_len,&ret);
	else
		rc = get_eu_rate_price_prefix(it->eu_rt_ratesheet,it->rt_trie,it->eu_rt_rate_type,&src,&dst,&dst_matched_len,&src_matched_len,&ret);

	if (rc < 0) {
		unlock_bucket_read( entry->lock );
		return init_mi_tree( 401, "No prefix match", sizeof("No prefix match")-1);
	}

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==NULL) {
		unlock_bucket_read( entry->lock );
		return NULL;
	}

	rpl = &rpl_tree->node;

	if (ret.ani_based == NULL) {
		node = addf_mi_node_child( rpl, 0, MI_SSTR("Result"),
			"[\"%.*s\",\"%.*s\",\"\",\"\",%f,%d,%d,\"%.*s\"]",dst_matched_len,dst.s,
			ret.regular->destination.len,ret.regular->destination.s,ret.regular->price,
			ret.regular->minimum,ret.regular->increment,
			is_wholesale?it->ws_rate_currency.len:it->rt_rate_currency.len,
			is_wholesale?it->ws_rate_currency.s:it->rt_rate_currency.s);
	} else {
		node = addf_mi_node_child( rpl, 0, MI_SSTR("Result"),
			"[\"%.*s\",\"%.*s\",\"%.*s\",\"%.*s\",%f,%d,%d,\"%.*s\"]",dst_matched_len,dst.s,
			ret.regular->destination.len,ret.regular->destination.s,
			src_matched_len,src.s,ret.ani_based->source_name.len,ret.ani_based->source_name.s,
			ret.ani_based->price,
			ret.ani_based->minimum,ret.ani_based->increment,
			is_wholesale?it->ws_rate_currency.len:it->rt_rate_currency.len,
			is_wholesale?it->ws_rate_currency.s:it->rt_rate_currency.s);
	}

	unlock_bucket_read( entry->lock );
	return rpl_tree;

error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
}

static struct mi_root * mi_get_bulk_client_price(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node,*rpl,*node_ret;
	struct account_cell *it;
	struct account_entry *entry;
	int bucket,is_wholesale;
	unsigned int matched_len;
	str accountid;
	str prefix;
	struct ratesheet_cell_entry *ret;
	struct mi_root *rpl_tree;

	node = cmd_tree->node.kids;

	if (node==NULL || node->next==NULL || node->next->next==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len)
		goto error;

	accountid = node->value;

	node = node->next;
	if ( !node->value.s || !node->value.len || str2sint(&node->value,&is_wholesale)<0 )
		goto error;

	bucket = core_hash(&accountid,0,acc_table->size);
	entry = &(acc_table->entries[bucket]);

	lock_bucket_read( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->accountid.len == accountid.len &&
		memcmp(it->accountid.s,accountid.s,accountid.len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		unlock_bucket_read( entry->lock );
		return init_mi_tree( 401, "No such client", sizeof("No such client")-1);
	}

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==NULL) {
		unlock_bucket_read( entry->lock );
		return NULL;
	}

	rpl = &rpl_tree->node;
	node_ret = add_mi_node_child(rpl,0,MI_SSTR("RESULT"),MI_SSTR(""));

	while ((node = node->next) && (node->value.s && node->value.len)) {
		prefix = node->value;
		if (is_wholesale)
			ret = get_rate_price_prefix(it->ws_trie,&prefix,&matched_len);
		else
			ret = get_rate_price_prefix(it->rt_trie,&prefix,&matched_len);

		if (ret == NULL) {
			add_mi_node_child( node_ret, 0, MI_SSTR(""),MI_SSTR("[False]"));
		} else
			addf_mi_node_child( node_ret, 0, MI_SSTR(""),
				"[\"%.*s\",\"%.*s\",%f,%d,%d,\"%.*s\"]",matched_len,prefix.s,
				ret->destination.len,ret->destination.s,ret->price,
				ret->minimum,ret->increment,
				is_wholesale?it->ws_rate_currency.len:it->rt_rate_currency.len,
				is_wholesale?it->ws_rate_currency.s:it->rt_rate_currency.s);
	}

	unlock_bucket_read( entry->lock );
	return rpl_tree;

error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);

}

static struct mi_root * mi_reload_client(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node;
	int rate_id,is_wholesale,ret;
	str accountid;

	node = cmd_tree->node.kids;

	if (node==NULL || node->next==NULL || node->next->next==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len)
		goto error;

	accountid = node->value;

	node = node->next;
	if ( !node->value.s || !node->value.len || str2sint(&node->value,&is_wholesale)<0)
		goto error;

	node = node->next;
	if ( !node->value.s || !node->value.len || str2sint(&node->value,&rate_id)<0)
		goto error;

	LM_INFO("XXX - reloadClientRate %.*s %d %d\n",accountid.len,accountid.s,is_wholesale,rate_id);

	ret = reload_client_rate(&accountid,is_wholesale,rate_id,0);
	if (ret == -2)
		return init_mi_tree( 401, "No such client", sizeof("No such client")-1);
	else if (ret < 0)
		return init_mi_tree( 500, "Failed to reload", sizeof("Failed to reload")-1);
	else
		return init_mi_tree( 200, MI_SSTR(MI_OK));
error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
}

static struct mi_root * mi_reload_eu_client(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node;
	int rate_id,is_wholesale,eu_type,ret;
	str accountid;

	node = cmd_tree->node.kids;

	if (node==NULL || node->next==NULL || node->next->next==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len)
		goto error;

	accountid = node->value;

	node = node->next;
	if ( !node->value.s || !node->value.len || str2sint(&node->value,&is_wholesale)<0)
		goto error;

	node = node->next;
	if ( !node->value.s || !node->value.len || str2sint(&node->value,&eu_type)<0)
		goto error;

	node = node->next;
	if ( !node->value.s || !node->value.len || str2sint(&node->value,&rate_id)<0)
		goto error;

	LM_INFO("XXX - reloadEuClientRate %.*s %d %d %d\n",accountid.len,accountid.s,is_wholesale,eu_type,rate_id);

	ret = reload_eu_client_rate(&accountid,is_wholesale,eu_type,rate_id,0);
	if (ret == -2)
		return init_mi_tree( 401, "No such client", sizeof("No such client")-1);
	else if (ret < 0)
		return init_mi_tree( 500, "Failed to reload", sizeof("Failed to reload")-1);
	else
		return init_mi_tree( 200, MI_SSTR(MI_OK));
error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
}

static struct mi_root * mi_add_client(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node;
	str accountid;
	int rc;

	node = cmd_tree->node.kids;

	if (node==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len)
		goto error;

	accountid = node->value;

	LM_INFO("XXX - addClient %.*s\n",accountid.len,accountid.s);
	rc = add_client(&accountid,1);
	if (rc < 0)
		return init_mi_tree( 500, "Failed to add", sizeof("Failed to add")-1);
	else if (rc > 0)
		return init_mi_tree( 402, "Account exists", sizeof("Carrier exists")-1);
	else
		return init_mi_tree( 200, MI_SSTR(MI_OK));
error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
}

static struct mi_root * mi_delete_client(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node;
	str accountid;
	int bucket;
	struct account_entry* entry;
	struct account_cell* it;

	node = cmd_tree->node.kids;

	if (node==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len)
		goto error;

	accountid = node->value;

	LM_INFO("XXX - deleteClient %.*s\n",accountid.len,accountid.s);

	bucket = core_hash(&accountid,0,acc_table->size);
	entry = &(acc_table->entries[bucket]);

	lock_bucket_write( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->accountid.len == accountid.len &&
		memcmp(it->accountid.s,accountid.s,accountid.len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		LM_ERR("Client %.*s does not exist \n",accountid.len,accountid.s);
		unlock_bucket_write( entry->lock );
		return init_mi_tree( 401, "No such client", sizeof("No such client")-1);
	}

	/* unlink the client from the hash */
	if (it->next)
		it->next->prev = it->prev;
	else
		entry->last = it->prev;
	if (it->prev)
		it->prev->next = it->next;
	else
		entry->first = it->next;
	it->next = it->prev = 0;

	unlock_bucket_write( entry->lock );

	if (it->ws_rate_table.s)
		shm_free(it->ws_rate_table.s);
	if (it->rt_rate_table.s && it->rt_rate_table.s != it->ws_rate_table.s)
		shm_free(it->rt_rate_table.s);
	if (it->ws_rate_currency.s)
		shm_free(it->ws_rate_currency.s);
	if (it->rt_rate_currency.s && it->rt_rate_currency.s != it->ws_rate_currency.s)
		shm_free(it->rt_rate_currency.s);
	if (it->ws_trie)
		free_trie(it->ws_trie);
	if (it->rt_trie && it->rt_trie != it->ws_trie)
		free_trie(it->rt_trie);
	shm_free(it);

	return init_mi_tree( 200, MI_SSTR(MI_OK));
error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
}

static struct mi_root * mi_delete_client_rate(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node;
	str accountid;
	int bucket,wholesale;
	struct account_entry* entry;
	struct account_cell* it;

	node = cmd_tree->node.kids;

	if (node==NULL || node->next==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len)
		goto error;

	accountid = node->value;

	node = node->next;
	if ( !node->value.s || !node->value.len || str2sint(&node->value,&wholesale)<0)
		goto error;

	LM_INFO("XXX - deleteClientRate %.*s %d\n",accountid.len,accountid.s,wholesale);

	bucket = core_hash(&accountid,0,acc_table->size);
	entry = &(acc_table->entries[bucket]);

	lock_bucket_write( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->accountid.len == accountid.len &&
		memcmp(it->accountid.s,accountid.s,accountid.len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		LM_ERR("Client %.*s does not exist \n",accountid.len,accountid.s);
		unlock_bucket_write( entry->lock );
		return init_mi_tree( 401, "No such client", sizeof("No such client")-1);
	}

	if (wholesale) {
		it->ws_rateid = 0;
		if (it->ws_rate_table.s) {
			if (it->ws_rate_table.s != it->rt_rate_table.s) {
				shm_free(it->ws_rate_table.s);
			}
			it->ws_rate_table.s = NULL;
			it->ws_rate_table.len = 0;
		}

		if (it->ws_rate_currency.s) {
			if (it->ws_rate_currency.s != it->rt_rate_currency.s) {
				shm_free(it->ws_rate_currency.s);
			}
			it->ws_rate_currency.s = NULL;
			it->ws_rate_currency.len = 0;
		}
		if (it->ws_trie) {
			if (it->ws_trie != it->rt_trie)
				free_trie(it->ws_trie);
			it->ws_trie = NULL;
		}
	} else {
		it->rt_rateid = 0;
		if (it->rt_rate_table.s) {
			if (it->rt_rate_table.s != it->ws_rate_table.s) {
				shm_free(it->rt_rate_table.s);
			}
			it->rt_rate_table.s = NULL;
			it->rt_rate_table.len = 0;
		}

		if (it->rt_rate_currency.s) {
			if (it->rt_rate_currency.s != it->ws_rate_currency.s) {
				shm_free(it->rt_rate_currency.s);
			}
			it->rt_rate_currency.s = NULL;
			it->rt_rate_currency.len = 0;
		}
		if (it->rt_trie) {
			if (it->rt_trie != it->ws_trie)
				free_trie(it->rt_trie);
			it->rt_trie = NULL;
		}
	}

	unlock_bucket_write( entry->lock );
	return init_mi_tree( 200, MI_SSTR(MI_OK));
error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
}

static struct mi_root * mi_delete_eu_client_rate(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node;
	str accountid;
	int bucket,wholesale;
	struct account_entry* entry;
	struct account_cell* it;

	node = cmd_tree->node.kids;

	if (node==NULL || node->next==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len)
		goto error;

	accountid = node->value;

	node = node->next;
	if ( !node->value.s || !node->value.len || str2sint(&node->value,&wholesale)<0)
		goto error;

	LM_INFO("XXX - deleteEuClientRate %.*s %d\n",accountid.len,accountid.s,wholesale);

	bucket = core_hash(&accountid,0,acc_table->size);
	entry = &(acc_table->entries[bucket]);

	lock_bucket_write( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->accountid.len == accountid.len &&
		memcmp(it->accountid.s,accountid.s,accountid.len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		LM_ERR("Client %.*s does not exist \n",accountid.len,accountid.s);
		unlock_bucket_write( entry->lock );
		return init_mi_tree( 401, "No such client", sizeof("No such client")-1);
	}

	if (wholesale) {
		it->eu_ws_rateid = 0;
		if (it->eu_ws_rate_table.s) {
			if (it->eu_ws_rate_table.s != it->eu_rt_rate_table.s) {
				shm_free(it->eu_ws_rate_table.s);
			}
			it->eu_ws_rate_table.s = NULL;
			it->eu_ws_rate_table.len = 0;
		}

		if (it->eu_ws_rate_currency.s) {
			if (it->eu_ws_rate_currency.s != it->eu_rt_rate_currency.s) {
				shm_free(it->eu_ws_rate_currency.s);
			}
			it->eu_ws_rate_currency.s = NULL;
			it->eu_ws_rate_currency.len = 0;
		}
		if (it->eu_ws_ratesheet) {
			if (it->eu_ws_ratesheet != it->eu_rt_ratesheet) {
				if (it->eu_ws_rate_type == 0)
					free_trie((ptree_t*)it->eu_ws_ratesheet);
				else
					free_extended_hash((struct eu_extended_table *)it->eu_ws_ratesheet);
			}
			it->eu_ws_ratesheet = NULL;
		}
	} else {
		it->eu_rt_rateid = 0;
		if (it->eu_rt_rate_table.s) {
			if (it->eu_rt_rate_table.s != it->eu_ws_rate_table.s) {
				shm_free(it->eu_rt_rate_table.s);
			}
			it->eu_rt_rate_table.s = NULL;
			it->eu_rt_rate_table.len = 0;
		}

		if (it->eu_rt_rate_currency.s) {
			if (it->eu_rt_rate_currency.s != it->eu_ws_rate_currency.s) {
				shm_free(it->eu_rt_rate_currency.s);
			}
			it->eu_rt_rate_currency.s = NULL;
			it->eu_rt_rate_currency.len = 0;
		}
		if (it->eu_rt_ratesheet) {
			if (it->eu_rt_ratesheet != it->eu_ws_ratesheet) {
				if (it->eu_rt_rate_type == 0)
					free_trie((ptree_t*)it->eu_rt_ratesheet);
				else
					free_extended_hash((struct eu_extended_table *)it->eu_rt_ratesheet);
			}
			it->eu_rt_ratesheet = NULL;
		}
	}

	unlock_bucket_write( entry->lock );
	return init_mi_tree( 200, MI_SSTR(MI_OK));
error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
}

static int fixup_cost_based_routing(void** param, int param_no)
{
	return fixup_sgp(param);
}

static char* cost_based_routing(str *clientid,int isws,int iseu,
	str *carrierlist,int carr_no,str *ani,str *dnis,double *profit_margin) 
{
	int bucket,rc,i;
	char *result;
	struct account_entry *entry;
	struct account_cell *it;
	struct eu_rate_lookup_rpl eu_ret; 
	struct ratesheet_cell_entry *ret;
	unsigned int dst_matched_len,src_matched_len;
	double client_price,vendor_price;
	str carrier;
	struct carrier_cell *carr_it;
	struct carrier_entry *carr_entry;
	
	bucket = core_hash(clientid,0,acc_table->size);
	entry = &(acc_table->entries[bucket]);

	lock_bucket_read( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->accountid.len == clientid->len &&
		memcmp(it->accountid.s,clientid->s,clientid->len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		unlock_bucket_read( entry->lock );
		return NULL;
	}

	if (iseu) {
		eu_ret.regular = NULL;
		eu_ret.ani_based = NULL;
		dst_matched_len = 0;
		src_matched_len = 0;

		if (isws) {
			rc = get_eu_rate_price_prefix(it->eu_ws_ratesheet,it->ws_trie,it->eu_ws_rate_type,ani,dnis,&dst_matched_len,&src_matched_len,&eu_ret);
		} else {
			rc = get_eu_rate_price_prefix(it->eu_rt_ratesheet,it->rt_trie,it->eu_rt_rate_type,ani,dnis,&dst_matched_len,&src_matched_len,&eu_ret);
		}

		if (rc < 0)
			goto eu_fallback;
		if (eu_ret.ani_based == NULL) {
			client_price = eu_ret.regular->price;
		} else {
			client_price = eu_ret.ani_based->price;
		}

		/* found our price, fall through to carrier lookup */
	} else {
eu_fallback:
		if (isws) {
			ret = get_rate_price_prefix(it->ws_trie,dnis,&dst_matched_len);
		} else {
			ret = get_rate_price_prefix(it->rt_trie,dnis,&dst_matched_len);
		}

		if (ret == NULL) {
			LM_ERR("Failed to get client price \n");
			unlock_bucket_read( entry->lock );
			return NULL;
		}

		client_price = ret->price;
	} 

	unlock_bucket_read( entry->lock );
	LM_INFO("Client price is %f\n",client_price);

	result = (char *)pkg_malloc(carr_no);
	if (result == NULL) {
		LM_ERR("No more mem \n");
		return NULL;
	}
	memset(result,0,carr_no);

	for (i=0;i<carr_no;i++) {
		carrier = carrierlist[i];

		bucket = core_hash(&carrier,0,carr_table->size);
		carr_entry = &(carr_table->entries[bucket]);

		lock_bucket_read( carr_entry->lock );
		for (carr_it=carr_entry->first;carr_it;carr_it=carr_it->next) {
			if (carr_it->carrierid.len == carrier.len &&
			memcmp(carr_it->carrierid.s,carrier.s,carrier.len) == 0) {
				break;
			}
		}

		if (carr_it == NULL) {
			unlock_bucket_read( carr_entry->lock );
			/* we did not find the carrier - do not use it */
			result[i] = 0;
			continue;
		}

		eu_ret.regular = NULL;
		eu_ret.ani_based = NULL;

		if (iseu) {
			if (get_eu_rate_price_prefix(carr_it->eu_ratesheet,carr_it->trie,
			carr_it->eu_type,ani,dnis,&dst_matched_len,&src_matched_len,&eu_ret) < 0)
				goto carr_eu_fallback;

			if (eu_ret.ani_based == NULL) {
				vendor_price = eu_ret.regular->price;
			} else {
				vendor_price = eu_ret.ani_based->price;
			}

			/* found our price, fall through to price comparison */
		} else {
carr_eu_fallback:
			ret = get_rate_price_prefix(carr_it->trie,dnis,&dst_matched_len);
			if (ret == NULL) {
				/* no price found for carrier, do not use it */
				unlock_bucket_read( carr_entry->lock );
				result[i] = 0;
				continue;
			}

			vendor_price = ret->price;
		}

		LM_INFO("Vendor %.*s price is %f\n",carrier.len,carrier.s,vendor_price);
		
		unlock_bucket_read( carr_entry->lock );

		if (((client_price / vendor_price)*100-100) >= *profit_margin)
			result[i] = 1;
		else
			result[i] = 0;

		LM_INFO("%d\n",result[i]);
	}

	return result;
}

static int script_cost_based_routing(struct sip_msg *msg, char *s_clientid, char *s_isws, char *s_iseu, 
		char *s_carrierlist,char *s_ani,char *s_dnis)
{
	str clientid = {0,0};
	int isws=0,iseu=0,i;
        str carrierlist = {0,0};
        str ani = {0,0};
        str dnis = {0,0};
	char *tmp=NULL,*token=NULL,*nts_carrierlist=NULL,*result=NULL,*avp_result=NULL;
	str carrier_array[100];
	int carrier_array_len=0;
	int_str val;
	str profit_margin_s;
	double profit_margin;

        if (fixup_get_svalue(msg, (gparam_p)s_clientid, &clientid) != 0) {
                LM_ERR("failed to extract clientid\n");
                return -1;
        }

        if (fixup_get_ivalue(msg, (gparam_p)s_isws, &isws) != 0) {
                LM_ERR("failed to isws\n");
                return -1;
        }

        if (fixup_get_ivalue(msg, (gparam_p)s_iseu, &iseu) != 0) {
                LM_ERR("failed to iseu\n");
                return -1;
        }

        if (fixup_get_svalue(msg, (gparam_p)s_carrierlist, &carrierlist) != 0) {
                LM_ERR("failed to extract carrierlist\n");
                return -1;
        }

        if (fixup_get_svalue(msg, (gparam_p)s_ani, &ani) != 0) {
                LM_ERR("failed to extract ani\n");
                return -1;
        }

        if (fixup_get_svalue(msg, (gparam_p)s_dnis, &dnis) != 0) {
                LM_ERR("failed to extract dnis\n");
                return -1;
        }

	if (search_first_avp(0, rc_profit_margin_avp, &val, 0)
	&& val.s.len > 0) {
		profit_margin_s.s = pkg_malloc(val.s.len+1);
		if (!profit_margin_s.s) {
			LM_ERR("No more pkg\n");
			return -1;
		}

		memcpy(profit_margin_s.s,val.s.s,val.s.len);
		profit_margin_s.s[val.s.len] = 0;
		
		profit_margin = atof(profit_margin_s.s);
		pkg_free(profit_margin_s.s);
	} else 
		profit_margin = 0;

	nts_carrierlist = (char *)pkg_malloc(carrierlist.len+1);
	if (nts_carrierlist == NULL) {
		LM_ERR("Failed to alloc mem\n");
		return -1;
	}
	memcpy(nts_carrierlist,carrierlist.s,carrierlist.len);
	nts_carrierlist[carrierlist.len]=0;

	for (token = strtok_r(nts_carrierlist, ",", &tmp);
	token;
	token = strtok_r(NULL, ",", &tmp))
	{
		carrier_array[carrier_array_len].len = strlen(token);
		carrier_array[carrier_array_len].s = pkg_malloc(carrier_array[carrier_array_len].len);
		if (carrier_array[carrier_array_len].s == NULL) {
			LM_ERR("Failed to alloc mem\n");
			return -1;
		}
		
		memcpy(carrier_array[carrier_array_len].s,token,carrier_array[carrier_array_len].len);
		carrier_array_len++;
	}

	result = cost_based_routing(&clientid,isws,iseu,carrier_array,carrier_array_len,&ani,&dnis,&profit_margin);
	if (result == NULL) {
		LM_ERR("Failed to do CBR\n");
		goto err_free;
	}

	destroy_avps( 0, rc_reply_avp, 1);	
	avp_result = (char *)pkg_malloc(2*carrier_array_len);
	if (!avp_result) 
		goto err_free;

	memset(avp_result,0,2*carrier_array_len);
	for (i=0,tmp=avp_result;i<carrier_array_len;i++) {
		if (i == 0) {
			*tmp++ = result[i] + '0';
		} else {
			*tmp++ = ',';
			*tmp++ = result[i] + '0';
		}
	}

	val.s.s = avp_result;
	val.s.len = strlen(avp_result);

	if (add_avp_last( AVP_VAL_STR, rc_reply_avp, val)!=0 ) {
		LM_ERR("failed to insert ruri avp\n");
		goto err_free;
	}

	if (result)
		pkg_free(result);
	if (avp_result)
		pkg_free(avp_result);
	for (i=0;i<carrier_array_len;i++)
		pkg_free(carrier_array[i].s);
	
	return 1;

err_free:
	if (result)
		pkg_free(result);
	if (avp_result)
		pkg_free(avp_result);
	for (i=0;i<carrier_array_len;i++)
		pkg_free(carrier_array[i].s);

	return -1;
}
