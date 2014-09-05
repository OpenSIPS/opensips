#include "../../ut.h"
#include "../../db/db.h"
#include "../../time_rec.h"
#include "../drouting/dr_api.h"

#include "frd_stats.h"
#include "frd_load.h"

extern str db_url;
extern str table_name;

extern str rid_col;
extern str pid_col;
extern str prefix_col;
extern str start_h_col;
extern str end_h_col;
extern str days_col;
extern str cpm_thresh_warn_col;
extern str cpm_thresh_crit_col;
extern str calldur_thresh_warn_col;
extern str calldur_thresh_crit_col;
extern str totalc_thresh_warn_col;
extern str totalc_thresh_crit_col;
extern str concalls_thresh_warn_col;
extern str concalls_thresh_crit_col;
extern str seqcalls_thresh_warn_col;
extern str seqcalls_thresh_crit_col;


dr_head_p dr_head;
struct dr_binds drb;
rw_lock_t *frd_data_lock;


static int mod_init(void);
static int child_init(int);
static void destroy(void);


static cmd_export_t cmds[]={
/*	{"get_mapping",(cmd_function)get_mapping,1,fixup_pvar_null,
		0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"get_mapping",(cmd_function)get_mapping0,0,0,
		0, REQUEST_ROUTE|ONREPLY_ROUTE},*/
	{0,0,0,0,0,0}
};

static param_export_t params[]={
	{"db_url",                      STR_PARAM, &db_url.s},
	{"table_name",                  STR_PARAM, &table_name.s},
	{"rid_col",                     STR_PARAM, &rid_col.s},
	{"pid_col",                     STR_PARAM, &pid_col.s},
	{"prefix_col",                  STR_PARAM, &prefix_col.s},
	{"start_h_col",                 STR_PARAM, &start_h_col.s},
	{"end_h_col",                   STR_PARAM, &end_h_col.s},
	{"days_col",                    STR_PARAM, &days_col.s},
	{"cpm_thresh_warn_col",         STR_PARAM, &cpm_thresh_warn_col.s},
	{"cpm_thresh_crit_col",         STR_PARAM, &cpm_thresh_crit_col.s},
	{"calldur_thresh_warn_col",     STR_PARAM, &calldur_thresh_warn_col.s},
	{"calldur_thresh_crit_col",     STR_PARAM, &calldur_thresh_crit_col.s},
	{"totalc_thresh_warn_col",      STR_PARAM, &totalc_thresh_warn_col.s},
	{"totalc_thresh_crit_col",      STR_PARAM, &totalc_thresh_crit_col.s},
	{"concalls_thresh_warn_col",    STR_PARAM, &concalls_thresh_warn_col.s},
	{"concalls_thresh_crit_col",    STR_PARAM, &concalls_thresh_crit_col.s},
	{"seqcalls_thresh_warn_col",    STR_PARAM, &seqcalls_thresh_warn_col.s},
	{"seqcalls_thresh_crit_col",    STR_PARAM, &seqcalls_thresh_crit_col.s},
	{0,0,0}
};

static mi_export_t mi_cmds[] = {
	//{ "get_maps","return all mappings",mi_get_maps,MI_NO_INPUT_FLAG,0,0},
	{0,0,0,0,0,0}
};

static dep_export_t deps = {
	{
		{MOD_TYPE_SQLDB, NULL, DEP_ABORT},
		{MOD_TYPE_DEFAULT, "drouting", DEP_ABORT},
		{MOD_TYPE_NULL, NULL, 0},
	},
	{
		{NULL, NULL},
	},
};

/** module exports */
struct module_exports exports= {
	"fraud_detection",               /* module name */
	MOD_TYPE_DEFAULT,
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	&deps,
	cmds,                       /* exported functions */
	params,                     /* exported parameters */
	0,                          /* exported statistics */
	mi_cmds,                    /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,                          /* extra processes */
	mod_init,                   /* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function)destroy,  /* destroy function */
	child_init                  /* per-child init function */
};


static void set_lengths(void)
{
	db_url.len = strlen(db_url.s);
	table_name.len = strlen(table_name.s);
	rid_col.len = strlen(rid_col.s);
	pid_col.len = strlen(pid_col.s);
	prefix_col.len = strlen(prefix_col.s);
	start_h_col.len = strlen(start_h_col.s);
	end_h_col.len = strlen(end_h_col.s);
	days_col.len = strlen(days_col.s);
	cpm_thresh_warn_col.len = strlen(cpm_thresh_warn_col.s);
	cpm_thresh_crit_col.len = strlen(cpm_thresh_crit_col.s);
	calldur_thresh_warn_col.len = strlen(calldur_thresh_warn_col.s);
	calldur_thresh_crit_col.len = strlen(calldur_thresh_crit_col.s);
	totalc_thresh_warn_col.len = strlen(totalc_thresh_warn_col.s);
	totalc_thresh_crit_col.len = strlen(totalc_thresh_crit_col.s);
	concalls_thresh_warn_col.len = strlen(concalls_thresh_warn_col.s);
	concalls_thresh_crit_col.len = strlen(concalls_thresh_crit_col.s);
	seqcalls_thresh_warn_col.len = strlen(seqcalls_thresh_warn_col.s);
	seqcalls_thresh_crit_col.len = strlen(seqcalls_thresh_crit_col.s);
}

static int mod_init(void)
{
	LM_INFO("Initializing module\n");

	if ((frd_data_lock = lock_init_rw()) == NULL) {
		LM_CRIT("failed to init reader/writer lock\n");
		return -1;
	}

	set_lengths();

	if (load_dr_api(&drb) != 0) {
		LM_ERR("Cannot load dr_api\n");
		return -1;
	}

	frd_init_db();
	frd_reload_data();

	str number = str_init("0754565");
	rt_info_t *test = drb.match_number(dr_head, 1, &number);

	if (test) {
		frd_thresholds_t *thr = (frd_thresholds_t*)test->attrs.s;

		LM_INFO("xxx - <%u> matched: %d %d %d %d %d\n", test->id, thr->cpm_thr.warning,
				thr->call_duration_thr.critical, thr->total_calls_thr.warning,
				thr->concurrent_calls_thr.critical, thr->seq_calls_thr.warning);
	}
	else
		LM_INFO("no match\n");

	return 0;
}

static int child_init(int rank)
{
	return 0;
}

/*
 * destroy function
 */
static void destroy(void)
{
	LM_INFO("Destroying module\n");
}
