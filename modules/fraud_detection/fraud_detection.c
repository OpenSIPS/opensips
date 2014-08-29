#include "../../ut.h"
#include "../../db/db.h"
#include "../../time_rec.h"
#include "../drouting/dr_api.h"

#include "frd_stats.h"


#define FRD_PID_COL                   "profileid"
#define FRD_PREFIX_COL                "prefix"
#define FRD_START_H_COL               "start_hour"
#define FRD_END_H_COL                 "end_hour"
#define FRD_DAYS_COL                  "daysoftheweek"
#define FRD_CPM_THRESH_WARN_COL       "cpm_warning"
#define FRD_CPM_THRESH_CRIT_COL       "cpm_critical"
#define FRD_CALLDUR_THRESH_WARN_COL   "call_duration_warning"
#define FRD_CALLDUR_THRESH_CRIT_COL   "call_duration_critical"
#define FRD_TOTALC_THRESH_WARN_COL    "total_calls_warning"
#define FRD_TOTALC_THRESH_CRIT_COL    "total_calls_critical"
#define FRD_CONCALLS_THRESH_WARN_COL  "concurrent_calls_warning"
#define FRD_CONCALLS_THRESH_CRIT_COL  "concurrent_calls_critical"
#define FRD_SEQCALLS_THRESH_WARN_COL  "sequential_calls_warning"
#define FRD_SEQCALLS_THRESH_CRIT_COL  "sequential_calls_critical"


static str db_url;
static str table_name = str_init("fraud_detection");

static str pid_col = str_init(FRD_PID_COL);
static str prefix_col = str_init(FRD_PREFIX_COL);
static str start_h_col = str_init(FRD_START_H_COL);
static str end_h_col = str_init(FRD_END_H_COL);
static str days_col = str_init(FRD_DAYS_COL);
static str cpm_thresh_warn_col = str_init(FRD_CPM_THRESH_WARN_COL);
static str cpm_thresh_crit_col = str_init(FRD_CPM_THRESH_CRIT_COL);
static str calldur_thresh_warn_col = str_init(FRD_CALLDUR_THRESH_WARN_COL);
static str calldur_thresh_crit_col = str_init(FRD_CALLDUR_THRESH_CRIT_COL);
static str totalc_thresh_warn_col = str_init(FRD_TOTALC_THRESH_WARN_COL);
static str totalc_thresh_crit_col = str_init(FRD_TOTALC_THRESH_CRIT_COL);
static str concalls_thresh_warn_col = str_init(FRD_CONCALLS_THRESH_WARN_COL);
static str concalls_thresh_crit_col = str_init(FRD_CONCALLS_THRESH_CRIT_COL);
static str seqcalls_thresh_warn_col = str_init(FRD_SEQCALLS_THRESH_WARN_COL);
static str seqcalls_thresh_crit_col = str_init(FRD_SEQCALLS_THRESH_CRIT_COL);

static int mod_init(void);
static int child_init(int);
static void destroy(void);


static db_func_t db_funcs;
static db_con_t *db_con;

static cmd_export_t cmds[]={
/*	{"get_mapping",(cmd_function)get_mapping,1,fixup_pvar_null,
		0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"get_mapping",(cmd_function)get_mapping0,0,0,
		0, REQUEST_ROUTE|ONREPLY_ROUTE},*/
	{0,0,0,0,0,0}
};

static param_export_t params[]={
	{"db_url",                      STR_PARAM, &db_url.s},
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


/** module exports */
struct module_exports exports= {
	"fraud_detection",               /* module name */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
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

static inline tmrec_t* parse_time_def(char *time_str)
{
	tmrec_p time_rec;
	char *p,*s;

	p = time_str;
	time_rec = 0;

	/*	time_rec = (tmrec_t*)shm_malloc(sizeof(tmrec_t)); */
	time_rec = tmrec_new(SHM_ALLOC);
	if (time_rec==0) {
		LM_ERR("no more shm mem\n");
		goto error;
	}
	/*	memset( time_rec, 0, sizeof(tmrec_t)); */

	/* empty definition? */
	if ( time_str==0 || *time_str==0 )
		goto done;

	load_TR_value( p, s, time_rec, tr_parse_dtstart, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_duration, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_freq, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_until, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_interval, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_byday, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_bymday, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_byyday, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_byweekno, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_bymonth, parse_error, done);

	/* success */
done:
	return time_rec;
parse_error:
	LM_ERR("parse error in <%s> around position %i\n",
			time_str, (int)(long)(p-time_str));
error:
	if (time_rec)
		tmrec_free( time_rec );
	return 0;
}

static int mod_init(void)
{
	LM_INFO("Initializing module\n");
	if (db_url.s) {
		db_url.len = strlen(db_url.s);
		LM_INFO("We have db_url = %.*s\n",db_url.len,db_url.s);

		/* Find a database module */
		if (db_bind_mod(&db_url, &db_funcs) < 0){
			LM_ERR("Unable to bind to a database driver\n");
			return -1;
		}

		/* open a test connection */
		if ((db_con = db_funcs.init(&db_url)) == 0) {
			LM_ERR("cannot init connection to DB\n");
			return -1;
		}

		db_funcs.close(db_con);
		db_con = 0;
	}

	struct dr_binds drb;
	if (load_dr_api(&drb) != 0) {
		LM_ERR("Cannot load dr_api\n");
		return -1;
	}

	dr_head_p dr_head = drb.create_head();

	if (dr_head == NULL) {
		LM_ERR("Cannot create dr_head\n");
		return -1;
	}

	init_stats_table();
	str users[] = {str_init("andrei"), str_init("john")};
	str prefixes[] = {str_init("074"), str_init("0722"), str_init("0767"), str_init("0744")};

	int i, j;
	for (i = 0; i < 2; ++i)
		for (j = 0; j < 4; ++j) {
			frd_stats_entry_t *entry = get_stats(users[i], prefixes[j]);
			entry->stats.total_calls += i * 4 + j;
		}

	for (i = 0; i < 2; ++i)
		for (j = 0; j < 4; ++j) {
			frd_stats_entry_t *entry = get_stats(users[i], prefixes[j]);
			LM_INFO("%d %d %d\n", entry->stats.cps, entry->stats.total_calls, entry->stats.concurrent_calls);
		}

	free_stats_table();

	drb.free_head(dr_head);
	return 0;
}

static int child_init(int rank)
{
	LM_INFO("Initializing child\n");
	if (db_url.s) {
		/* open a test connection */
		if ((db_con = db_funcs.init(&db_url)) == 0) {
			LM_ERR("cannot init connection to DB\n");
			return -1;
		}
	}
	return 0;
}

/*
 * destroy function
 */
static void destroy(void)
{
	LM_INFO("Destroying module\n");

	if (db_url.s)
		db_funcs.close(db_con);
}
