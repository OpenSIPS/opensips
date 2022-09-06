/*
 * Copyright (C) 2022 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include "dprint.h"
#include "locking.h"
#include "rw_locking.h"
#include "str.h"
#include "ut.h"
#include "evi/evi.h"
#include "mi/fmt.h"
#include "status_report.h"

struct report_rec {
	str log;
	time_t ts;
};

/* Implementation details
 * The list of group is static, groups are to be registered only at startup and
 * it does not change at runtime; so it is safe to grap and hold referances
 * to groups (as they will not change or be deleted).
 * The list of identifiers under a group may change; identifiers may be added
 * or deleted at runtime; so, the framework does not expose any reference to
 * the identifiers. The identifiers will be looked up each time.
 * Both types of lists are protected by a RW lock. WRITE is used only when the
 * lists are to changed as elements (adding / removing), otherwise READ is
 * used.
 * For changes within an identity (like changing status or reports), the
 * per-identity lock is used.
 */

typedef struct _sr_identifier {
	/* name of the indentifier, allocated in the same mem chunk */
	str name;
	/* some text detailing / explaining the reason (usually for "KO" reason)
	 * allocated as a separated mem chunk, to be freed
	 * it is optional*/
	str status_txt;
	/* value of the status "> 0" ok; "< 0" not ok ; 0 not allowed */
	short status;
	/* size of the "reports" array, pre-allocated */
	short max_reports;
	/* indexes of first and last used reports
	 * starts as -1/-1 meaning no report at all */
	short first_report;
	short last_report;
	/* lock for protexting access to "status" and "reports" */
	gen_lock_t lock;
	/* array of max_reports reports, allocated in the same mem chunk */
	struct report_rec *reports;
	/* next identifier in the group */
	struct _sr_identifier *next;
} sr_identifier;


typedef struct _sr_group {
	/* name of the group, the buffer is allocated in the same mem chunk */
	str name;
	/* if public, no script or external function (like MI) will be allowed
	 * to change the status or report here */
	int is_public;
	/* identifiers as a simple linked list (the list SHOULD not be empty) */
	sr_identifier *identifiers;
	/* link to the next group (simple linked list) */
	struct _sr_group *next;
} sr_group;


/* lock to protect the list of sr_groups and changes on their field */
static rw_lock_t *sr_lock = NULL;

/* global list of 'status_report' groups */
static sr_group *sr_groups = NULL;

/* name to be used as default (or nameless) identifier */
static str main_identifier = str_init("main");

/* event to be raised when the status of an identifier changed */
static str sr_event = str_init("E_CORE_SR_STATUS_CHANGED");
static event_id_t sr_evi_id;

/* the SR group of the core */
static sr_group *srg_core = NULL;
static sr_identifier *sri_core = NULL;


/****************** Internal functions  **********************/

/* Allocates, initializes and links a new group.
 * NOTE 1 - is expects the sr_lock to be already taken !!
 */
static sr_group* _create_new_group(str *name)
{
	sr_group *srg;

	LM_DBG("adding new group [%.*s]\n", name->len, name->s);

	srg=(sr_group*)shm_malloc( sizeof(sr_group) + name->len );
	if ( srg==NULL ) {
		LM_ERR("shm allocing for a new group failed\n");
		return NULL;
	}

	memset( srg, 0,  sizeof(sr_group));

	/* set the name*/
	srg->name.s = (char*)(srg+1);
	srg->name.len = name->len;
	memcpy( srg->name.s, name->s, name->len );

	/* link it first */
	srg->next = sr_groups;
	sr_groups = srg;

	return srg;
}


/* Searches a SR group by its name and returns the pointer to it
 * NOTE 1: the function assumes that the sr lock is already taken !!
 */
static sr_group* _get_group_by_name(str *name)
{
	sr_group *srg;

	/* locate the group */
	for ( srg=sr_groups ; srg ; srg=srg->next ) {
		if ( (srg->name.len == name->len) &&
		strncasecmp( srg->name.s, name->s, name->len)==0 )
			return srg;
	}

	return NULL;
}


/* Searches a SR identifier by its group and name and returns the pointer to it
 * NOTE 1: the function assumes that the sr lock is already taken !!
 */
static sr_identifier* _get_identifier_by_name(sr_group *srg, str *id_name)
{
	sr_identifier *sri;

	for( sri=srg->identifiers ; sri ; sri=sri->next )
		if (sri->name.len==id_name->len && 
		strncasecmp( sri->name.s, id_name->s, id_name->len)==0)
			return sri;

	return NULL;
}



/****************** Module (to be used) functions  **********************/

/* Registers a new SR group by its name
 * To be done at startup only
 * The modules should typically use their names as groups
 */
void *sr_register_group( char* name_s, int name_len, int is_public)
{
	sr_group *srg = NULL;
	str name = {name_s, name_len};

	lock_start_write( sr_lock );

	/* locate the group, for duplicates */
	srg = _get_group_by_name(&name);
	if (srg) {
		LM_ERR("duplicated group already existing [%.*s]\n",
			name.len, name.s);
		srg = NULL;
	} else {
		srg = _create_new_group( &name );
		if ( srg==NULL ) {
			LM_ERR("failed to register group [%.*s]\n",
				name.len, name.s);
		}
		srg->is_public = is_public;
	}

	lock_stop_write( sr_lock );

	return srg;
}


/* Search a SR group by name and and returns its pointer
 */
void *sr_get_group_by_name(  char *name_s, int name_len)
{
	sr_group *srg = NULL;
	str name = {name_s, name_len};

	lock_start_read( sr_lock );

	/* locate the group, for duplicates */
	srg = _get_group_by_name( &name );

	lock_stop_read( sr_lock );

	return srg;
}


/* Registers a new SR identifier into a existing group.
 * - The group is mandatory
 * - The identifier name is optional; if missing, the default one (per entire
 *   group) will be used.
 * - The initial status of the identity; 0 is not accepted, it will be
 *   converted to 1
 * - The status text / details - optional string to detail the status code
 * - The max_reports defines how many logs should be kept (last logs) for the
 *   identifier; if 0, no logs/reports will be stored.
 */
int sr_register_identifier( void *group, 
		char *identifier_s, int identifier_len,
		int init_status, char *status_txt_s, int status_txt_len,
		int max_reports)
{
	sr_group *srg = (sr_group*)group;
	str identifier = {identifier_s, identifier_len};
	char *err_txt = "";
	sr_identifier *sri = NULL;


	if (identifier.s==NULL)
		identifier = main_identifier;

	LM_DBG("adding new identifier [%.*s] to group [%.*s]\n",
		identifier.len, identifier.s, srg->name.len, srg->name.s);

	lock_start_write( sr_lock );

	/* double check if we already have such identifier, just to be sure */
	sri = _get_identifier_by_name( srg, &identifier);
	if (sri) {
		err_txt = "add identifier (already existing)";
		sri = NULL; /* just to avoid its freeing on error handling */
		goto error;
	}

	/* allocate a new identifier */
	sri = (sr_identifier*)shm_malloc( sizeof(sr_identifier) + identifier.len
		+ max_reports*sizeof(struct report_rec) );
	if (sri==NULL) {
		err_txt = "shm allocate new identifier";
		goto error;
	}
	memset(sri, 0, sizeof(sr_identifier) + identifier.len
		+ max_reports*sizeof(struct report_rec) );

	/* initialize the new identifier */
	sri->reports = (struct report_rec*)(sri+1);
	sri->name.s = (char*)(sri->reports + max_reports);
	sri->name.len = identifier.len;
	memcpy( sri->name.s, identifier.s, identifier.len);

	sri->status = (init_status==0) ? 1: init_status;
	if (status_txt_s) {
		sri->status_txt.s = shm_malloc(status_txt_len);
		if (sri->status_txt.s) {
			memcpy( sri->status_txt.s, status_txt_s, status_txt_len);
			sri->status_txt.len = status_txt_len;
		} else
			sri->status_txt.len = 0;
	}

	if (max_reports==0)
		sri->reports = NULL;
	sri->max_reports = max_reports;
	sri->first_report = sri->last_report = -1;

	if (lock_init(&sri->lock)==NULL) {
		err_txt = "init identifier's lock";
		goto error;
	}

	/* add the new identifier to the group */
	sri->next = srg->identifiers;
	srg->identifiers = sri;

	lock_stop_write( sr_lock );

	return 0;

error:
	if (sri)
		shm_free(sri);
	lock_stop_write( sr_lock );
	LM_ERR("failed to %s when registering the [%.*s] identifier "
		"in [%.*s] group\n", err_txt, identifier.len, identifier.s,
		srg->name.len, srg->name.s);
	return -1;
}


/* Just a simple bundle of register_group and register_identifier for
 * cases where you need to register both in a single shot
 */
void* sr_register_group_with_identifier( char *group_s, int group_len,
		int grp_is_public,
		char *identifier_s, int identifier_len,
		int init_status, char *status_txt_s, int status_txt_len,
		int max_reports)
{
	void *srg;

	if ( (srg=sr_register_group( group_s, group_len, grp_is_public))<0 ) {
		LM_ERR("failed to register 'status_report' group [%.*s]\n",
			group_len, group_s);
		return NULL;
	}
	if (sr_register_identifier( srg, identifier_s, identifier_len,
	init_status, status_txt_s, status_txt_len, max_reports)<0 ) {
		LM_ERR("Failed to create 'core' group and identifier\n'\n");
		return NULL;
	}

	return srg;
}


/* Unregisters / removes an identifier from its group
 */
int sr_unregister_identifier( void *group,
		char *identifier_s, int identifier_len)
{
	sr_group *srg = (sr_group*)group;
	str identifier = {identifier_s, identifier_len};
	sr_identifier *sri, *prev_sri;
	int i;

	if (identifier.s==NULL)
		identifier = main_identifier;

	/* search for the identifier, but remember
	 * the prev as group and identifier as we will have to unlink it */
	lock_start_write( sr_lock );

	/* locate the identifier */
	for (sri=srg->identifiers, prev_sri=NULL ; sri ;
	prev_sri=sri,sri=sri->next ) {
		if ( sri->name.len==identifier.len &&
		strncasecmp( sri->name.s, identifier.s, identifier.len)==0 ) {
			LM_DBG("identity [%.*s] found in group [%.*s] , removing...\n",
				sri->name.len, sri->name.s,
				srg->name.len, srg->name.s);
			/* we found the identifier, first remove it from the 
			 * list of identifiers within the group */
			if (prev_sri)
				prev_sri->next = sri->next;
			else
				srg->identifiers = sri->next;

			/* purge the identity - it is safe to remove it as we have
			 * the WRITE access to the lists, so no one else may have 
			 * a referece to the identity */
			for( i=0 ; i<sri->max_reports ; i++ )
				if (sri->reports[i].log.s)
					shm_free(sri->reports[i].log.s);
			if (sri->status_txt.s)
				shm_free(sri->status_txt.s);
			shm_free( sri );

			/* done */
			lock_stop_write( sr_lock );
			return 0;
		}
	}

	/* not found */
	LM_BUG("asking to remove an identity which was not found\n");
	lock_stop_write( sr_lock );
	return -1;
}

/* event parameters */
static str evi_group_str = str_init("group");
static str evi_identifier_str = str_init("identifier");
static str evi_status_str = str_init("status");
static str evi_details_str = str_init("details");
static str evi_old_status_str = str_init("old_status");


/* Sets a new status for an existing identifier (within a group).
 * - The "group" must a pointer to a registered SR group, mandatory
 * - The "identifier" name is optional if this is a default (per entire group
 *    identifier).
 * - Optionally a status text/detail may be provided (set status_txt_s NULL
 *    to avoid using it)
 * - Set "is_public" if this operation was triggered from script or external
      sources (like MI). If the identity does not accept public ops, this
 *    operation will be forbidden.
 */
int sr_set_status( void *group,
		char *identifier_s, int identifier_len,
		int status, char *status_txt_s, int status_txt_len,
		int is_public)
{
	sr_group *srg = (sr_group*)group;
	str identifier = {identifier_s, identifier_len};
	sr_identifier *sri;
	evi_params_p list = NULL;
	int old_status;
	str s;

	if (identifier.s==NULL)
		identifier = main_identifier;

	if ( (is_public) ^ (srg->is_public) ) {
		LM_ERR("forbidden setting status for identifier [%.*s] group [%.*s]\n",
			identifier.len, identifier.s, srg->name.len, srg->name.s);
		return -1;
	}

	lock_start_read( sr_lock );

	sri = _get_identifier_by_name( srg, &identifier);
	if (sri==NULL) {
		lock_stop_read( sr_lock );
		LM_ERR("setting status for unknow identifier [%.*s] group [%.*s]\n",
			identifier.len, identifier.s, srg->name.len, srg->name.s);
		return -1;
	}

	/* we do no accept 0 status values, as we cannot return 0 to script */
	if (status==0)
		status = 1;

	lock_get( &sri->lock );
	old_status = sri->status;
	sri->status = status;
	if (sri->status_txt.s) shm_free(sri->status_txt.s);
	if (status_txt_s) {
		sri->status_txt.s = shm_malloc(status_txt_len);
		if (sri->status_txt.s) {
			memcpy( sri->status_txt.s, status_txt_s, status_txt_len);
			sri->status_txt.len = status_txt_len;
		} else
			sri->status_txt.len = 0;
	} else {
		sri->status_txt.s = NULL;
		sri->status_txt.len = 0;
	}
	lock_release( &sri->lock );

	/* raise event if status changed */
	if (old_status != status && evi_probe_event(sr_evi_id)) {
		if (!(list = evi_get_params()))
			goto done;
		if (evi_param_add_str( list, &evi_group_str, &srg->name)) {
			LM_ERR("unable to add group EVI parameter\n");
			evi_free_params(list);
			goto done;
		}
		if (evi_param_add_str( list, &evi_identifier_str, &sri->name)) {
			LM_ERR("unable to add identifier EVI parameter\n");
			evi_free_params(list);
			goto done;
		}
		if (evi_param_add_int( list, &evi_status_str, &status)) {
			LM_ERR("unable to add status EVI parameter\n");
			evi_free_params(list);
			goto done;
		}
		if (status_txt_s) {
			s.s = status_txt_s;
			s.len = status_txt_len;
			if (evi_param_add_str( list, &evi_details_str, &s)) {
				LM_ERR("unable to add identifier parameter\n");
				evi_free_params(list);
				goto done;
			}
		}
		if (evi_param_add_int( list, &evi_old_status_str, &old_status)) {
			LM_ERR("unable to add old_status EVI parameter\n");
			evi_free_params(list);
			goto done;
		}

		if (evi_raise_event( sr_evi_id, list)) {
			LM_ERR("unable to raise status_changed event\n");
		}

	}

	lock_stop_read( sr_lock );

done:
	return 0;
}


/* Adds a new report log to an identifier.
 * - The "group" must a pointer to a registered SR group, mandatory
 * - The "identifier" name is optional if this is the default, per entire group
 *    identifier.
 * - The "report" is mandatory too, it will be internally duplicated
 * - Set "is_public" if this operation was triggered from script or external
 *    sources (like MI). If the identity does not accept public ops, this
 *    operation will be forbidden.
 */
int sr_add_report(void *group,
		char *identifier_s, int identifier_len,
		char *report_s, int report_len,
		int is_public)
{
	sr_group *srg = (sr_group*)group;
	str identifier = {identifier_s, identifier_len};
	sr_identifier *sri;
	short idx;
	char *s;

	if (group==NULL || report_s==NULL) {
		LM_BUG("bogus call wtih group %p, report %p\n",
			group, report_s);
		return -1;
	}

	if (identifier.s==NULL)
		identifier = main_identifier;

	if ( (is_public) ^ (srg->is_public) ) {
		LM_ERR("forbidden adding report to identifier [%.*s] group [%.*s]\n",
			identifier.len, identifier.s, srg->name.len, srg->name.s);
		return -1;
	}

	lock_start_read( sr_lock );

	sri = _get_identifier_by_name( srg, &identifier);
	if (sri==NULL) {
		lock_stop_read( sr_lock );
		LM_ERR("adding report for unknow identifier [%.*s] group [%.*s]\n",
			identifier.len, identifier.s, srg->name.len, srg->name.s);
		return -1;
	}

	if (sri->max_reports==0)  {
		lock_stop_read( sr_lock );
		LM_ERR("identifier [%.*s] group [%.*s] does not accept reports\n",
			identifier.len, identifier.s, srg->name.len, srg->name.s);
		return -1;
	}

	s = shm_malloc( report_len );
	if (s==NULL) {
		LM_ERR("failed to sh malloc for cloning report\n");
		lock_stop_read( sr_lock );
		return -1;
	}

	lock_get( &sri->lock );

	/* compute the index where to add the new report */
	if (sri->first_report==-1 && sri->last_report==-1) {
		sri->first_report = 0;
		idx = 0;
	} else {
		idx = (sri->last_report+1) % sri->max_reports;
	}

	if (idx==sri->first_report && -1!=sri->last_report) {
		/* overflow, free the oldest report */
		shm_free( sri->reports[idx].log.s );
		sri->reports[idx].log.s = NULL;
		sri->reports[idx].log.len = 0;
		sri->first_report = (sri->first_report+1) % sri->max_reports;
	}

	sri->last_report = idx;

	LM_DBG("adding report to identifier [%.*s] group [%.*s] on idx %d "
		"[%d,%d]\n", identifier.len, identifier.s,
		srg->name.len, srg->name.s, idx, sri->first_report, sri->last_report);

	/* copy the report here */
	sri->reports[idx].log.s = s;
	memcpy( s, report_s, report_len);
	sri->reports[idx].log.len = report_len;
	sri->reports[idx].ts = time(NULL);

	lock_release( &sri->lock );

	lock_stop_read( sr_lock );

	return sri?0:-1;
}


int sr_add_report_fmt(void *group,
		char *identifier_s, int identifier_len,
		int is_public,
		char *fmt_val, ...)
{
	va_list ap;
	char *report_s;
	int report_len;

	va_start(ap, fmt_val);
	report_s = mi_print_fmt(fmt_val, ap, &report_len);
	va_end(ap);
	if (!report_s)
		return -1;

	return sr_add_report( group, identifier_s, identifier_len,
		report_s, report_len, is_public);
}


#define _add_mi_readiness( _mi_item, _status) \
	add_mi_bool(_mi_item, CHAR_INT("Readiness"), (_status<0)?0:1)

/* Checks the status of an identifier
 * NOTE1 : for internal usage only, it does its own locking
 */
static int _check_status(sr_group *srg, str *identifier, mi_item_t *id_item)
{
	sr_identifier *sri;
	int status;

	if (identifier==NULL) {
		identifier = &main_identifier;
	} else if (identifier->len==3 && strncasecmp(identifier->s, "all", 3)==0){
		identifier = (void*)-1;
	}

	lock_start_read( sr_lock );

	if ( identifier != (void*)-1 ) {

		/* only one identifier */
		sri = _get_identifier_by_name( srg, identifier);
		if (sri==NULL) {
			LM_DBG("identifier [%.*s] not found in group [%.*s]\n",
				identifier->len, identifier->s,
				srg->name.len, srg->name.s);
			status = SR_STATUS_NOT_FOUND;
		} else {
			lock_get( &sri->lock );
			status = sri->status ;
			if (id_item) {
				_add_mi_readiness( id_item, status);
				add_mi_number( id_item, CHAR_INT("Status"), status);
				if (sri->status_txt.s)
					add_mi_string(id_item, CHAR_INT("Details"),
						sri->status_txt.s, sri->status_txt.len);
			}
			lock_release( &sri->lock );
		}

	} else {

		/* aggregate the status of all indetifiers in the group */
		status = SR_STATUS_READY;
		for( sri=srg->identifiers ; sri ; sri=sri->next) {
			lock_get( &sri->lock );
			if (sri->status < 0)
				status = SR_STATUS_NOT_READY;
			lock_release( &sri->lock );
		}

		if (id_item) {
			_add_mi_readiness( id_item, status);
			add_mi_number( id_item, CHAR_INT("Status"), status);
			add_mi_string(id_item, CHAR_INT("Details"),
				CHAR_INT("aggregated"));
		}

	}

	lock_stop_read( sr_lock );

	return status;
}


/****************** SR status of the OpenSIPS core  **************/

int sr_set_core_status(int status, char *txt_s, int txt_len)
{
	return sr_set_status( srg_core, CHAR_INT_NULL /*main*/, status,
		txt_s, txt_len, 0);
}


/* light version of set_core_status, doing no shm, locking or event
 * operations - such ops are potentially dangerous during shutdonw */
void sr_set_core_status_terminating( void )
{
	sri_core->status = STATE_TERMINATING;
	/* note: the below assigment will produce a small mem leak in shm
	 * (for the previously allocated status), but we do not really care
	 * as we do this only once, at shutdown */
	sri_core->status_txt.s = "shutting down";
	sri_core->status_txt.len = 13;
}


int sr_get_core_status(void)
{
	return sri_core->status;
}


int sr_add_core_report(char *report_s, int report_len)
{
	return sr_add_report( srg_core, CHAR_INT_NULL /*main*/,
		report_s, report_len, 0);
}

/****************** Core (to be used) functions  **********************/

int init_status_report(void)
{
	sr_lock = lock_init_rw();
	if (sr_lock==NULL) {
		LM_ERR("Failed to create the global RW lock, abording\n");
		return -1;
	}

	sr_evi_id = evi_publish_event(sr_event);
	if (sr_evi_id == EVI_ERROR) {
		LM_ERR("cannot register 'statis_changed' event\n");
		return -1;
	}

	srg_core = (sr_group*)sr_register_group_with_identifier(
		CHAR_INT("core"), 0/*not public*/, CHAR_INT_NULL /*main*/,
		STATE_NONE, CHAR_INT_NULL/*report*/, 10);
	if (srg_core==NULL) {
		LM_ERR("Failed to register 'status_report' group and identifier for "
			"'core'\n");
		return -1;
	}

	/* this is a bit hackish, but 100% safe as time as it is done right
	 * after the above sr_register_group_with_identifier() - the "main"
	 * identifier will be the only one in the group, so the first one too */
	sri_core = (srg_core)->identifiers;
	/* also it is safe to keep a reference here as we will never delete 
	 * this identifer - but be CAREFULL on this !!! */

	return 0;
}


/****************** Core Scripting functions  **********************/

int fixup_sr_group(void **param)
{
	str *name = (str*)*param;
	sr_group *srg = NULL;

	if ( (srg=sr_get_group_by_name( name->s, name->len )) == NULL ) {
		LM_ERR("SR group [%.*s] not registered\n",
			name->len, name->s);
		return -1;
	}
	*param = (void*)srg;

	return 0;
}


/* Checks the status of an identifier
 * - The "msg" is useless, just for compatibility with script functions
 * - The "group" must a pointer to a registered SR group, mandatory
 * - The "identifier" may be: (1) name of an identifier, (2) NULL, to refer to
 *    the default (per group) identifier or (3) "all" to refer to all the
 *    identifiers in the group
 * Returns the status (as non zero value) of the requested identifier(s). If
 *  multiple indetifiers are to be checked - case (3) - the returned 
 *  status is an aggregated one as 1 or -1 (over all identifiers).
 */
int w_sr_check_status(struct sip_msg *msg, void *group, str *identifier)
{
	return _check_status((sr_group *)group, identifier, NULL);
}


/****************** Core MI  functions  **********************/

mi_response_t *mi_sr_get_status(const mi_params_t *params,
											struct mi_handler *async_hdl)
{
	str group;
	str identifier;
	int status;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	sr_group *srg = NULL;

	if (get_mi_string_param(params, "group", &group.s, &group.len) < 0)
		return init_mi_param_error();

	if ( (srg=sr_get_group_by_name( group.s, group.len )) == NULL ) {
		LM_DBG("SR group [%.*s] not found as registered\n",
			group.len, group.s);
		return init_mi_error(404, CHAR_INT("Group not found"));
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (try_get_mi_string_param(params, "identifier",
	&identifier.s, &identifier.len)!=0) {
		/* no identifier passed */
		status = _check_status( srg, NULL, resp_obj);
	} else {
		status = _check_status( srg, &identifier, resp_obj);
	}

	if (status == SR_STATUS_NOT_FOUND) {
		free_mi_response(resp);
		return init_mi_error(404, CHAR_INT("Identity not found"));
	}

	return resp;
}


static int _mi_list_status_group(sr_group *srg, mi_item_t *id_arr)
{
	sr_identifier *sri;
	mi_item_t *id_item;

	for ( sri=srg->identifiers ; sri ; sri=sri->next ) {

		id_item = add_mi_object(id_arr, 0, 0);
		if (!id_item)
			return -1;

		lock_get( &sri->lock );

		if (add_mi_string(id_item, CHAR_INT("Name"),
		sri->name.s, sri->name.len ) < 0 ) {
			lock_release( &sri->lock );
			return -1;
		}

		if (_add_mi_readiness( id_item, sri->status)<0 ) {
			lock_release( &sri->lock );
			return -1;
		}

		if (add_mi_number( id_item, CHAR_INT("Status"), sri->status)<0) {
			lock_release( &sri->lock );
			return -1;
		}

		if (sri->status_txt.s && add_mi_string(id_item, CHAR_INT("Details"),
		sri->status_txt.s, sri->status_txt.len) < 0) {
			lock_release( &sri->lock );
			return -1;
		}

		lock_release( &sri->lock );

	}

	return 0;
}


mi_response_t *mi_sr_list_status(const mi_params_t *params,
											struct mi_handler *async_hdl)
{
	str group;
	mi_response_t *resp;
	mi_item_t *grp_arr, *grp_item, *id_arr;
	sr_group *srg = NULL;

	if (try_get_mi_string_param(params, "group", &group.s, &group.len)!=0) {
		/* no group passed */
		srg = NULL;
	} else {
		if ( (srg=sr_get_group_by_name( group.s, group.len )) == NULL ) {
			LM_DBG("SR group [%.*s] not found as registered\n",
				group.len, group.s);
			return init_mi_error(404, CHAR_INT("Group not found"));
		}
	}

	lock_start_read( sr_lock );

	/* list the readiness of all identifiers from the group(s) */
	if (srg) {

		resp = init_mi_result_array( &id_arr);
		if (!resp)
			goto error;

		if (_mi_list_status_group( srg, id_arr)<0) {
			LM_ERR("failed to inser group, mem failure\n");
			goto error;
		}

	} else {

		resp = init_mi_result_array( &grp_arr);
		if (!resp)
			goto error;

		for ( srg=sr_groups ; srg ; srg=srg->next ) {
			
			grp_item = add_mi_object( grp_arr, 0, 0);
			if (!grp_item)
				goto error;

			if (add_mi_string( grp_item, CHAR_INT("Name"),
			srg->name.s, srg->name.len)<0)
				goto error;

			id_arr = add_mi_array( grp_item, CHAR_INT("Identifiers"));
			if (!id_arr)
				goto error;

			if (_mi_list_status_group( srg, id_arr)<0) {
				LM_ERR("failed to inser group, mem failure\n");
				goto error;
			}
		}

	}

	lock_stop_read( sr_lock );

	return resp;
error:
	lock_stop_read( sr_lock );
	free_mi_response(resp);
	return 0;

}


static int _mi_list_reports(sr_identifier *sri, mi_item_t *log_arr)
{
	mi_item_t *log_item;
	short i, cnt;
	str date;

	lock_get( &sri->lock );

	if (sri->first_report==-1 || sri->max_reports==0) {
		/* no reports at all */
		lock_release( &sri->lock );
		return 0;
	}


	cnt = sri->last_report - sri->first_report + 1;
	if (cnt<=0)
		cnt += sri->max_reports;

	LM_DBG("idxes: first=%d, last=%d, cnt=%d\n",
		sri->first_report,sri->last_report,cnt);

	for ( i=sri->first_report ; cnt ; i=(i+1)%sri->max_reports,cnt-- ) {

		log_item = add_mi_object( log_arr, 0, 0);
		if (log_item==NULL)
			goto error;

		if (add_mi_number( log_item, CHAR_INT("Timestamp"), sri->reports[i].ts) < 0)
			goto error;

		date.s = ctime( &sri->reports[i].ts );
		date.len = strlen(date.s) - 1 /* get rid of the trailing \n */;
		if (add_mi_string( log_item, CHAR_INT("Date"), date.s, date.len) < 0)
			goto error;

		if (add_mi_string( log_item, CHAR_INT("Log"),
		sri->reports[i].log.s, sri->reports[i].log.len ) < 0)
			goto error;
	}

	lock_release( &sri->lock );
	return 0;

error:
	lock_release( &sri->lock );
	return -1;
}


static int _mi_list_reports_group(sr_group *srg, mi_item_t *id_arr)
{
	sr_identifier *sri;
	mi_item_t *id_item, *log_arr;

	for ( sri=srg->identifiers ; sri ; sri=sri->next ) {

		id_item = add_mi_object( id_arr, 0, 0);
		if (!id_item)
			return -1;

		if (add_mi_string( id_item, CHAR_INT("Name"),
		sri->name.s, sri->name.len ) < 0 )
			return -1;

		log_arr = add_mi_array( id_item, CHAR_INT("Reports"));
		if (log_arr==NULL)
			return -1;

		if ( _mi_list_reports( sri, log_arr)!=0 )
			return -1;

	}

	return 0;
}


mi_response_t *mi_sr_list_reports(const mi_params_t *params,
											struct mi_handler *async_hdl)
{
	str group, identifier;
	mi_response_t *resp;
	mi_item_t *log_arr, *id_arr, *grp_arr, *grp_item;
	sr_group *srg = NULL;
	sr_identifier *sri = NULL;

	if (try_get_mi_string_param(params, "group", &group.s, &group.len)==0) {

		/* group provide */
		if ( (srg=sr_get_group_by_name( group.s, group.len )) == NULL ) {
			LM_DBG("SR group [%.*s] not found as registered\n",
				group.len, group.s);
			return init_mi_error(404, CHAR_INT("Group not found"));
		}

		lock_start_read( sr_lock );

		if (try_get_mi_string_param(params, "identifier",
		&identifier.s, &identifier.len)==0) {
			if ( (sri=_get_identifier_by_name( srg, &identifier )) == NULL ) {
				lock_stop_read( sr_lock );
				LM_DBG("SR identifier [%.*s] group [%.*s] not found as "
					"registered\n", identifier.len, identifier.s,
					group.len, group.s);
				return init_mi_error(404, CHAR_INT("Identifier not found"));
			}

		}

	} else {

		lock_start_read( sr_lock );

	}

	if (sri) {

		resp = init_mi_result_array( &log_arr);
		if (!log_arr)
			goto error;

		if (_mi_list_reports( sri, log_arr)<0) {
			LM_ERR("failed to inser identity, mem failure\n");
			goto error;
		}

	} else if (srg) {

		resp = init_mi_result_array( &id_arr);
		if (!id_arr)
			goto error;

		if (_mi_list_reports_group( srg, id_arr)<0) {
			LM_ERR("failed to inser group, mem failure\n");
			goto error;
		}

	} else {

		resp = init_mi_result_array( &grp_arr);
		if (!grp_arr)
			goto error;

		for ( srg=sr_groups ; srg ; srg=srg->next ) {

			grp_item = add_mi_object(grp_arr, 0, 0);
			if (!grp_item)
				goto error;

			if (add_mi_string( grp_item, CHAR_INT("Name"),
			srg->name.s, srg->name.len)<0)
				goto error;

			id_arr = add_mi_array(grp_item, CHAR_INT("Identifiers"));
			if (!id_arr)
				goto error;

			if (_mi_list_reports_group( srg, id_arr)<0) {
				LM_ERR("failed to inser group, mem failure\n");
				goto error;
			}
		}
	}

	lock_stop_read( sr_lock );

	return resp;
error:
	lock_stop_read( sr_lock );
	if (resp)
		free_mi_response(resp);
	return 0;
}


mi_response_t *mi_sr_list_identifiers(const mi_params_t *params,
											struct mi_handler *async_hdl)
{
	str group;
	mi_response_t *resp;
	mi_item_t *id_arr, *grp_arr, *grp_item;
	sr_group *srg = NULL;
	sr_identifier *sri = NULL;

	if (try_get_mi_string_param(params, "group", &group.s, &group.len)==0) {

		/* group provide */
		if ( (srg=sr_get_group_by_name( group.s, group.len )) == NULL ) {
			LM_DBG("SR group [%.*s] not found as registered\n",
				group.len, group.s);
			return init_mi_error(404, CHAR_INT("Group not found"));
		}

	}

	lock_start_read( sr_lock );

	if (srg) {

		resp = init_mi_result_object( &grp_item);
		if (!grp_item)
			goto error;

		if (add_mi_string( grp_item, CHAR_INT("Group"),
		srg->name.s, srg->name.len)<0)
			goto error;

		id_arr = add_mi_array( grp_item,  CHAR_INT("Identifiers"));
		if (!id_arr)
			goto error;

		for ( sri=srg->identifiers ; sri ; sri=sri->next ) {
			if (add_mi_string( id_arr, CHAR_INT("Name"),
			sri->name.s, sri->name.len ) < 0 )
				goto error;
		}

	} else {

		resp = init_mi_result_array( &grp_arr);
		if (!grp_arr)
			goto error;

		for ( srg=sr_groups ; srg ; srg=srg->next ) {

			grp_item = add_mi_object(grp_arr, 0, 0);
			if (!grp_item)
				goto error;

			if (add_mi_string( grp_item, CHAR_INT("Group"),
			srg->name.s, srg->name.len)<0)
				goto error;

			id_arr = add_mi_array( grp_item,  CHAR_INT("Identifiers"));
			if (!id_arr)
				goto error;

			for ( sri=srg->identifiers ; sri ; sri=sri->next ) {
				if (add_mi_string( id_arr, CHAR_INT("Name"),
				sri->name.s, sri->name.len ) < 0 )
					goto error;
			}

		}
	}

	lock_stop_read( sr_lock );

	return resp;
error:
	lock_stop_read( sr_lock );
	if (resp)
		free_mi_response(resp);
	return 0;

}
