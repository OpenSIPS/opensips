/*
 * Copyright (C) 2007-2008 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2007-08-01 initial version (ancuta onofrei)
 */

#include "../../re.h"
#include "../../time_rec.h"
#include "dialplan.h"

#define MAX_REPLACE_WITH	10

void repl_expr_free(struct subst_expr *se)
{
	if(!se)
		return;

	if(se->replacement.s){
		shm_free(se->replacement.s);
		se->replacement.s = 0;
	}

	shm_free(se);
	se = 0;
}


struct subst_expr* repl_exp_parse(str subst)
{
	struct replace_with rw[MAX_REPLACE_WITH];
	int rw_no;
	struct subst_expr * se;
	int replace_all;
	char * p, *end, *repl, *repl_end;
	int max_pmatch, r;

	se = 0;
	replace_all = 0;
	p = subst.s;
	end = p + subst.len;
	rw_no = 0;

	repl = p;
	if((rw_no = parse_repl(rw, &p, end, &max_pmatch, WITHOUT_SEP))< 0)
		goto error;

	repl_end=p;

	/* construct the subst_expr structure */
	se = shm_malloc(sizeof(struct subst_expr)+
					((rw_no)?(rw_no-1)*sizeof(struct replace_with):0));
		/* 1 replace_with structure is  already included in subst_expr */
	if (se==0){
		LM_ERR("out of shm memory (subst_expr)\n");
		goto error;
	}
	memset((void*)se, 0, sizeof(struct subst_expr));

	se->replacement.len=repl_end-repl;
	if (!(se->replacement.s=shm_malloc(se->replacement.len * sizeof(char))) ){
		LM_ERR("out of shm memory \n");
		goto error;
	}
	if(!rw_no){
		replace_all = 1;
	}
	/* start copying */
	memcpy(se->replacement.s, repl, se->replacement.len);
	se->re=0;
	se->replace_all=replace_all;
	se->n_escapes=rw_no;
	se->max_pmatch=max_pmatch;

	/*replace_with is a simple structure, no shm alloc needed*/
	for (r=0; r<rw_no; r++) se->replace[r]=rw[r];
	return se;

error:
	if (se) { repl_expr_free(se);}
	return NULL;
}


#define MAX_PHONE_NB_DIGITS		127
#define MAX_MATCHES (100 * 3)

static char dp_output_buf[MAX_PHONE_NB_DIGITS+1];
static int matches[MAX_MATCHES];

int rule_translate(struct sip_msg * msg, str string, dpl_node_t * rule, str * result) {

	int repl_nb, offset, match_nb;
	struct replace_with token;
	pcre * subst_comp;
	struct subst_expr * repl_comp;
	pv_value_t sv;
	str* uri;
	int capturecount;
	char *match_begin;
	int match_len;

	dp_output_buf[0] = '\0';
	result->s = dp_output_buf;
	result->len = 0;

	subst_comp 	= rule->subst_comp;
	repl_comp 	= rule->repl_comp;

	if(!repl_comp){
		LM_DBG("null replacement\n");
		return 0;
	}


	if(subst_comp){

		pcre_fullinfo(
		subst_comp,                   /* the compiled pattern */
		NULL,                 /* no extra data - we didn't study the pattern */
		PCRE_INFO_CAPTURECOUNT ,  /* number of named substrings */
		&capturecount);          /* where to put the answer */


		/*just in case something went wrong at load time*/
		if(repl_comp->max_pmatch > capturecount){
			LM_ERR("illegal access to the "
				"%i-th subexpr of the subst expr\n", repl_comp->max_pmatch);
			return -1;
		}

		/*search for the pattern from the compiled subst_exp*/
		if(test_match(string, rule->subst_comp,matches,MAX_MATCHES) <= 0){
			LM_ERR("the string %.*s "
				"matched the match_exp %.*s but not the subst_exp %.*s!\n",
				string.len, string.s,
				rule->match_exp.len, rule->match_exp.s,
				rule->subst_exp.len, rule->subst_exp.s);
			return -1;
		}
	}

	/*simply copy from the replacing string*/
	if(!subst_comp || (repl_comp->n_escapes <=0)){
		if(!repl_comp->replacement.s || repl_comp->replacement.len == 0){
			LM_ERR("invalid replacing string\n");
			goto error;
		}
		LM_DBG("simply replace the string, "
			"subst_comp %p, n_escapes %i\n",subst_comp, repl_comp->n_escapes);
		memcpy(result->s, repl_comp->replacement.s, repl_comp->replacement.len);
		result->len = repl_comp->replacement.len;
		result->s[result->len] = '\0';
		return 0;
	}

	/* offset- offset in the replacement string */
	result->len = repl_nb = offset = 0;

	while( repl_nb < repl_comp->n_escapes){
		token = repl_comp->replace[repl_nb];

		if(offset< token.offset){
			if((repl_comp->replacement.len < offset)||
				(result->len + token.offset -offset >= MAX_PHONE_NB_DIGITS)){
				LM_ERR("invalid length\n");
				goto error;
			}
			/*copy from the replacing string*/
			memcpy(result->s + result->len, repl_comp->replacement.s + offset,
					token.offset-offset);
			result->len += (token.offset - offset);
			offset += token.offset-offset; /*update the offset*/
		}

		switch(token.type) {
			case REPLACE_NMATCH:
				/*copy from the match subexpression*/
				match_nb = token.u.nmatch;

				match_begin = string.s + matches[2*match_nb];
				match_len = matches[2*match_nb+1] - matches[2*match_nb];

				if(result->len + match_len >= MAX_PHONE_NB_DIGITS){
					LM_ERR("overflow\n");
					goto error;
				}

				memcpy(result->s + result->len, match_begin, match_len);
				result->len += match_len;
				offset += token.size; /*update the offset*/
				break;

			case REPLACE_CHAR:
				if(result->len + 1>= MAX_PHONE_NB_DIGITS){
					LM_ERR("overflow\n");
					goto error;
				}
				*result->s=repl_comp->replace[repl_nb].u.c;
				result->len++;
				break;
			case REPLACE_URI:
				if ( msg== NULL || msg->first_line.type!=SIP_REQUEST){
					LM_CRIT("uri substitution attempt on no request"
						" message\n");
					break; /* ignore, we can continue */
				}
				uri= (msg->new_uri.s)?(&msg->new_uri):
					(&msg->first_line.u.request.uri);
				if(result->len+uri->len>=MAX_PHONE_NB_DIGITS){
					LM_ERR("overflow\n");
					goto error;
				}
				memcpy(result->s + result->len, uri->s, uri->len);
				result->len+=uri->len;
				break;
			case REPLACE_SPEC:
				if (msg== NULL) {
					LM_DBG("replace spec attempted on no message\n");
					break;
				}
			if(pv_get_spec_value(msg,
				&repl_comp->replace[repl_nb].u.spec, &sv)!=0){
					LM_CRIT( "item substitution returned error\n");
					break; /* ignore, we can continue */
				}
				if(result->len+sv.rs.len>=MAX_PHONE_NB_DIGITS){
					LM_ERR("ERROR:dialplan: rule_translate: overflow\n");
					goto error;
				}
				memcpy(result->s + result->len, sv.rs.s, sv.rs.len);
				result->len+=sv.rs.len;
				break;
			default:
				LM_CRIT("BUG: unknown type %d\n",
					repl_comp->replace[repl_nb].type);
				/* ignore it */
		}
		repl_nb++;
	}
	/* anything left? */
	if( repl_nb && token.offset+token.size < repl_comp->replacement.len){
		/*copy from the replacing string*/
		memcpy(result->s + result->len,
			repl_comp->replacement.s + token.offset+token.size,
			repl_comp->replacement.len -(token.offset+token.size) );
			result->len +=repl_comp->replacement.len-(token.offset+token.size);
	}

	result->s[result->len] = '\0';
	return 0;

error:
	result->s = 0;
	result->len = 0;
	return -1;
}

int timerec_print(tmrec_p _trp)
{
	static char *_wdays[] = {"SU", "MO", "TU", "WE", "TH", "FR", "SA"}; 
	int i;
	UNUSED(_wdays);
	
	if(!_trp)
	{
		LM_DBG("\n(null)\n");
		return -1;
	}
	LM_DBG("Recurrence definition\n-- start time ---\n");
	LM_DBG("Sys time: %d\n", (int)_trp->dtstart);
	LM_DBG("Time: %02d:%02d:%02d\n", _trp->ts.tm_hour, 
				_trp->ts.tm_min, _trp->ts.tm_sec);
	LM_DBG("Date: %s, %04d-%02d-%02d\n", _wdays[_trp->ts.tm_wday],
				_trp->ts.tm_year+1900, _trp->ts.tm_mon+1, _trp->ts.tm_mday);
	LM_DBG("---\n");
	LM_DBG("End time: %d\n", (int)_trp->dtend);
	LM_DBG("Duration: %d\n", (int)_trp->duration);
	LM_DBG("Until: %d\n", (int)_trp->until);
	LM_DBG("Freq: %d\n", (int)_trp->freq);
	LM_DBG("Interval: %d\n", (int)_trp->interval);
	if(_trp->byday)
	{
		LM_DBG("Byday: ");
		for(i=0; i<_trp->byday->nr; i++)
			LM_DBG(" %d%s", _trp->byday->req[i], _wdays[_trp->byday->xxx[i]]);
		LM_DBG("\n");
	}
	if(_trp->bymday)
	{
		LM_DBG("Bymday: %d:", _trp->bymday->nr);
		for(i=0; i<_trp->bymday->nr; i++)
			LM_DBG(" %d", _trp->bymday->xxx[i]*_trp->bymday->req[i]);
		LM_DBG("\n");
	}
	if(_trp->byyday)
	{
		LM_DBG("Byyday:");
		for(i=0; i<_trp->byyday->nr; i++)
			LM_DBG(" %d", _trp->byyday->xxx[i]*_trp->byyday->req[i]);
		LM_DBG("\n");
	}
	if(_trp->bymonth)
	{
		LM_DBG("Bymonth: %d:", _trp->bymonth->nr);
		for(i=0; i< _trp->bymonth->nr; i++)
			LM_DBG(" %d", _trp->bymonth->xxx[i]*_trp->bymonth->req[i]);
		LM_DBG("\n");
	}
	if(_trp->byweekno)
	{
		LM_DBG("Byweekno: ");
		for(i=0; i<_trp->byweekno->nr; i++)
			LM_DBG(" %d", _trp->byweekno->xxx[i]*_trp->byweekno->req[i]);
		LM_DBG("\n");
	}
	LM_DBG("Weekstart: %d\n", _trp->wkst);
	return 0;
}

// Validate Passed Time Recurrence Instance
static inline int check_time(tmrec_t *time_rec) {
	ac_tm_t att;

	// No TimeRec: Rule is Valid
	if(time_rec->dtstart == 0)
		return 1;

	// Uncomment to enable Debug
	// timerec_print(time_rec);

	// Set Current Time
	memset(&att, 0, sizeof(att));
	if(ac_tm_set_time(&att, time(0)))
		return -1;

	// Check_Tmrec will return 0 on successfully time recurrence match
	if(check_tmrec(time_rec, &att, 0) != 0)
		return 0;

	// Recurrence Matched -- Validating Rule
	return 1;
}

/**
 * Check for match_var SRC/DST variable. On success replace
 * input/output placeholders
 */
static int check_match_var(struct sip_msg *msg, char * match_var, str * input, dp_param_p dp_par) {

	pv_value_t value;

	/* Backup Original Source */
	char *backup = pkg_malloc(sizeof(char) * strlen(match_var));
	strcpy(backup, match_var);

	/* Check for input string validity */
	if(check_input_param(dp_par, backup) <= 0) {
		LM_ERR("wrong match_var syntax ... skipping rule!\n");
		return -1;
	}

	/* Free backup memory */
	pkg_free(backup);

	/* Unable to retrieve input PV stored value */
	if (pv_get_spec_value(msg, &dp_par->v.sp[0], &value) != 0) {
		LM_ERR("no input match_var PV found ... skipping rule!\n");
		return -1;
	}

	/* Input PV stored value was empty or NULL ... unusable for pattern matching */
	if (value.flags &(PV_VAL_NULL|PV_VAL_EMPTY)) {
		LM_ERR("NULL or empty input match_var ... skipping rule!\n");
		return -1;
	}

	/* Rewrite input PV string */
	input->s = value.rs.s;
	memcpy(input->s, value.rs.s, value.rs.len * sizeof(char));
	input->len = value.rs.len;

	/* Debug */
	LM_DBG("PV input changed to %.*s due to match_var option!\n", input->len, input->s);

	/* Success */
	return 1;
}

#define DP_MAX_ATTRS_LEN	32
static char dp_attrs_buf[DP_MAX_ATTRS_LEN+1];
int translate(struct sip_msg *msg, str input, str * output, dpl_id_p idp, str * attrs, int matched_rule_id) {

	int_str val;
	int dbmatch = 0;
	dpl_node_p rrulep = NULL;
	dp_param_p rdp_par = NULL;
	struct usr_avp *ruleid_avp = NULL;
	int string_res = -1, regexp_res = -1, matched = 0;

	if(!input.s || !input.len) {
		LM_ERR("invalid input string\n");
		return -1;
	}

	/* try to match the input in the regexp bucket */
	for (rrulep = idp->rule_hash[DP_INDEX_HASH_SIZE].first_rule; rrulep; rrulep=rrulep->next) {

		/* Debug */
		LM_DBG("Comparing (match op: %i continue search: %i) input %.*s with rule %.*s [%d] and timerec %.*s\n",
			rrulep->matchop, rrulep->continue_search, input.len, input.s, rrulep->match_exp.len, rrulep->match_exp.s,
			rrulep->match_flags, rrulep->timerec.len, rrulep->timerec.s);

		/* Check for match_var existance. If true override input search string and output pointer */
		if(rrulep->match_var.len > 0) {
			/* Build a parameters data structure and allocate it */
			rdp_par = (dp_param_p) pkg_malloc(sizeof(dp_param_t));
			if(rdp_par == NULL) { LM_ERR("no more pkg memory\n"); goto err; }
			memset(rdp_par, 0, sizeof(dp_param_t));

			if(check_match_var(msg, rrulep->match_var.s, &input, rdp_par) <= 0) continue;
		}

		/* Lenght match failed on a best match rule ... skipping rule */
		if(rrulep->matchop == EQUAL_OP)
			if(rrulep->match_exp.len != input.len) {
				LM_DBG("Match length failed ... discarding rule!\n");
				continue;
			}

		/* Check for Time Period if Set */
		if(rrulep->parsed_timerec) {
			LM_DBG("Timerec exists for rule checking: %.*s\n", rrulep->timerec.len, rrulep->timerec.s);
			// Doesn't matches time period continue with next rule
			if(!check_time(rrulep->parsed_timerec)) {
				LM_DBG("Time rule doesn't match: skip next!\n");
				continue;
			}
		}

		/* Reset Return Values */
		string_res = regexp_res = -1;

		/* Check wich match to apply */
		if(rrulep->matchop == EQUAL_OP) {
			/* Doing Best Match */
			if (rrulep->match_flags & DP_CASE_INSENSITIVE)
				string_res = strncasecmp(rrulep->match_exp.s,input.s,input.len);
			else
				string_res = strncmp(rrulep->match_exp.s,input.s,input.len);
		} else {
			/* Doing RegEXP Match */
			regexp_res = (test_match(input, rrulep->match_comp, matches, MAX_MATCHES) >= 0 ? 0 : -1);
		}

		/* If a match occours apply translation */
		if (string_res == 0 || regexp_res == 0) {

			/* Update Match Counter */
			++matched;

			/* Applying translate on input string */
			if(rule_translate(msg, input, rrulep, output) != 0){
				LM_ERR("could not build the output\n");
				goto err;
			}
		
			/* Update database retrieved output PV */
			if(rrulep->match_var.len > 0 && rdp_par !=  NULL) {
				if (dp_update(msg, &rdp_par->v.sp[0], &rdp_par->v.sp[1], output) != 0) 
					LM_ERR("Unable to update database retrieved input/output PVs!\n");
		
				/* Free Datastructure */
				pkg_free(rdp_par);
		
				/* Set as Matched */
				dbmatch = 1;
			}
		
			/* Check for a valid matching rule avp id */
			if(matched_rule_id > 0) {
				/* Check if AVP already exists ... */
				ruleid_avp = search_first_avp(0, matched_rule_id, &val, NULL);
		
				/* ... and destroy it!!! */
				if(ruleid_avp && !(is_avp_str_val(ruleid_avp) == 0)) { 
					LM_DBG("AVP %i already exists with value %d\n", matched_rule_id, val.n);
					destroy_avp(ruleid_avp);
					ruleid_avp = NULL; 
				}
			
				/* Validate AVP value */
				val.n = rrulep->id;
			
				/* Add AVP */
				if (add_avp(0, matched_rule_id, val) < 0) {
					LM_ERR("unable to add AVP");
					goto err;
				}
			}

			/* A Rule Was Found ... build ATTRS PVAR content */
			if(attrs) {
				attrs->len = 0;
				attrs->s = 0;
		
				if(rrulep->attrs.len > 0) {
					LM_DBG("the rule's attrs are %.*s\n", rrulep->attrs.len, rrulep->attrs.s);
		
					if(rrulep->attrs.len >= DP_MAX_ATTRS_LEN) {
						LM_ERR("EXCEEDED Max attribute length.\n");
						goto err;
					}
		
					attrs->s = dp_attrs_buf;
					memcpy(attrs->s, rrulep->attrs.s, rrulep->attrs.len*sizeof(char));
					attrs->len = rrulep->attrs.len;
					attrs->s[attrs->len] = '\0';
		
					LM_DBG("the copied attributes are: %.*s\n", attrs->len, attrs->s);
				}
			}

			/* Check if continue searching through dialplan rules */
			if(rrulep->continue_search == 0) break;
		}
	}

	/* No Rule Found ... */
	if (matched <= 0) {
		LM_DBG("No matching rule for input %.*s\n", input.len, input.s);
		goto err;
	}

	/* Return Value */
	return dbmatch;

/* Purge on error */
err:
	if(rdp_par) pkg_free(rdp_par);
	return -1;	
}


int test_match(str string, pcre * exp, int * out, int out_max)
{
	int i, result_count;
	char *substring_start;
	int substring_length;
	UNUSED(substring_start);
	UNUSED(substring_length);

	if(!exp){
		LM_ERR("invalid compiled expression\n");
		return -1;
	}

	result_count = pcre_exec (
		exp,		/* the compiled pattern */
		NULL,		/* no extra data - we didn't study the pattern */
		string.s,	/* the subject string */
		string.len,	/* the length of the subject */
		0,		/* start at offset 0 in the subject */
		0,		/* default options */
		out,		/* output vector for substring information */
		out_max		/* number of elements in the output vector */
	);

	if(result_count < 0)
		return result_count;

	if(result_count == 0)
	{
		LM_ERR("Not enough space for mathing\n");
		return result_count;
	}


	for (i = 0; i < result_count; i++)
	{
		substring_start = string.s + out[2 * i];
		substring_length = out[2 * i + 1] - out[2 * i];
		LM_DBG("test_match:[%d] %.*s\n",i, substring_length, substring_start);
	}


	return result_count;
}

