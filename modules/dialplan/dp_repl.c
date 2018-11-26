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

int rule_translate(struct sip_msg *msg, str string, dpl_node_t * rule,
		str * result)
{
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
		LM_DBG("Byday: \n");
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
		LM_DBG("Byyday:\n");
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
		LM_DBG("Byweekno: \n");
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

#define DP_MAX_ATTRS_LEN	256
static char dp_attrs_buf[DP_MAX_ATTRS_LEN+1];
int translate(struct sip_msg *msg, str input, str * output, dpl_id_p idp, str * attrs) {

	dpl_node_p rulep, rrulep;
	int string_res = -1, regexp_res = -1, bucket;

	if(!input.s || !input.len) {
		LM_ERR("invalid input string\n");
		return -1;
	}

	bucket = core_case_hash(&input, NULL, DP_INDEX_HASH_SIZE);

	/* try to match the input in the corresponding string bucket */
	for (rulep = idp->rule_hash[bucket].first_rule; rulep; rulep=rulep->next) {

		LM_DBG("Equal operator testing\n");

		if(rulep->match_exp.len != input.len)
			continue;

		LM_DBG("Comparing (input %.*s) with (rule %.*s) [%d] and timerec %.*s\n",
				input.len, input.s, rulep->match_exp.len, rulep->match_exp.s,
				rulep->match_flags, rulep->timerec.len, rulep->timerec.s);

		// Check for Time Period if Set
		if(rulep->parsed_timerec) {
			LM_DBG("Timerec exists for rule checking: %.*s\n", rulep->timerec.len, rulep->timerec.s);
			// Doesn't matches time period continue with next rule
			if(!check_time(rulep->parsed_timerec)) {
				LM_DBG("Time rule doesn't match: skip next!\n");
				continue;
			}
		}

		if (rulep->match_flags & DP_CASE_INSENSITIVE) {
			string_res = strncasecmp(rulep->match_exp.s,input.s,input.len);
		} else {
			string_res = strncmp(rulep->match_exp.s,input.s,input.len);
		}

		if (string_res == 0) {
			break;
		}
	}

	/* try to match the input in the regexp bucket */
	for (rrulep = idp->rule_hash[DP_INDEX_HASH_SIZE].first_rule; rrulep; rrulep=rrulep->next) {

		// Check for Time Period if Set
		if(rrulep->parsed_timerec) {
			LM_DBG("Timerec exists for rule checking: %.*s\n", rrulep->timerec.len, rrulep->timerec.s);
			// Doesn't matches time period continue with next rule
			if(!check_time(rrulep->parsed_timerec)) {
				LM_DBG("Time rule doesn't match: skip next!\n");
				continue;
			}
		}

		regexp_res = (test_match(input, rrulep->match_comp, matches, MAX_MATCHES)
					>= 0 ? 0 : -1);

		LM_DBG("Regex operator testing. Got result: %d\n", regexp_res);

		if (regexp_res == 0) {
			break;
		}
	}

	if (string_res != 0 && regexp_res != 0) {
		LM_DBG("No matching rule for input %.*s\n", input.len, input.s);
		return -1;
	}

	/* pick the rule with lowest table index if both match and prio are equal */
	if (string_res == 0 && regexp_res == 0) {
		if (rrulep->pr < rulep->pr) {
			rulep = rrulep;
		} else if (rrulep->pr == rulep->pr &&
		           rrulep->table_id < rulep->table_id) {
			rulep = rrulep;
		}
	}

	if (!rulep)
		rulep = rrulep;

	LM_DBG("Found a matching rule %p: pr %i, match_exp %.*s\n",
		rulep, rulep->pr, rulep->match_exp.len, rulep->match_exp.s);

	if(attrs){
		attrs->len = 0;
		attrs->s = 0;
		if(rulep->attrs.len>0) {
			LM_DBG("the rule's attrs are %.*s\n",
				rulep->attrs.len, rulep->attrs.s);
			attrs->s = dp_attrs_buf;
			if (rulep->attrs.len >= DP_MAX_ATTRS_LEN) {
				LM_WARN("attribute for rule %d truncated to %d chars only\n",
					rulep->dpid, DP_MAX_ATTRS_LEN);
				memcpy(attrs->s, rulep->attrs.s, DP_MAX_ATTRS_LEN);
				attrs->len = DP_MAX_ATTRS_LEN;
			} else {
				memcpy(attrs->s, rulep->attrs.s, rulep->attrs.len);
				attrs->len = rulep->attrs.len;
			}
			attrs->s[attrs->len] = '\0';

			LM_DBG("the copied attributes are: %.*s\n",
				attrs->len, attrs->s);
		}
	}

	if(rule_translate(msg, input, rulep, output)!=0){
		LM_ERR("could not build the output\n");
		return -1;
	}

	return 0;
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

	result_count = pcre_exec(
							exp, /* the compiled pattern */
							NULL, /* no extra data - we didn't study the pattern */
							string.s, /* the subject string */
							string.len, /* the length of the subject */
							0, /* start at offset 0 in the subject */
							0, /* default options */
							out, /* output vector for substring information */
							out_max); /* number of elements in the output vector */

	if( result_count < 0 )
		return result_count;

	if( result_count == 0)
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

