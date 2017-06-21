/*
 * regexp and regexp substitutions implementations
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 *
 * History:
 * --------
 *   2003-08-04  created by andrei
 *   2004-11-12  minor api extension, added *count (andrei)
 *   2007-07-27  split function for parsing of replacing string (ancuta)
 */

/*!
 * \file
 * \brief Regexp and regexp substitutions implementations
 */



#include "dprint.h"
#include "mem/mem.h"
#include "re.h"

#include <string.h>



void subst_expr_free(struct subst_expr* se)
{
	if (se->replacement.s) pkg_free(se->replacement.s);
	if (se->re) { regfree(se->re); pkg_free(se->re); };
	pkg_free(se);
}



/*! \brief frees the entire list, head (l) too */
void replace_lst_free(struct replace_lst* l)
{
	struct replace_lst* t;

	while (l){
		t=l;
		l=l->next;
		if (t->rpl.s) pkg_free(t->rpl.s);
		pkg_free(t);
	}
}

#define MAX_REPLACE_WITH 100
int parse_repl(struct replace_with * rw, char ** begin,
				char * end, int *max_token_nb, int with_sep)
{

	char* p0;
	char * repl;
	str s;
	int token_nb;
	int escape;
	int max_pmatch;
	char *p, c;

	/* parse replacement */
	p = *begin;
	c = *p;
	if(with_sep)
		p++;
	repl= p;
	token_nb=0;
	max_pmatch=0;
	escape=0;
	for(;p<end; p++){
		if (escape){
			escape=0;
			switch (*p){
				/* special char escapes */
				case '\\':
					rw[token_nb].size=2;
					rw[token_nb].offset=(p-1)-repl;
					rw[token_nb].type=REPLACE_CHAR;
					rw[token_nb].u.c='\\';
					break;
				case 'n':
					rw[token_nb].size=2;
					rw[token_nb].offset=(p-1)-repl;
					rw[token_nb].type=REPLACE_CHAR;
					rw[token_nb].u.c='\n';
					break;
				case 'r':
					rw[token_nb].size=2;
					rw[token_nb].offset=(p-1)-repl;
					rw[token_nb].type=REPLACE_CHAR;
					rw[token_nb].u.c='\r';
					break;
				case 't':
					rw[token_nb].size=2;
					rw[token_nb].offset=(p-1)-repl;
					rw[token_nb].type=REPLACE_CHAR;
					rw[token_nb].u.c='\t';
					break;
				case PV_MARKER:
					rw[token_nb].size=2;
					rw[token_nb].offset=(p-1)-repl;
					rw[token_nb].type=REPLACE_CHAR;
					rw[token_nb].u.c=PV_MARKER;
					break;
				/* special sip msg parts escapes */
				case 'u':
					rw[token_nb].size=2;
					rw[token_nb].offset=(p-1)-repl;
					rw[token_nb].type=REPLACE_URI;
					break;
				/* re matches */
				case '0': /* allow 0, too, reference to the whole match */
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
					rw[token_nb].size=2;
					rw[token_nb].offset=(p-1)-repl;
					rw[token_nb].type=REPLACE_NMATCH;
					rw[token_nb].u.nmatch=(*p)-'0';
								/* 0 is the whole matched str*/
					if (max_pmatch<rw[token_nb].u.nmatch)
						max_pmatch=rw[token_nb].u.nmatch;
					break;
				default: /* just print current char */
					if (*p!=c){
						LM_WARN("\\%c unknown escape in %s\n", *p, *begin);
					}
					rw[token_nb].size=2;
					rw[token_nb].offset=(p-1)-repl;
					rw[token_nb].type=REPLACE_CHAR;
					rw[token_nb].u.c=*p;
					break;
			}

			token_nb++;

			if (token_nb>=MAX_REPLACE_WITH){
				LM_ERR("too many escapes in the replace part %s\n", *begin);
				goto error;
			}
		}else if (*p=='\\') {
			escape=1;
		}else if (*p==PV_MARKER) {
			s.s = p;
			s.len = end - s.s;
			p0 = pv_parse_spec(&s, &rw[token_nb].u.spec);
			if(p0==NULL)
			{
				LM_ERR("bad specifier in replace part %s\n", *begin);
				goto error;
			}
			rw[token_nb].size=p0-p;
			rw[token_nb].offset=p-repl;
			rw[token_nb].type=REPLACE_SPEC;
			token_nb++;
			p=p0-1;
		}else  if (*p==c && with_sep){
				goto found_repl;
		}
	}
	if(with_sep){

		LM_ERR("missing separator: %s\n", *begin);
		goto error;
	}

found_repl:

	*max_token_nb = max_pmatch;
	*begin = p;
	return token_nb;

error:
	return -1;
}


/*! \brief Parse a /regular expression/replacement/flags into a subst_expr structure
 */
struct subst_expr* subst_parser(str* subst)
{
	char c;
	char* end;
	char* p;
	char* re;
	char* re_end;
	char* repl;
	char* repl_end;
	struct replace_with rw[MAX_REPLACE_WITH];
	int rw_no;
	//int escape;
	int cflags; /* regcomp flags */
	int replace_all;
	struct subst_expr* se;
	regex_t* regex;
	int max_pmatch;
	int r;

	/* init */
	se=0;
	regex=0;
	cflags=REG_EXTENDED  | REG_NEWLINE; /* don't match newline */
	replace_all=0;
	if (subst->len<3){
		LM_ERR("expression is too short: %.*s\n", subst->len, subst->s);
		goto error;
	}

	p=subst->s;
	end=subst->s+subst->len;

	c=*p;
	if (c=='\\'){
		LM_ERR("invalid separator char <%c> in %.*s\n", c,
				subst->len, subst->s);
		goto error;
	}
	p++;

	/* find re */
	re=p;
	for (;p<end;p++){
		/* if unescaped sep. char */
		if ((*p==c) && (*(p-1)!='\\')) goto found_re;
	}
	LM_ERR("no separator found: %.*s\n", subst->len, subst->s);
	goto error;
found_re:
	re_end=p;
	if(end< (p+2) ){
		LM_ERR("string too short\n");
		goto error;
	}
	repl=p+1;
	if((rw_no = parse_repl(rw, &p, end, &max_pmatch, WITH_SEP))< 0)
		goto error;


	repl_end=p;
	p++;
	/* parse flags */
	for(;p<end; p++){
		switch(*p){
			case 'i':
				cflags|=REG_ICASE;
				break;
			case 's':
				cflags&=(~REG_NEWLINE);
				break;
			case 'g':
				replace_all=1;
				break;
			default:
				LM_ERR("unknown flag %c in %.*s\n",	*p, subst->len, subst->s);
				goto error;
		}
	}

	/* compile the re */
	if ((regex=pkg_malloc(sizeof(regex_t)))==0){
		LM_ERR("out of pkg memory (re)\n");
		goto error;
	}
	c=*re_end; /* regcomp expects null terminated strings -- save */
	*re_end=0;
	if (regcomp(regex, re, cflags)!=0){
		*re_end=c; /* restore */
		LM_ERR("bad regular expression %.*s in %.*s\n",
				(int)(re_end-re), re, subst->len, subst->s);
		goto error;
	}
	*re_end=c; /* restore */
	/* construct the subst_expr structure */
	se=pkg_malloc(sizeof(struct subst_expr)+
					((rw_no)?(rw_no-1)*sizeof(struct replace_with):0));
		/* 1 replace_with structure is  already included in subst_expr */
	if (se==0){
		LM_ERR("out of pkg memory (subst_expr)\n");
		goto error;
	}
	memset((void*)se, 0, sizeof(struct subst_expr));

	se->replacement.len=repl_end-repl;
	if ((se->replacement.s=pkg_malloc(se->replacement.len))==0){
		LM_ERR("out of pkg memory (replacement)\n");
		goto error;
	}

	/* start copying */
	memcpy(se->replacement.s, repl, se->replacement.len);
	se->re=regex;
	se->replace_all=replace_all;
	se->n_escapes=rw_no;
	se->max_pmatch=max_pmatch;
	for (r=0; r<rw_no; r++) se->replace[r]=rw[r];
	LM_DBG("ok, se is %p\n", se);
	return se;

error:
	if (se) { subst_expr_free(se); regex=0; }
	if (regex) { regfree (regex); pkg_free(regex); }
	return 0;
}


#if 0
static int replace_len(const char* match, int nmatch, regmatch_t* pmatch,
					struct subst_expr* se, struct sip_msg* msg)
{
	int r;
	int len;
	str* uri;

	len=se->replacement.len;
	for (r=0; r<se->n_escapes; r++){
		switch(se->replace[r].type){
			case REPLACE_NMATCH:
				len-=se->replace[r].size;
				if ((se->replace[r].u.nmatch<nmatch)&&(
						pmatch[se->replace[r].u.nmatch].rm_so!=-1)){
						/* do the replace */
						len+=pmatch[se->replace[r].u.nmatch].rm_eo-
								pmatch[se->replace[r].u.nmatch].rm_so;
				};
				break;
			case REPLACE_CHAR:
				len-=(se->replace[r].size-1);
				break;
			case REPLACE_URI:
				len-=se->replace[r].size;
				if (msg->first_line.type!=SIP_REQUEST){
					LM_CRIT("uri substitution on a reply\n");
					break; /* ignore, we can continue */
				}
				uri= (msg->new_uri.s)?(&msg->new_uri):
					(&msg->first_line.u.request.uri);
				len+=uri->len;
				break;
			default:
				LM_CRIT("unknown type %d\n", se->replace[r].type);
				/* ignore it */
		}
	}
	return len;
}

#endif

/*! \brief Replies will be allocated with the proper size & rpl.len set
 * \return 0 on success, <0 on error
 */
static int replace_build(const char* match, int nmatch, regmatch_t* pmatch,
					struct subst_expr* se, struct sip_msg* msg, str* rpl)
{
	int r;
	str* uri;
	pv_value_t sv;
	char* p;
	char* dest;
	char* end;
	int size;
#define REPLACE_BUFFER_SIZE	1024
	static char rbuf[REPLACE_BUFFER_SIZE];

#if 0
	/* use static bufer now since we cannot easily get the length */
	rpl->len=replace_len(match, nmatch, pmatch, se, msg);
	if (rpl->len==0){
		rpl->s=0; /* empty string */
		return 0;
	}
	rpl->s=pkg_malloc(rpl->len);
	if (rpl->s==0){
		LM_ERR("out of pkg mem (rpl)\n");
		goto error;
	}
#endif

	p=se->replacement.s;
	end=p+se->replacement.len;
	dest=rbuf;
	for (r=0; r<se->n_escapes; r++){
		/* copy the unescaped parts */
		size=se->replacement.s+se->replace[r].offset-p;
		if(dest-rbuf+size>=REPLACE_BUFFER_SIZE-1){
			LM_ERR("overflow\n");
			goto error;
		}
		memcpy(dest, p, size);
		p+=size+se->replace[r].size;
		dest+=size;
		switch(se->replace[r].type){
			case REPLACE_NMATCH:
				if ((se->replace[r].u.nmatch<nmatch)&&(
						pmatch[se->replace[r].u.nmatch].rm_so!=-1)){
						/* do the replace */
						size=pmatch[se->replace[r].u.nmatch].rm_eo-
								pmatch[se->replace[r].u.nmatch].rm_so;
						if(dest-rbuf+size>=REPLACE_BUFFER_SIZE-1){
							LM_ERR("overflow\n");
							goto error;
						}
						memcpy(dest,
								match+pmatch[se->replace[r].u.nmatch].rm_so,
								size);
						dest+=size;
				};
				break;
			case REPLACE_CHAR:
				if(dest-rbuf+1>=REPLACE_BUFFER_SIZE-1){
					LM_ERR("overflow\n");
					goto error;
				}
				*dest=se->replace[r].u.c;
				dest++;
				break;
			case REPLACE_URI:
				if (msg->first_line.type!=SIP_REQUEST){
					LM_CRIT("uri substitution on a reply\n");
					break; /* ignore, we can continue */
				}
				uri= (msg->new_uri.s)?(&msg->new_uri):
					(&msg->first_line.u.request.uri);
				if(dest-rbuf+uri->len>=REPLACE_BUFFER_SIZE-1){
					LM_ERR("overflow\n");
					goto error;
				}
				memcpy(dest, uri->s, uri->len);
				dest+=uri->len;
				break;
			case REPLACE_SPEC:
				if(pv_get_spec_value(msg, &se->replace[r].u.spec, &sv)!=0)
				{
					LM_CRIT("item substitution returned error\n");
					break; /* ignore, we can continue */
				}
				if(dest-rbuf+sv.rs.len>=REPLACE_BUFFER_SIZE-1){
					LM_ERR("overflow\n");
					goto error;
				}
				memcpy(dest, sv.rs.s, sv.rs.len);
				dest+=sv.rs.len;
				break;
			default:
				LM_CRIT("unknown type %d\n", se->replace[r].type);
				/* ignore it */
		}
	}
	memcpy(dest, p, end-p);

	rpl->len = (dest-rbuf)+(end-p);
	rpl->s=pkg_malloc(rpl->len);
	if (rpl->s==0){
		LM_ERR("out of pkg mem (rpl)\n");
		goto error;
	}
	memcpy(rpl->s, rbuf, rpl->len);

	return 0;
error:
	return -1;
}



/*! \brief run substitutions
 * \return 0 if no match or error, or subst result; if count!=0
 *           it will be set to 0 (no match), the number of matches
 *           or -1 (error).
 * \note WARNING: input must be 0 terminated!
 */
struct replace_lst* subst_run(struct subst_expr* se, const char* input,
								struct sip_msg* msg, int* count)
{
	struct replace_lst *head;
	struct replace_lst **crt;
	const char *p;
	int r;
	regmatch_t* pmatch;
	int nmatch;
	int eflags;
	int cnt;


	/* init */
	head=0;
	cnt=0;
	crt=&head;
	p=input;
	nmatch=se->max_pmatch+1;
	/* no of () referenced + 1 for the whole string: pmatch[0] */
	pmatch=pkg_malloc(nmatch*sizeof(regmatch_t));
	if (pmatch==0){
		LM_ERR("out of pkg mem. (pmatch)\n");
		goto error;
	}
	eflags=0;
	do{
		r=regexec(se->re, p, nmatch, pmatch, eflags);
		LM_DBG("running. r=%d\n", r);
		/* subst */
		if (r==0){ /* != REG_NOMATCH */
			/* some checks */
			if (pmatch[0].rm_so==-1){
				LM_ERR("unknown offset?\n");
				goto error;
			}
			if (pmatch[0].rm_so==pmatch[0].rm_eo){
				LM_ERR("matched string is empty... invalid regexp?\n");
				goto error;
			}
			*crt=pkg_malloc(sizeof(struct replace_lst));
			if (*crt==0){
				LM_ERR("out of pkg mem (crt)\n");
				goto error;
			}
			memset(*crt, 0, sizeof(struct replace_lst));
			(*crt)->offset=pmatch[0].rm_so+(int)(p-input);
			(*crt)->size=pmatch[0].rm_eo-pmatch[0].rm_so;
			LM_DBG("matched (%d, %d): [%.*s]\n",
					(*crt)->offset, (*crt)->size,
					(*crt)->size, input+(*crt)->offset);
			/* create subst. string */
			/* construct the string from replace[] */
			if (replace_build(p, nmatch, pmatch, se, msg, &((*crt)->rpl))<0){
				goto error;
			}
			crt=&((*crt)->next);
			p+=pmatch[0].rm_eo;
			/* is it still a string start? */
			if (*(p-1)=='\n' || *(p-1)=='\r')
				eflags&=~REG_NOTBOL;
			else
				eflags|=REG_NOTBOL;
			cnt++;
		}
	}while((r==0) && se->replace_all);
	pkg_free(pmatch);
	if (count)*count=cnt;
	return head;
error:
	if (head) replace_lst_free(head);
	if (pmatch) pkg_free(pmatch);
	if (count) *count=-1;
	return 0;
}



/*! \return the substitution result in a str, input must be 0 term
 *  0 on no match or malloc error
 *  if count is non zero it will be set to the number of matches, or -1
 *   if error
 */
str* subst_str(const char *input, struct sip_msg* msg, struct subst_expr* se,
				int* count)
{
	str* res;
	struct replace_lst *lst;
	struct replace_lst* l;
	int len;
	int size;
	const char* p;
	char* dest;
	const char* end;


	/* compute the len */
	len=strlen(input);
	end=input+len;
	lst=subst_run(se, input, msg, count);
	if (lst==0){
		LM_DBG("no match\n");
		return 0;
	}
	for (l=lst; l; l=l->next)
		len+=(int)(l->rpl.len)-l->size;
	res=pkg_malloc(sizeof(str));
	if (res==0){
		LM_ERR("out of pkg memory\n");
		goto error;
	}
	res->s=pkg_malloc(len+1); /* space for null termination */
	if (res->s==0){
		LM_ERR("out of pkg memory (res->s)\n");
		goto error;
	}
	res->s[len]=0;
	res->len=len;

	/* replace */
	dest=res->s;
	p=input;
	for(l=lst; l; l=l->next){
		size=l->offset+input-p;
		memcpy(dest, p, size); /* copy till offset */
		p+=size + l->size; /* skip l->size bytes */
		dest+=size;
		if (l->rpl.len){
			memcpy(dest, l->rpl.s, l->rpl.len);
			dest+=l->rpl.len;
		}
	}
	memcpy(dest, p, end-p);
	if(lst) replace_lst_free(lst);
	return res;
error:
	if (lst) replace_lst_free(lst);
	if (res){
		if (res->s) pkg_free(res->s);
		pkg_free(res);
	}
	if (count) *count=-1;
	return 0;
}
