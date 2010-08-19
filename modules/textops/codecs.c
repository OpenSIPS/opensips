/*
 * $Id$
 *
 * Copyright (C) 2009 Voice Sistem SRL
 * Copyright (C) 2009 Andrei Dragus
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * History:
 * ---------
 *  2009-07-23  first version (andreidragus)
 */

#include "../../sr_module.h"
#include "../../parser/msg_parser.h"
#include "../../mem/mem.h"
#include "../../data_lump.h"
#include "../../parser/sdp/sdp.h"
#include "codecs.h"
#include "../../script_cb.h"
#include "../../route.h"
#include "../../mod_fix.h"


typedef struct _lump_arr
{
	str * v;
	int len;
}lump_arr_t;


static struct lump ** lumps;
static int lumps_len;

static lump_arr_t stack[3];
static int idx;
static int used = 0;


enum{
	FIND,
	DELETE,
	ADD_TO_FRONT,
	ADD_TO_BACK
};

enum{
	DESC_NAME,
	DESC_NAME_AND_CLOCK,
	DESC_REGEXP,
	DESC_REGEXP_COMPLEMENT
};


static int stream_process(struct sip_msg* msg, struct sdp_stream_cell *cell,
						  str* s, str* ss, regex_t* re, int op, int description);
static int create_lumps(struct sip_msg * msg);
static int find_flagged_lumps(struct sip_msg * msg);

/* reset the global array of lumps*/
void clear_global_data(void)
{
	if( lumps )
	{
		pkg_free(lumps);
	}
	
	lumps = NULL;
	lumps_len = -1;
};

/* save the lumps that need to be restored later */
int backup(void)
{
	int len = lumps_len;
	int i = 0;

	stack[idx].len = len;

	if( len > 0)
	{
		stack[idx].v = pkg_malloc(len * sizeof(str));

		for( i=0; i<len; i++)
		{
			str * l = & stack[idx].v[i];
			struct lump * old = lumps[i]->after;
			int n = old->len;

			l->s = pkg_malloc(n);

			if( l->s == NULL)
			{
				LM_ERR("Not enough memory n=%d\n",n);
				return -1;
			}
			
			memcpy(l->s, old->u.value, n);
			l->len = n;

		}

	}

	idx++;

	return 0;
};

void restore(void)
{
	int len;
	int i = 0;

	if (idx > 0)
	{
		idx--;
		len = stack[idx].len;


		if (len > 0)
		{
			for (i = 0; i < len; i++)
			{
				str* l = &stack[idx].v[i];
				struct lump * old = lumps[i]->after;
				int n = l->len;

				memcpy(old->u.value, l->s, n);
				old->len = n;

				pkg_free(l->s);

			}

			pkg_free(stack[idx].v);
		}
	}

};

int pre_route_callback( struct sip_msg *msg, void *param )
{
	if( used )
	{
		if( route_type & (REQUEST_ROUTE | ONREPLY_ROUTE)  )
		{
			if( create_lumps(msg) )
				return 0;
		}

		if( route_type & (FAILURE_ROUTE | BRANCH_ROUTE) )
		{
			find_flagged_lumps(msg);
		}

		if( route_type & (FAILURE_ROUTE | BRANCH_ROUTE)  )
		{
			backup();
		}
	}

	return 0;
};


int post_route_callback( struct sip_msg *msg, void *param )
{
	if( used )
	{
		if( route_type & (FAILURE_ROUTE | BRANCH_ROUTE)  )
		{
			restore();
		}
	}

	return 0;
};



int codec_init(void)
{
	register_route_cb( pre_route_callback, PRE_SCRIPT_CB, NULL );
	register_route_cb( post_route_callback, POST_SCRIPT_CB, NULL );

	clear_global_data();

	idx = 0;

	return 0;
}

int fixup_codec(void** param, int param_no)
{
	str * s = pkg_malloc(sizeof(str));

	used = 1;

	if( s == NULL)
	{
		LM_ERR("Out of memory\n");
		return -1;
	}

	s->s=*param;
	s->len = strlen(*param);
	*param = s;

	return 0;
}

int fixup_codec_regexp(void** param, int param_no)
{
	used = 1;

	return fixup_regexp_null(param, param_no);
}

/*
 * Create the necessary lumps from the message
 */
int create_lumps(struct sip_msg * msg)
{

	struct sdp_session_cell * cur_session;
	int count;
	struct lump * tmp;

	if(parse_sdp(msg))
	{
		LM_DBG("Message has no SDP\n");
		return -1;
	}

	/* get the number of streams */
	count = 0;
	cur_session = msg->sdp->sessions;

	while(cur_session)
	{
		count += cur_session->streams_num;
		cur_session = cur_session->next;
	}

	lumps = pkg_realloc(lumps, count * sizeof(struct lump*));
	lumps_len = count;

	if( lumps == NULL)
	{
		LM_ERR("Out of memory\n");
		return -1;
	}


	/* for each stream create a specific lump for deletion and one for
	 *  insertion */

	count = 0;
	cur_session = msg->sdp->sessions;

	while(cur_session)
	{
		struct sdp_stream_cell * cur_cell = cur_session->streams;
		struct lump* l;
		str text;

		while(cur_cell)
		{
			l = del_lump(msg, cur_cell->payloads.s - msg->buf,
					cur_cell->payloads.len,0);

			lumps[count] = l;
			
			if( l == NULL)
			{
				LM_ERR("Error adding delete lump for m=\n");
				return -1;
			}

			l->flags |= LUMPFLAG_CODEC;

			text.len = cur_cell->payloads.len;
			text.s = (char*)pkg_malloc(cur_cell->payloads.len);

			if( text.s == NULL )
			{
				LM_ERR("Error alocating lump buffer\n");
				return -1;
			}

			memcpy(text.s,cur_cell->payloads.s,cur_cell->payloads.len);


			tmp = insert_new_lump_after( l,	text.s, text.len, 0);

			if(tmp == NULL)
			{
				LM_ERR("Error adding insert lump for m=\n");
				return -1;

			}

			count ++;
			cur_cell = cur_cell->next;
		}

		cur_session = cur_session->next;

	}

	return 0;

};
/*
 * Find the flagged lumps and save them in the global lump array
 */
int find_flagged_lumps(struct sip_msg * msg)
{
	struct lump *cur = msg->body_lumps;
	int count = 0;

	while( cur)
	{
		if( cur->flags & LUMPFLAG_CODEC && cur->after )
			count++;
			
		cur = cur->next;
	}

	if( count > 0)
	{

		lumps_len = 0;
		lumps = pkg_malloc(count * sizeof(struct lump*));

		if( lumps == NULL)
		{
			LM_ERR("Out of memory\n");
			return -1;
		}

		cur = msg->body_lumps;
		
		while( cur)
		{
			if( cur->flags & LUMPFLAG_CODEC && cur->after)
			{
				lumps[lumps_len] = cur;
				lumps_len++;
			}
			cur = cur->next;
		}

	}

	return 0;

};

/*
 * Associate a lump with a given cell
 */
struct lump * get_associated_lump(struct sip_msg * msg,
								  struct sdp_stream_cell * cell)
{
	int i;

	LM_DBG("Have %d lumps\n",lumps_len);
	
	for( i =0 ; i< lumps_len; i++)
	{
		int have = lumps[i]->u.offset;
		int want = cell->payloads.s - msg->buf;

		LM_DBG("have lump at %d want at %d\n", have, want );
		if( have == want )
			return lumps[i];
	}

	return NULL;
};


static int do_for_all_streams(struct sip_msg* msg, str* str1,str * str2,
				regex_t* re, int op,int desc)
{
	struct sdp_session_cell * cur_session;
	int rez;

	if (msg==NULL || msg==FAKED_REPLY)
		return -1;

	if(parse_sdp(msg))
	{
		LM_DBG("Message has no SDP\n");
		return -1;
	}


	cur_session = msg->sdp->sessions;
	rez = 0;

	while(cur_session)
	{
		struct sdp_stream_cell * cur_cell = cur_session->streams;

		while(cur_cell)
		{
			rez |= stream_process(msg,cur_cell,str1,str2,re,op,desc);
			cur_cell = cur_cell->next;
		}

		cur_session = cur_session->next;

	}

	if( rez <0 )
		rez = 0;
	return rez;
}




int delete_sdp_line( struct sip_msg * msg, char * s)
{
	char * start,*end;

	if( !s )
		return 1;

	start = s;
	end  = s;

	while(*start != '\n')
		start--;
	start++;

	while(*end != '\n')
		end++;
	end++;

	/* delete the entry */
	if( del_lump(msg, start - msg->buf, end - start,0) == NULL )
	{
		return -1;
	}

	return 0;
}



/* method that processes a stream and keeps the original order
 * of codecs with the same name */
int stream_process(struct sip_msg * msg, struct sdp_stream_cell *cell,
			str * s, str* ss, regex_t* re, int op,int description)
{
	sdp_payload_attr_t *payload;
	char *cur, *tmp, *buff, temp;
	struct lump * lmp;
	str found;
	int ret, i, depl, single, match, buff_len;
	regmatch_t pmatch;
	
	
	lmp = get_associated_lump(msg, cell);

	if( lmp == NULL)
	{
		LM_ERR("There is no lump for this sdp cell\n");
		return -1;
	}

	lmp = lmp->after;
	buff_len = 0;
	ret = 0;


	buff = pkg_malloc(lmp->len+1);

	if( buff == NULL)
	{
		LM_ERR("Out of memory\n");
		return -1;
	}
	
	

	/* go through the 'm=' field to find numbers to be deleted */
	cur = lmp->u.value;

	while( cur < lmp->u.value + lmp->len)
	{
		/* find the end of the first number */
		found.s = cur;

		while(  cur < lmp->u.value + lmp->len &&  *cur != ' ' )
			cur++;

		found.len = cur - found.s;
		


		/* search through each payload */

		payload = cell->payload_attr;

		while(payload)
		{

			if( payload->rtp_enc.s == NULL
			 || (payload->rtp_clock.s == NULL && ss != NULL)
			 || payload->rtp_payload.s == NULL)
			{
				payload = payload->next;
				continue;
			}

			match = 0;

			if( description == DESC_REGEXP ||description == DESC_REGEXP_COMPLEMENT )
			{
				/* try to match a regexp */
				temp = payload->rtp_enc.s[payload->rtp_enc.len];
				payload->rtp_enc.s[payload->rtp_enc.len] = 0;
				match = regexec( re, payload->rtp_enc.s, 1, &pmatch, 0) == 0;
				payload->rtp_enc.s[payload->rtp_enc.len] = temp;
			}

			if( description == DESC_REGEXP_COMPLEMENT)
				match = !match;

			if( description == DESC_NAME  )
			{
				match = s->len == payload->rtp_enc.len &&
				strncasecmp( s->s, payload->rtp_enc.s ,	payload->rtp_enc.len) == 0;
			}

			if( description == DESC_NAME_AND_CLOCK)
			{
				/* try to match name and clock if there is one */
				match = s->len == payload->rtp_enc.len &&
				strncasecmp( s->s, payload->rtp_enc.s ,
					payload->rtp_enc.len) == 0
				&&
				(ss == NULL || ( ss->len == payload->rtp_clock.len &&
				strncasecmp( ss->s, payload->rtp_clock.s ,
					payload->rtp_clock.len) == 0
				) );

			}

			/* try to match payload number */
			match = match && (found.len == payload->rtp_payload.len &&
				strncmp( found.s,payload->rtp_payload.s,found.len) == 0);


			/* if we find one of interest delete it */
			if( match )
			{

				if(op == FIND)
				{
					ret = 1;
					goto end;
				}

				if( op == DELETE)
				{
					/* find the full 'a=...' entry */

					if( delete_sdp_line( msg, payload->rtp_enc.s) < 0 )
					{
						LM_ERR("Unable to add delete lump for a=\n");
						ret = -1;
						goto end;

					}

					if( delete_sdp_line( msg, payload->fmtp_string.s) < 0 )
					{
						LM_ERR("Unable to add delete lump for a=\n");
						ret = -1;
						goto end;

					}

				}

			
				/* if this number equals the one of interest delete it */
				{

					/* take the following whitespaces as well */
					while( cur < lmp->u.value + lmp->len &&  *cur == ' '  )
					{
						cur++;
						found.len++;
					}

					/* delete the string and update iterators */
					for(tmp=found.s ; tmp< lmp->u.value + lmp->len ; tmp++ )
						*tmp  = *(tmp+found.len);

					cur -= found.len;
					lmp->len -= found.len;
				}

				
			
				/* add the deleted number into a buffer to be addded later */
				if( op == ADD_TO_FRONT  || op == ADD_TO_BACK)
				{
					if( buff_len > 0)
					{

						memcpy(&buff[buff_len]," ",1);
						buff_len++;
					}


					memcpy(&buff[buff_len],payload->rtp_payload.s,
						payload->rtp_payload.len);

					buff_len += payload->rtp_payload.len;

				}

				ret = 1;
				
			}

			

			payload = payload->next;
		}

		/* skip spaces if there still are any */
		while( cur < lmp->u.value + lmp->len && * cur == ' '  )
			cur++;

	}


	if( op == ADD_TO_FRONT && buff_len >0 )
	{
		depl = buff_len;
		single = 1;

		if( lmp->len > 0)
		{
			depl++;
			single = 0;
		}

		for( i = lmp->len -1 ; i>=0;i--)
			lmp->u.value[i+depl] = lmp->u.value[i];

		memcpy(lmp->u.value,buff,buff_len);

		if(!single)
			lmp->u.value[buff_len] = ' ';

		lmp->len += depl;

	}

	if( op == ADD_TO_BACK && buff_len >0 )
	{

		if( lmp->len > 0)
		{

			memcpy(&lmp->u.value[lmp->len]," ",1);
			lmp->len++;
		}


		memcpy(&lmp->u.value[lmp->len],buff,buff_len);

		lmp->len += buff_len;

	}

end:
	pkg_free(buff);
	return ret;
}


	


int codec_find (struct sip_msg* msg, char* str1 )
{
	
	if( do_for_all_streams( msg, (str*)str1, NULL, NULL,
		FIND, DESC_NAME) == 0)
		return -1;

	return 1;

}

int codec_find_re (struct sip_msg* msg, char* str1 )
{

	if( do_for_all_streams(msg, NULL, NULL, (regex_t*)str1,
		FIND, DESC_REGEXP) == 0)
		return -1;

	return 1;

}


int codec_find_clock (struct sip_msg* msg, char* str1,char * str2 )
{

	if( do_for_all_streams( msg, (str*)str1, (str*)str2, NULL,
		FIND, DESC_NAME_AND_CLOCK) == 0)
		return -1;

	return 1;

}

int codec_delete (struct sip_msg* msg, char* str1 )
{
	if( do_for_all_streams( msg, (str*)str1, NULL, NULL,
		DELETE, DESC_NAME) == 0)
		return -1;
	return 1;

}

int codec_delete_re (struct sip_msg* msg, char* str1 )
{
	if( do_for_all_streams( msg, NULL, NULL, (regex_t*) str1,
		DELETE, DESC_REGEXP) == 0)
		return -1;
	return 1;

}

int codec_delete_except_re (struct sip_msg* msg, char* str1 )
{
	if( do_for_all_streams( msg, NULL, NULL, (regex_t*) str1,
		DELETE, DESC_REGEXP_COMPLEMENT) == 0)
		return -1;
	return 1;

}

int codec_delete_clock (struct sip_msg* msg, char* str1 ,char * str2)
{
	if( do_for_all_streams( msg, (str*)str1, (str*)str2, NULL,
		DELETE, DESC_NAME_AND_CLOCK) == 0)
		return -1;
	return 1;

}

int codec_move_up (struct sip_msg* msg, char* str1)
{
	if( do_for_all_streams( msg, (str*)str1, NULL, NULL,
		ADD_TO_FRONT, DESC_NAME) == 0)
		return -1;
	return 1;
}

int codec_move_up_re (struct sip_msg* msg, char* str1)
{
	if( do_for_all_streams( msg, NULL, NULL, (regex_t*)str1,
		ADD_TO_FRONT, DESC_REGEXP) == 0)
		return -1;
	return 1;
}


int codec_move_up_clock (struct sip_msg* msg, char* str1 ,char * str2)
{
	if( do_for_all_streams( msg, (str*)str1, (str*)str2, NULL,
		ADD_TO_FRONT, DESC_NAME_AND_CLOCK) == 0)
		return -1;
	return 1;

}


int codec_move_down (struct sip_msg* msg, char* str1)
{
	if( do_for_all_streams( msg, (str*)str1, NULL, NULL,
		ADD_TO_BACK, DESC_NAME) == 0)
		return -1;
	return 1;
}


int codec_move_down_re (struct sip_msg* msg, char* str1)
{
	if( do_for_all_streams( msg, NULL, NULL, (regex_t*)str1,
		ADD_TO_BACK, DESC_REGEXP) == 0)
		return -1;
	return 1;
}




int codec_move_down_clock (struct sip_msg* msg, char* str1 ,char * str2)
{
	if( do_for_all_streams( msg, (str*)str1, (str*)str2, NULL,
		ADD_TO_BACK, DESC_NAME_AND_CLOCK) == 0)
		return -1;
	return 1;

}




