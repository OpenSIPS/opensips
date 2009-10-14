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





static struct _static_data_t
{
	unsigned int last_id;
	struct lump ** lumps;
	int len;
	struct sip_msg * msg;
}data;

enum{
	FIND,
	DELETE,
	ADD_TO_FRONT,
	ADD_TO_BACK
};


typedef  int (*stream_func)(struct sdp_stream_cell *cell, int pos,
	str * str1, str* str2, regex_t * re, int op);

int codec_init(void)
{
	data.last_id = (unsigned int)-1;
	data.lumps = NULL;

	return 0;
}

int fixup_codec(void** param, int param_no)
{
	str * s = pkg_malloc(sizeof(str));
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

static int do_for_all_streams(struct sip_msg* msg, str* str1,str * str2,
				regex_t* re, int op, stream_func f)
{
	struct sdp_session_cell * cur_session;
	int count, rez;


	if(parse_sdp(msg))
	{
		LM_DBG("Message has no SDP\n");
		return -1;
	}

	if( data.last_id  != msg->id )
	{
		

		/* get the number of streams */
		count = 0;
		cur_session = msg->sdp->sessions;

		while(cur_session)
		{
			count += cur_session->streams_num;
			cur_session = cur_session->next;
		}


		
		data.lumps = pkg_realloc(data.lumps,count * sizeof(struct lump*));
		

		if( data.lumps == NULL)
		{
			LM_ERR("Out of memory\n");
			return -1;
		}


		/* for each stream create a specific lump for deletion an one for
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

				if( l == NULL)
				{
					LM_ERR("Error adding delete lump for m=\n");
					return -1;
				}

				text.len = cur_cell->payloads.len;
				text.s = (char*)pkg_malloc(cur_cell->payloads.len);

				memcpy(text.s,cur_cell->payloads.s,cur_cell->payloads.len);

				
				data.lumps[count] = insert_new_lump_after( l,
							text.s, text.len, 0);

				if(data.lumps[count] == NULL)
				{
					LM_ERR("Error adding insert lump for m=\n");

				}

				count ++;
				cur_cell = cur_cell->next;
			}

			cur_session = cur_session->next;

		}

		data.last_id = msg->id;
		data.msg = msg;
	}

	count = 0 ;
	cur_session = msg->sdp->sessions;
	rez = 0;


	while(cur_session)
	{
		struct sdp_stream_cell * cur_cell = cur_session->streams;

		while(cur_cell)
		{
			rez |= f(cur_cell,count,str1,str2,re,op);

			count ++;
			cur_cell = cur_cell->next;
		}

		cur_session = cur_session->next;

	}

	if( rez <0 )
		rez = 0;
	return rez;

};




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

	
};



/* method that processes a stream and keeps the original order
 * of codecs with the same name */
static int stream_process(struct sdp_stream_cell *cell,int pos,str * s, str* ss,
				regex_t* re, int op)
{
	sdp_payload_attr_t *payload;
	char *cur, *tmp, *buff, temp;
	struct lump * lmp = data.lumps[pos];
	str found;
	int ret, i, depl, single, match, buff_len;
	regmatch_t pmatch;
	
	
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


			match = 0;

			if( s == NULL )
			{
				/* try to match a regexp */
				temp = payload->rtp_enc.s[payload->rtp_enc.len];
				payload->rtp_enc.s[payload->rtp_enc.len] = 0;
				match = regexec( re, payload->rtp_enc.s, 1, &pmatch, 0) == 0;
				payload->rtp_enc.s[payload->rtp_enc.len] = temp;
			}
			else
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

					if( delete_sdp_line( data.msg, payload->rtp_enc.s) < 0 )
					{
						LM_ERR("Unable to add delete lump for a=\n");
						ret = -1;
						goto end;

					}

					if( delete_sdp_line( data.msg, payload->fmtp_string.s) < 0 )
					{
						LM_ERR("Unable to add delete lump for a=\n");
						ret = -1;
						goto end;

					}

				}

			
				/* if this number equals the one of interest delete it */
				{

					/* take the following whitespaces as well */
					while( *cur == ' ' && cur < lmp->u.value + lmp->len)
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
		while(* cur == ' ' && cur < lmp->u.value + lmp->len)
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
};


	


int codec_find (struct sip_msg* msg, char* str1 )
{
	
	if( do_for_all_streams( msg, (str*)str1, NULL, NULL,
		FIND, stream_process) == 0)
		return -1;

	return 1;

};

int codec_find_re (struct sip_msg* msg, char* str1 )
{

	if( do_for_all_streams(msg, NULL, NULL, (regex_t*)str1,
		FIND, stream_process) == 0)
		return -1;

	return 1;

};


int codec_find_clock (struct sip_msg* msg, char* str1,char * str2 )
{

	if( do_for_all_streams( msg, (str*)str1, (str*)str2, NULL,
		FIND, stream_process) == 0)
		return -1;

	return 1;

};

int codec_delete (struct sip_msg* msg, char* str1 )
{
	if( do_for_all_streams( msg, (str*)str1, NULL, NULL,
		DELETE, stream_process) == 0)
		return -1;
	return 1;

};

int codec_delete_re (struct sip_msg* msg, char* str1 )
{
	if( do_for_all_streams( msg, NULL, NULL, (regex_t*) str1,
		DELETE, stream_process) == 0)
		return -1;
	return 1;

};

int codec_delete_clock (struct sip_msg* msg, char* str1 ,char * str2)
{
	if( do_for_all_streams( msg, (str*)str1, (str*)str2, NULL,
		DELETE, stream_process) == 0)
		return -1;
	return 1;

};

int codec_move_up (struct sip_msg* msg, char* str1)
{
	if( do_for_all_streams( msg, (str*)str1, NULL, NULL,
		ADD_TO_FRONT, stream_process) == 0)
		return -1;
	return 1;
};

int codec_move_up_re (struct sip_msg* msg, char* str1)
{
	if( do_for_all_streams( msg, NULL, NULL, (regex_t*)str1,
		ADD_TO_FRONT, stream_process) == 0)
		return -1;
	return 1;
};


int codec_move_up_clock (struct sip_msg* msg, char* str1 ,char * str2)
{
	if( do_for_all_streams( msg, (str*)str1, (str*)str2, NULL,
		ADD_TO_FRONT, stream_process) == 0)
		return -1;
	return 1;

};


int codec_move_down (struct sip_msg* msg, char* str1)
{
	if( do_for_all_streams( msg, (str*)str1, NULL, NULL,
		ADD_TO_BACK, stream_process) == 0)
		return -1;
	return 1;
};


int codec_move_down_re (struct sip_msg* msg, char* str1)
{
	if( do_for_all_streams( msg, NULL, NULL, (regex_t*)str1,
		ADD_TO_BACK, stream_process) == 0)
		return -1;
	return 1;
};




int codec_move_down_clock (struct sip_msg* msg, char* str1 ,char * str2)
{
	if( do_for_all_streams( msg, (str*)str1, (str*)str2, NULL,
		ADD_TO_BACK, stream_process) == 0)
		return -1;
	return 1;

};




