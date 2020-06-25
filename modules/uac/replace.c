/*
 * Copyright (C) 2005-2009 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * UAC OpenSIPS-module is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * UAC OpenSIPS-module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * History:
 * ---------
 *  2005-01-31  first version (ramona)
 *  2005-08-12  encoded old FROM URI stored in RR hdr and not in FROM anymore;
 *              some TM callbacks replaced with RR callback - more efficient;
 *              XOR used to mix together old and new URI
 *              (bogdan)
 *  2006-03-03  new display name is added even if there is no previous one
 *              (bogdan)
 *  2006-03-03  the RR parameter is encrypted via XOR with a password
 *              (bogdan)
 *  2009-08-22  TO header replacement added (bogdan)
 */


#include <ctype.h>

#include "../../parser/parse_from.h"
#include "../../mem/mem.h"
#include "../../data_lump.h"
#include "../tm/h_table.h"
#include "../tm/tm_load.h"
#include "../rr/api.h"
#include "../dialog/dlg_load.h"
#include "../../usr_avp.h"

#include "replace.h"

extern str uac_passwd;
extern int restore_mode;
extern str rr_from_param;
extern str rr_from_param_new;
extern str rr_to_param;
extern str rr_to_param_new;
extern struct tm_binds uac_tmb;
extern struct rr_binds uac_rrb;
extern struct dlg_binds dlg_api;
extern int force_dialog;

extern int_str rr_from_avp;
extern int_str rr_to_avp;

extern pv_spec_t from_bavp_spec;
extern pv_spec_t to_bavp_spec;

static char enc_table64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz0123456789+/";

static int dec_table64[256];

static void restore_uris_reply(struct cell* c, int t, struct tmcb_params *p);
void move_bavp_callback(struct cell* t, int type, struct tmcb_params *p);
static void replace_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params);

#define text3B64_len(_l)   ( ( ((_l)+2)/3 ) << 2 )


void init_from_replacer(void)
{
	int i;

	for( i=0 ; i<256 ; i++)
		dec_table64[i] = -1;
	for ( i=0 ; i<64; i++)
		dec_table64[(unsigned char)enc_table64[i]] = i;
	}


static inline int encode_uri( str *src, str *dst )
{
	static char buf[text3B64_len(MAX_URI_SIZE)];
	int  idx;
	int  left;
	int  block;
	int  i,r;
	char *p;

	dst->len = text3B64_len( src->len );
	dst->s = buf;
	if (dst->len>text3B64_len(MAX_URI_SIZE))
	{
		LM_ERR("uri too long\n");
		return -1;
	}

	for ( idx=0, p=buf ; idx<src->len ; idx+=3)
	{
		left = src->len - idx -1 ;
		left = (left>1? 2 : left);

		/* Collect 1 to 3 bytes to encode */
		block = 0;
		for ( i=0,r= 16 ; i<=left ; i++,r-=8 )
		{
			block += ((unsigned char)src->s[idx+i]) << r;
		}

		/* Encode into 2-4 chars appending '=' if not enough data left.*/
		*(p++) = enc_table64[(block >> 18) & 0x3f];
		*(p++) = enc_table64[(block >> 12) & 0x3f];
		*(p++) = left > 0 ? enc_table64[(block >> 6) & 0x3f] : '-';
		*(p++) = left > 1 ? enc_table64[block & 0x3f] : '-';
	}

	return 0;
}


static inline int decode_uri( str *src , str *dst)
{
	static char buf[MAX_URI_SIZE];
	int block;
	int n;
	int idx;
	int end;
	int i,j;
	char c;

	/* Count '-' at end and disregard them */
	for( n=0,i=src->len-1; src->s[i]=='-'; i--)
		n++;

	dst->len = ((src->len * 6) >> 3) - n;
	dst->s = buf;
	if (dst->len>MAX_URI_SIZE)
	{
		LM_ERR("uri too long\n");
		return -1;
	}

	end = src->len - n;
	for ( i=0,idx=0 ; i<end ; idx+=3 )
	{
		/* Assemble three bytes into an int from four "valid" characters */
		block = 0;
		for ( j=0; j<4 && i<end ; j++)
		{
			c = dec_table64[(unsigned char)src->s[i++]];
			if ( c<0 )
			{
				LM_ERR("invalid base64 string\"%.*s\"\n",src->len,src->s);
				return -1;
			}
			block += c << (18 - 6*j);
		}

		/* Add the bytes */
		for ( j=0,n=16 ; j<3 && idx+j< dst->len; j++,n-=8 )
			buf[idx+j] = (char) ((block >> n) & 0xff);
	}

	return 0;
}


static inline struct lump* get_display_anchor(struct sip_msg *msg,
							struct hdr_field *hdr, str *dsp, int add_laquotes)
{
	struct lump* l;
	struct to_body *body = (struct to_body *)hdr->parsed;
	char *p, *lim;

	/* is URI enclosed or not? */
	for (p = body->uri.s-1, lim = hdr->name.s+hdr->name.len; p>=lim; p--) {
		if (*p=='<') {
			l = anchor_lump( msg, (body->uri.s-1) - msg->buf, 0);
			if (l==0) {
				LM_ERR("unable to build lump anchor\n");
				return 0;
			}
			dsp->s[dsp->len++] = ' ';
			return l;
		}
	}

	if (add_laquotes) {
		/* place the closing angle quote */
		l = anchor_lump( msg, (body->uri.s+body->uri.len) - msg->buf, 0);
		if (l==0) {
			LM_ERR("unable to build lump anchor\n");
			return 0;
		}
		p = (char*)pkg_malloc(1);
		if (p==0) {
			LM_ERR("no more pkg mem \n");
			return 0;
		}
		*p = '>';
		if (insert_new_lump_after( l, p, 1, 0)==0) {
			LM_ERR("insert lump failed\n");
			pkg_free(p);
			return 0;
		}
	}

	/* build anchor for display */
	l = anchor_lump( msg, body->uri.s - msg->buf, 0);
	if (l==0) {
		LM_ERR("unable to build lump anchor\n");
		return 0;
	}

	if (add_laquotes) {
		/* ... and the opening angle quote */
		dsp->s[dsp->len++] = ' ';
		dsp->s[dsp->len++] = '<';
	}

	return l;
}


/*
 * Expand the @uri buffer to include its enclosing left-angle quotes
 * (< and >), if they are present within the given @llim and @rlim boundaries.
 */
static inline void expand_aquotes(str *uri, const char *llim, const char *rlim)
{
	char *p;

	for (p = uri->s; p >= llim; p--) {
		if (*p == '<') {
			uri->len += (uri->s - p);
			uri->s = p;

			/* we are guaranteed to find a '>', since parse_header() worked */
			for (p = uri->s + uri->len - 1; p < rlim; p++, uri->len++)
				if (*p == '>')
					return;

			return;
		}
	}
}


/*
 * relace uri and/or display name in FROM / TO header
 */
int replace_uri( struct sip_msg *msg, str *display, str *uri,
										struct hdr_field *hdr, int to)
{
	static char buf_s[MAX_URI_SIZE];
	struct to_body *body;
	struct lump* l;
	struct cell *Trans;
	str *rr_param, replace, old_uri;
	str param, buf;
	char *p;
	int uac_flag, i, ret;
	struct dlg_cell *dlg = NULL;
	pv_value_t val;

	/* consistency check! in AUTO mode, do NOT allow URI changing
	 * in sequential request */
	if (restore_mode==UAC_AUTO_RESTORE && uri && uri->len) {
		if ( msg->to==0 && (parse_headers(msg,HDR_TO_F,0)!=0 || msg->to==0) ) {
			LM_ERR("failed to parse TO hdr\n");
			goto error;
		}
		if (get_to(msg)->tag_value.len!=0) {
			LM_ERR("decline FROM/TO replacing in sequential request "
				"in auto mode (has TO tag)\n");
			goto error;
		}
	}

	body = (struct to_body*)hdr->parsed;

	/* first deal with display name */
	if (display) {
		/* must be replaced/ removed */
		l = 0;
		/* first remove the existing display */
		if ( body->display.len) {
			LM_DBG("removing display [%.*s]\n",
				body->display.len,body->display.s);
			/* build del lump */
			l = del_lump( msg, body->display.s-msg->buf, body->display.len, 0);
			if (l==0) {
				LM_ERR("display del lump failed\n");
				goto error;
			}
		}
		/* some new display to set? */
		if (display->len) {
			/* add the new display exactly over the deleted one */
			buf.s = pkg_malloc( display->len + 2 );
			if (buf.s==0) {
				LM_ERR("no more pkg mem\n");
				goto error;
			}
			memcpy( buf.s, display->s, display->len);
			buf.len =  display->len;
			if (l==0 && (l=get_display_anchor(msg, hdr, &buf, ZSTRP(uri)))==0)
			{
				LM_ERR("failed to insert anchor\n");
				goto error;
			}
			if (insert_new_lump_after( l, buf.s, buf.len, 0)==0)
			{
				LM_ERR("insert new display lump failed\n");
				pkg_free(buf.s);
				goto error;
			}
		}
	}

	/* now handle the URI */
	if (uri==0 || uri->len==0 )
		/* do not touch URI part */
		return 0;

	p = pkg_malloc(1 + uri->len + 1 + 1);
	if (!p) {
		LM_ERR("no more pkg mem\n");
		goto error;
	}

	uri->len = sprintf(p, "<%.*s>", uri->len, uri->s);
	uri->s = p;

	/* trim away any <, > (the replacement URI always includes them) */
	old_uri = body->uri;
	expand_aquotes(&old_uri,
			hdr->name.s + hdr->name.len,
			hdr->body.s + hdr->body.len);

	LM_DBG("uri to replace [%.*s], replacement is [%.*s]\n",
		old_uri.len, old_uri.s, uri->len, uri->s);

	/* build del/add lumps */
	if ((l=del_lump( msg, old_uri.s - msg->buf, old_uri.len, 0))==0) {
		LM_ERR("del lump failed\n");
		goto error;
	}

	if (insert_new_lump_after(l, uri->s, uri->len, 0)==0) {
		LM_ERR("insert new lump failed\n");
		pkg_free(p);
		goto error;
	}

	if (restore_mode==UAC_NO_RESTORE)
		return 0;

	/* trying to create/get dialog */
	if (dlg_api.get_dlg) {
		dlg = dlg_api.get_dlg();
		/* if the dialog doesn't already exist */
		if (!dlg && force_dialog) {
			if (dlg_api.create_dlg(msg,0) < 0) {
				LM_ERR("cannot create dialog\n");
				goto error;
			}
			dlg = dlg_api.get_dlg();
		}
	}
	rr_param = to ? &rr_to_param : &rr_from_param;

	uac_flag = (hdr==msg->from)?FL_USE_UAC_FROM:FL_USE_UAC_TO;

	/* if using dialog, store the result */
	if (dlg) {
		val.rs = body->uri;
		val.flags = AVP_VAL_STR;
		ret = pv_set_value(msg,(to?&to_bavp_spec:&from_bavp_spec),EQ_T,&val);
		/* if function call was in branch route - store in bavp */
		if (ret < 0) {
			if (ret == -2) {
				/* the call wasn't in branch route - store in dlg */
				if (dlg_api.store_dlg_value(dlg, rr_param, &body->uri) < 0) {
					LM_ERR("cannot store value\n");
					goto error;
				}
				LM_DBG("stored <%.*s> param in dialog\n", rr_param->len, rr_param->s);
			} else {
				LM_ERR("cannot store branch avp to restore at 200 OK!\n");
			}
		} else {
			if (!(msg->msg_flags&uac_flag)){
				if (uac_tmb.register_tmcb( msg, 0, TMCB_RESPONSE_OUT,
						move_bavp_callback,0,0)!=1) {
					LM_ERR("failed to install TM callback\n");
					goto error;
				}
			}
		}
		if (dlg_api.store_dlg_value(dlg,
					to ? &rr_to_param_new : &rr_from_param_new, uri) < 0) {
			LM_ERR("cannot store new uri value\n");
			goto error;
		}
		if (!(msg->msg_flags&uac_flag) &&
				dlg_api.register_dlgcb(dlg, DLGCB_REQ_WITHIN|DLGCB_TERMINATED,
					replace_callback, (void*)(unsigned long)to, 0) != 0) {
			LM_ERR("cannot register callback\n");
			goto error;
		}
	} else {
		/* build RR parameter */
		buf.s = buf_s;
		if ( body->uri.len>uri->len ) {
			if (body->uri.len>MAX_URI_SIZE) {
				LM_ERR("old %.*s uri too long\n",hdr->name.len,hdr->name.s);
				goto error;
			}
			memcpy( buf.s, body->uri.s, body->uri.len);
			for( i=0 ; i<uri->len ; i++ )
				buf.s[i] ^=uri->s[i];
			buf.len = body->uri.len;
		} else {
			if (uri->len>MAX_URI_SIZE) {
				LM_ERR("new %.*s uri too long\n",hdr->name.len,hdr->name.s);
				goto error;
			}
			memcpy( buf.s, uri->s, uri->len);
			for( i=0 ; i<body->uri.len ; i++ )
				buf.s[i] ^=body->uri.s[i];
			buf.len = uri->len;
		}

		/* encrypt parameter ;) */
		if (uac_passwd.len)
			for( i=0 ; i<buf.len ; i++)
				buf.s[i] ^= uac_passwd.s[i%uac_passwd.len];

		/* encode the param */
		if (encode_uri( &buf , &replace)<0 )
		{
			LM_ERR("failed to encode uris\n");
			goto error;
		}
		LM_DBG("encode is=<%.*s> len=%d\n",replace.len,replace.s,replace.len);

		/* add RR parameter */
		param.len = 1+rr_param->len+1+replace.len;
		param.s = (char*)pkg_malloc(param.len);
		if (param.s==0)
		{
			LM_ERR("no more pkg mem\n");
			goto error;
		}
		p = param.s;
		*(p++) = ';';
		memcpy( p, rr_param->s, rr_param->len);
		p += rr_param->len;
		*(p++) = '=';
		memcpy( p, replace.s, replace.len);
		p += replace.len;

		if (uac_rrb.add_rr_param( msg, &param)!=0)
		{
			LM_ERR("add_RR_param failed\n");
			goto error1;
		}
		pkg_free(param.s);
	}

	if ((msg->msg_flags&uac_flag)==0) {
		/* first time here ? */
		if ((msg->msg_flags&(FL_USE_UAC_FROM|FL_USE_UAC_TO))==0){
			/* add TM callback to restore the FROM/TO hdr in reply */
			if (uac_tmb.register_tmcb( msg, 0, TMCB_RESPONSE_IN,
			restore_uris_reply,0,0)!=1) {
				LM_ERR("failed to install TM callback\n");
				goto error;
			}
		}
		/* set TO/ FROM sepcific flags */
		msg->msg_flags |= uac_flag;
		if ( (Trans=uac_tmb.t_gett())!=NULL && Trans!=T_UNDEFINED &&
		Trans->uas.request)
			Trans->uas.request->msg_flags |= uac_flag;
	}

	return 0;
error1:
	pkg_free(param.s);
error:
	return -1;
}


/*
 * return  0 - restored
 *        -1 - not restored or error
 */
int restore_uri( struct sip_msg *msg, int to, int check_from)
{
	struct hdr_field *old_hdr;
	struct lump* l;
	str param_val;
	str old_uri, ou;
	str new_uri;
	str *rr_param;
	char *p;
	int i;
	int flag;

	/* we should process only sequntial request, but since we are looking
	 * for Route param, the test is not really required -bogdan */

	rr_param = to ? &rr_to_param : &rr_from_param;

	LM_DBG("getting '%.*s' Route param\n",
		rr_param->len,rr_param->s);
	/* is there something to restore ? */
	if (uac_rrb.get_route_param( msg, rr_param, &param_val)!=0) {
		LM_DBG("route param '%.*s' not found\n",
			rr_param->len,rr_param->s);
		goto failed;
	}
	LM_DBG("route param is '%.*s' (len=%d)\n",
		param_val.len,param_val.s,param_val.len);

	/* decode the parameter val to a URI */
	if (decode_uri( &param_val, &new_uri)<0 ) {
		LM_ERR("failed to decode uri\n");
		goto failed;
	}

	/* dencrypt parameter ;) */
	if (uac_passwd.len)
		for( i=0 ; i<new_uri.len ; i++)
			new_uri.s[i] ^= uac_passwd.s[i%uac_passwd.len];

	/* check the request direction */
	if ( (check_from && uac_rrb.is_direction( msg, RR_FLOW_UPSTREAM)==0) ||
	(!check_from && uac_rrb.is_direction( msg, RR_FLOW_DOWNSTREAM)==0)  ) {
		/* replace the TO URI */
		if ( msg->to==0 && (parse_headers(msg,HDR_TO_F,0)!=0 || msg->to==0) ) {
			LM_ERR("failed to parse TO hdr\n");
			goto failed;
		}
		ou = old_uri = ((struct to_body*)msg->to->parsed)->uri;
		old_hdr = msg->to;
		flag = FL_USE_UAC_TO;
	} else {
		/* replace the FROM URI */
		if ( parse_from_header(msg)<0 ) {
			LM_ERR("failed to find/parse FROM hdr\n");
			goto failed;
		}
		ou = old_uri = ((struct to_body*)msg->from->parsed)->uri;
		old_hdr = msg->from;
		flag = FL_USE_UAC_FROM;
	}

	if (uac_rrb.is_direction(msg, RR_FLOW_UPSTREAM) == 0)
		expand_aquotes(&old_uri,
				old_hdr->name.s + old_hdr->name.len,
				old_hdr->body.s + old_hdr->body.len);

	/* get new uri */
	if ( new_uri.len<old_uri.len ) {
		if (parse_headers(msg,HDR_CALLID_F,0) < 0) {
			LM_ERR("cannot find callid!\n");
			goto failed;
		}
		if (msg->callid)
			LM_ERR("new URI shorter than old URI (callid=%.*s)\n",
				msg->callid->body.len,msg->callid->body.s);
		else
			LM_ERR("new URI shorter than old URI (callid=?)\n");
		goto failed;
	}
	for( i=0 ; i<old_uri.len ; i++ )
		new_uri.s[i] ^= old_uri.s[i];
	if (new_uri.len==old_uri.len) {
		for( ; new_uri.len && (new_uri.s[new_uri.len-1]==0) ; new_uri.len-- );
		if (new_uri.len==0) {
			LM_ERR("new URI got 0 len\n");
			goto failed;
		}
	}

	LM_DBG("decoded uris are: new=[%.*s] old=[%.*s]\n",
		new_uri.len, new_uri.s, old_uri.len, old_uri.s);

	/* duplicate the decoded value */
	p = pkg_malloc( new_uri.len);
	if (p==0) {
		LM_ERR("no more pkg mem\n");
		goto failed;
	}
	memcpy( p, new_uri.s, new_uri.len);
	new_uri.s = p;

	old_uri = ou;
	if (uac_rrb.is_direction(msg, RR_FLOW_DOWNSTREAM) == 0)
		expand_aquotes(&old_uri,
				old_hdr->name.s + old_hdr->name.len,
				old_hdr->body.s + old_hdr->body.len);

	/* build del/add lumps */
	l = del_lump( msg, old_uri.s-msg->buf, old_uri.len, 0);
	if (l==0) {
		LM_ERR("del lump failed\n");
		goto failed1;
	}

	if (insert_new_lump_after( l, new_uri.s, new_uri.len, 0)==0) {
		LM_ERR("insert new lump failed\n");
		goto failed1;
	}

	msg->msg_flags |= flag;

	return 0;
failed1:
	pkg_free(new_uri.s);
failed:
	return -1;
}

/************************** Dialog functions ******************************/

void dlg_restore_callback(struct dlg_cell* dlg, int type, struct dlg_cb_params * params)
{
	str val;

	/* check if the UAC corresponding values are present */

	if ( dlg_api.fetch_dlg_value( dlg, &rr_to_param_new, &val, 0)==0 ) {
		/* TO variable found -> TO URI changed */
		LM_DBG("UAC TO related DLG vals found -> installing callback\n");
		if ( dlg_api.register_dlgcb(dlg, DLGCB_REQ_WITHIN|DLGCB_TERMINATED,
		replace_callback, (void*)1/*to*/, 0) != 0) {
			LM_ERR("cannot register callback\n");
		}
	}

	if ( dlg_api.fetch_dlg_value( dlg, &rr_from_param_new, &val, 0)==0 ) {
		/* FROM variable found -> FROM URI changed */
		LM_DBG("UAC FROM related DLG vals found -> installing callback\n");
		if ( dlg_api.register_dlgcb(dlg, DLGCB_REQ_WITHIN|DLGCB_TERMINATED,
		replace_callback, (void*)0/*from*/, 0) != 0) {
			LM_ERR("cannot register callback\n");
		}
	}

	return;
}



static void replace_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params)
{
	struct lump* l;
	struct sip_msg *msg;
	struct hdr_field *old_hdr;
	str *rr_param;
	str old_uri;
	str new_uri;
	int to, flag;
	char *p;

	if (!dlg || !_params || _params->direction == DLG_DIR_NONE || !_params->msg)
		return;

	msg = _params->msg;

	to = *(_params->param) ? 1 : 0;

	/* check the request direction */
	if ((to && _params->direction == DLG_DIR_DOWNSTREAM) ||
		(!to && _params->direction == DLG_DIR_UPSTREAM)) {
		/* replace the TO URI */
		if ( msg->to==0 && (parse_headers(msg,HDR_TO_F,0)!=0 || msg->to==0) ) {
			LM_ERR("failed to parse TO hdr\n");
			return;
		}
		old_uri = ((struct to_body*)msg->to->parsed)->uri;
		old_hdr = msg->to;
		flag = FL_USE_UAC_TO;
	} else {
		/* replace the FROM URI */
		if ( parse_from_header(msg)<0 ) {
			LM_ERR("failed to find/parse FROM hdr\n");
			return;
		}
		old_uri = ((struct to_body*)msg->from->parsed)->uri;
		old_hdr = msg->from;
		flag = FL_USE_UAC_FROM;
	}

	if (msg->msg_flags & flag)
		return;

	if (_params->direction == DLG_DIR_DOWNSTREAM) {
		/* not upstream */
		rr_param = to ? &rr_to_param_new : &rr_from_param_new;
		LM_DBG("DOWNSTREAM direction detected - replacing %s header"
				" with the uac_replace_%s() parameters\n",
				to ? "TO" : "FROM", to ? "to": "from");
	} else {
		rr_param = to ? &rr_to_param : &rr_from_param;
		LM_DBG("UPSTREAM direction detected - replacing %s header"
				" with the original headers\n", to ? "TO" : "FROM");
	}

	if (dlg_api.fetch_dlg_value(dlg, rr_param, &new_uri, 0) < 0) {
		LM_DBG("<%.*s> param not found\n", rr_param->len, rr_param->s);
		return;
	}

	LM_DBG("decoded uris are: new=[%.*s] old=[%.*s]\n",
		new_uri.len, new_uri.s, old_uri.len, old_uri.s);

	/* duplicate the decoded value */
	p = pkg_malloc( new_uri.len);
	if (!p) {
		LM_ERR("no more pkg mem\n");
		return;
	}
	memcpy( p, new_uri.s, new_uri.len);
	new_uri.s = p;

	/* trim away any <, > (the replacement URI always includes them) */
	if (_params->direction == DLG_DIR_DOWNSTREAM)
		expand_aquotes(&old_uri,
				old_hdr->name.s + old_hdr->name.len,
				old_hdr->body.s + old_hdr->body.len);

	/* build del/add lumps */
	l = del_lump( msg, old_uri.s-msg->buf, old_uri.len, 0);
	if (l==0) {
		LM_ERR("del lump failed\n");
		goto free;
	}

	if (insert_new_lump_after( l, new_uri.s, new_uri.len, 0)==0) {
		LM_ERR("insert new lump failed\n");
		goto free;
	}

	/* change replies but only if not registered earlier */
	if (!(msg->msg_flags & (FL_USE_UAC_FROM|FL_USE_UAC_TO)) &&
			uac_tmb.register_tmcb( msg, 0, TMCB_RESPONSE_IN,
			restore_uris_reply, 0, 0) != 1 ) {
		LM_ERR("failed to install TM callback\n");
		return;
	}

	msg->msg_flags |= flag;
	return;

free:
	pkg_free(new_uri.s);
}


/************************** RRCB functions ******************************/

void rr_checker(struct sip_msg *msg, str *r_param, void *cb_param)
{
	/* check if the request contains the route param */
	if ( (restore_uri( msg, 0, 1/*from*/) +
	restore_uri( msg, 1, 0/*to*/) )!= -2 ) {
		/* restore in req performed -> replace in reply */
		/* in callback we need TO/FROM to be parsed- it's already done
		 * by restore_from_to() function */
		if ( uac_tmb.register_tmcb( msg, 0, TMCB_RESPONSE_IN,
		restore_uris_reply, 0, 0)!=1 ) {
			LM_ERR("failed to install TM callback\n");
				return;
		}
	}
}


/************************** TMCB functions ******************************/


static inline int restore_uri_reply(struct sip_msg *rpl,
						struct to_body *rpl_hdr, struct to_body *req_hdr)
{
	struct lump* l;
	struct to_body *body;
	str new_val;
	int len;
	char *p;

	/* duplicate the new hdr value */
	body = req_hdr;
	for( p = body->uri.s+body->uri.len, len=0; isspace(p[len]) ; len++ );
	len =  p - body->body.s + ((p[len]=='>') ? (len+1) : 0) ;
	new_val.s = pkg_malloc( len );
	if (new_val.s==0) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memcpy( new_val.s, body->body.s, len);
	new_val.len = len;

	body = rpl_hdr;
	for( p = body->uri.s+body->uri.len, len=0; isspace(p[len]) ; len++ );
	len =  p - body->body.s + ((p[len]=='>') ? (len+1) : 0) ;
	LM_DBG("removing <%.*s>\n", len,body->body.s);
	l = del_lump( rpl, body->body.s-rpl->buf, len, 0);
	if (l==0) {
		LM_ERR("del lump failed\n");
		pkg_free( new_val.s );
		return -1;
	}

	LM_DBG("inserting <%.*s>\n",
			new_val.len,new_val.s);
	if (insert_new_lump_after( l, new_val.s, new_val.len, 0)==0) {
		LM_ERR("insert new lump failed\n");
		pkg_free( new_val.s );
		l->len = 0;
		return -1;
	}

	return 0;
}

/* moves the selected branch avps into dialog */
int move_bavp_dlg( struct sip_msg *msg, str* rr_param, pv_spec_t *store_spec)
{
	struct dlg_cell *dlg = NULL;
	unsigned int code = 0;
	pv_value_t value;

	if (!dlg_api.get_dlg)
		goto not_moved;

	dlg = dlg_api.get_dlg();
	if (!dlg) {
		LM_DBG("dialog not found - cannot move branch avps\n");
		goto not_moved;
	}

	code = msg->first_line.u.reply.statuscode;
	if (msg->first_line.type == SIP_REPLY && code >= 200 && code < 300) {
		/* check to see if there are bavps stored */
		if (pv_get_spec_value(msg, store_spec, &value)) {
			LM_DBG("bavp not found!\n");
			goto not_moved;
		}
		if (!(value.flags & PV_VAL_STR)) {
			LM_DBG("bug - invalid bavp type\n");
			goto not_moved;
		}
		if (dlg_api.store_dlg_value(dlg, rr_param, &value.rs) < 0) {
			LM_ERR("cannot store value\n");
			return -1;
		}

		LM_DBG("moved <%.*s> from branch avp list in dlg\n",
				rr_param->len, rr_param->s);
		return 1;
	}

not_moved:
/*	LM_DBG("nothing moved - message type %d code %u\n",
		msg->first_line.type, code);*/
	return 0;
}

/* callback for tm RESPONSE_OUT */
void move_bavp_callback(struct cell* t, int type, struct tmcb_params *p)
{
	struct sip_msg *req;
	struct sip_msg *rpl;

	if ( !t || !t->uas.request || !p->rpl )
		return;

	req = t->uas.request;
	rpl = p->rpl;
	if (req == FAKED_REPLY || rpl == FAKED_REPLY)
		return;

	if (req->msg_flags & FL_USE_UAC_FROM &&
			(move_bavp_dlg(rpl, &rr_from_param, &from_bavp_spec) < 0))
		LM_ERR("failed to move bavp list\n");

	if (req->msg_flags & FL_USE_UAC_TO &&
				(move_bavp_dlg( rpl, &rr_to_param, &to_bavp_spec) < 0))
		LM_ERR("failed to move bavp list\n");
}

/* replace the entire from HDR with the original FROM request */
void restore_uris_reply(struct cell* t, int type, struct tmcb_params *p)
{
	struct sip_msg *req;
	struct sip_msg *rpl;
	struct to_body local_body;

	if ( !t || !t->uas.request || !p->rpl )
		return;

	req = t->uas.request;
	rpl = p->rpl;
	if (req == FAKED_REPLY || rpl == FAKED_REPLY)
		return;

	if (req->msg_flags & FL_USE_UAC_FROM ) {
		/* parse FROM in reply */
		if (parse_from_header( rpl )<0 ) {
			LM_ERR("failed to find/parse FROM hdr\n");
			return;
		}
		if (req->from->parsed) {
			/* FROM body is already parsed */
			if (restore_uri_reply( rpl, (struct to_body*)rpl->from->parsed,
			(struct to_body*)req->from->parsed))
				LM_ERR("failed to restore FROM\n");
		} else {
			/* FROM body has to be locally parsed and freed */
			memset( &local_body, 0, sizeof(struct to_body));
			parse_to( req->from->body.s,
				req->from->body.s+req->from->body.len+1, &local_body);
			if (local_body.error == PARSE_ERROR) {
				LM_ERR("failed to parse FROM hdr from TM'ed request\n");
			} else {
				if (restore_uri_reply( rpl, (struct to_body*)rpl->from->parsed,
				&local_body))
					LM_ERR("failed to restore FROM\n");
				free_to_params( &local_body );
			}
		}
	}

	if (req->msg_flags & FL_USE_UAC_TO ) {
		/* parse TO in reply */
		if ( rpl->to==0 && (parse_headers(rpl,HDR_TO_F,0)!=0 || rpl->to==0) ) {
			LM_ERR("failed to parse TO hdr\n");
			return;
		}
		/* TO body should be allways parsed  */
		if (restore_uri_reply( rpl, (struct to_body*)rpl->to->parsed,
		(struct to_body*)req->to->parsed) )
			LM_ERR("failed to restore FROM\n");
	}
}

