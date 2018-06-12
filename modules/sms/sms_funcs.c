/*
 * $Id$
 *
 * Copyright (C) 2001-2003 Fhg Fokus
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * History:
 * --------
 * 2003-01-23: switched from t_uac to t_uac_dlg, adapted to new way of
 *              parsing for Content-Type (bogdan)
 * 2003-02-28: protocolization of t_uac_dlg completed (jiri)
 * 2003-08-05: adapted to the new parse_content_type_hdr function (bogdan)
 * 2003-09-11: updated to new build_lump_rpl() interface (bogdan)
 * 2003-09-11: force parsing to hdr when extracting destination user (bogdan)
 */

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include "../../dprint.h"
#include "../../ut.h"
#include "../../config.h"
#include "../../globals.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_content.h"
#include "../../parser/parse_from.h"
#include "../../data_lump_rpl.h"
#include "../tm/t_hooks.h"
#include "../tm/uac.h"
#include "sms_funcs.h"
#include "sms_report.h"
#include "libsms_modem.h"
#include "libsms_sms.h"




struct modem modems[MAX_MODEMS];
struct network networks[MAX_NETWORKS];
int net_pipes_in[MAX_NETWORKS];
int nr_of_networks;
int nr_of_modems;
int max_sms_parts;
int *queued_msgs;
int use_contact;
int sms_report_type;
struct tm_binds tmb;


#define ERR_NUMBER_TEXT " is an invalid number! Please resend your SMS "\
	"using a number in +(contry code)(area code)(local number) format. Thanks"\
	" for using our service!"
#define ERR_NUMBER_TEXT_LEN (sizeof(ERR_NUMBER_TEXT)-1)

#define ERR_TRUNCATE_TEXT "We are sorry, but your message exceeded our "\
	"maximum allowed length. The following part of the message wasn't sent"\
	" : "
#define ERR_TRUNCATE_TEXT_LEN (sizeof(ERR_TRUNCATE_TEXT)-1)

#define ERR_MODEM_TEXT "Due to our modem temporary indisponibility, "\
	"the following message couldn't be sent : "
#define ERR_MODEM_TEXT_LEN (sizeof(ERR_MODEM_TEXT)-1)

#define STORED_NOTE "NOTE: Your SMS received provisional confirmation"\
	" 48 \"Delivery is not yet possible\". The SMS was store on the "\
	"SMSCenter for further delivery. Our gateway cannot guarantee "\
	"further information regarding your SMS delivery! Your message was: "
#define STORED_NOTE_LEN  (sizeof(STORED_NOTE)-1)

#define OK_MSG "Your SMS was finally successfully delivered!"\
	" Your message was: "
#define OK_MSG_LEN  (sizeof(OK_MSG)-1)

#define CONTENT_TYPE_HDR     "Content-Type: text/plain"
#define CONTENT_TYPE_HDR_LEN (sizeof(CONTENT_TYPE_HDR)-1)

#define append_str(_p,_s,_l) \
	{memcpy((_p),(_s),(_l));\
	(_p) += (_l);}

#define is_in_sip_addr(_p) \
	((_p)!=' ' && (_p)!='\t' && (_p)!='(' && (_p)!='[' && (_p)!='<' \
	&& (_p)!='>' && (_p)!=']' && (_p)!=')' && (_p)!='?' && (_p)!='!' \
	&& (_p)!=';' && (_p)!=',' && (_p)!='\n' && (_p)!='\r' && (_p)!='=')

#define no_sip_addr_begin(_p) \
	( (_p)!=' ' && (_p)!='\t' && (_p)!='-' && (_p)!='=' && (_p)!='\r'\
	&& (_p)!='\n' && (_p)!=';' && (_p)!=',' && (_p)!='.' && (_p)!=':')



#if 0
inline int add_contact(struct sip_msg* msg , str* user)
{
	struct lump_rpl *lump;
	char *buf, *p;
	int len;

	len = 9 /*"Contact: "*/ + user->len/*user*/ + 1 /*"@"*/
		+ domain.len/*host*/ + 6/*"<sip:>"*/ + CRLF_LEN;

	buf = pkg_malloc( len );
	if(!buf) {
		LOG(L_ERR,"ERROR:sms_add_contact: out of memory! \n");
		return -1;
	}

	p = buf;
	append_str( p, "Contact: " , 9);
	append_str( p, "<sip:" , 5);
	append_str( p, user->s, user->len);
	*(p++) = '@';
	append_str( p, domain.s, domain.len);
	*(p++) = '>';
	append_str( p, CRLF, CRLF_LEN);

	lump = build_lump_rpl( buf , len , LUMP_RPL_HDR);
	if(!lump) {
		LOG(L_ERR,"ERROR:sms_add_contact: unable to build lump_rpl! \n");
		pkg_free( buf );
		return -1;
	}
	add_lump_rpl( msg , lump );

	pkg_free(buf);
	return 1;
}
#endif



int push_on_network(struct sip_msg *msg, int net)
{
	str    body;
	struct sip_uri  uri;
	struct sms_msg  *sms_messg;
	struct to_body  *from;
	char   *p;
	int    len;
	int    mime;

	/* get the message's body
	 * anyhow we have to call this function, so let's do it at the beginning
	 * to force the parsing of all the headers - like this we avoid separat
	 * calls of parse_headers function for FROM, CONTENT_LENGTH, TO hdrs  */
	body.s = get_body( msg );
	if (body.s==0) {
		LOG(L_ERR,"ERROR:sms_push_on_net: cannot extract body from msg!\n");
		goto error;
	}

	/* content-length (if present) must be already parsed */
	if (!msg->content_length) {
		LOG(L_ERR,"ERROR:sms_push_on_net: no Content-Length header found!\n");
		goto error;
	}
	body.len = get_content_length( msg );

	/* parse the content-type header */
	if ( (mime=parse_content_type_hdr(msg))<1 ) {
		LOG(L_ERR,"ERROR:sms_push_on_net:cannot parse Content-Type header\n");
		goto error;
	}

	/* check the content-type value */
	if ( mime!=(TYPE_TEXT<<16)+SUBTYPE_PLAIN
	&& mime!=(TYPE_MESSAGE<<16)+SUBTYPE_CPIM ) {
		LOG(L_ERR,"ERROR:sms_push_on_net: invalid content-type for a "
			"message request! type found=%d\n",mime);
		goto error;
	}

	/* we try to get the user name (phone number) first from the RURI 
	   (in our case means from new_uri or from first_line.u.request.uri);
	   if it's missing there (like in requests generated by MSN MESSENGER),
	   we go for "to" header
	*/
	DBG("DEBUG:sms_push_on_net: tring to get user from new_uri\n");
	if ( !msg->new_uri.s||parse_uri( msg->new_uri.s,msg->new_uri.len,&uri)
	|| !uri.user.len )
	{
		DBG("DEBUG:sms_push_on_net: tring to get user from R_uri\n");
		if ( parse_uri( msg->first_line.u.request.uri.s,
		msg->first_line.u.request.uri.len ,&uri)||!uri.user.len )
		{
			DBG("DEBUG:sms_push_on_net: tring to get user from To\n");
			if ( (!msg->to&&((parse_headers(msg,HDR_TO,0)==-1) || !msg->to)) ||
			parse_uri( get_to(msg)->uri.s, get_to(msg)->uri.len, &uri)==-1
			|| !uri.user.len)
			{
				LOG(L_ERR,"ERROR:sms_push_on_net: unable to extract user"
					" name from RURI and To header!\n");
				goto error;
			}
		}
	}
	/* check the uri.user format = '+(inter code)(number)' */
	if (uri.user.len<2 || uri.user.s[0]!='+' || uri.user.s[1]<'1'
	|| uri.user.s[1]>'9') {
		LOG(L_ERR,"ERROR:sms_push_on_net: user tel number [%.*s] does not"
			"respect international format\n",uri.user.len,uri.user.s);
		goto error;
	}

	/* parsing from header */
	if ( parse_from_header( msg )==-1 ) {
		LOG(L_ERR,"ERROR:sms_push_on_net: cannot get FROM header\n");
		goto error;
	}
	from = (struct to_body*)msg->from->parsed;

#if 0
	/* adds contact header into reply */
	if (add_contact(msg,&(uri.user))==-1) {
		LOG(L_ERR,"ERROR:sms_push_on_net:can't build contact for reply\n");
		goto error;
	}
#endif

	/*-------------BUILD AND FILL THE SMS_MSG STRUCTURE --------------------*/
	/* computes the amount of memory needed */
	len = SMS_HDR_BF_ADDR_LEN + from->uri.len
		+ SMS_HDR_AF_ADDR_LEN + body.len + SMS_FOOTER_LEN /*text to send*/
		+ from->uri.len /* from */
		+ uri.user.len-1 /* to user (wihout '+') */
		+ sizeof(struct sms_msg) ; /* the sms_msg structure */
	/* allocs a new sms_msg structure in shared memory */
	sms_messg = (struct sms_msg*)shm_malloc(len);
	if (!sms_messg) {
		LOG(L_ERR,"ERROR:sms_push_on_net: cannot get shm memory!\n");
		goto error;
	}
	p = (char*)sms_messg + sizeof(struct sms_msg);

	/* copy "from" into sms struct */
	sms_messg->from.len = from->uri.len;
	sms_messg->from.s = p;
	append_str(p,from->uri.s,from->uri.len);

	/* copy "to.user" - we have to strip out the '+' */
	sms_messg->to.len = uri.user.len-1;
	sms_messg->to.s = p;
	append_str(p,uri.user.s+1,sms_messg->to.len);

	/* copy (and compossing) sms body */
	sms_messg->text.len = SMS_HDR_BF_ADDR_LEN + sms_messg->from.len
		+ SMS_HDR_AF_ADDR_LEN + body.len+SMS_FOOTER_LEN;
	sms_messg->text.s = p;
	append_str(p, SMS_HDR_BF_ADDR, SMS_HDR_BF_ADDR_LEN);
	append_str(p, sms_messg->from.s, sms_messg->from.len);
	append_str(p, SMS_HDR_AF_ADDR, SMS_HDR_AF_ADDR_LEN);
	append_str(p, body.s, body.len);
	append_str(p, SMS_FOOTER, SMS_FOOTER_LEN);

	if (*queued_msgs>MAX_QUEUED_MESSAGES)
		goto error;
	(*queued_msgs)++;

	if (write(net_pipes_in[net], &sms_messg, sizeof(sms_messg))!=
	sizeof(sms_messg) )
	{
		LOG(L_ERR,"ERROR:sms_push_on_net: error when writting for net %d "
			"to pipe [%d] : %s\n",net,net_pipes_in[net],strerror(errno) );
		shm_free(sms_messg);
		(*queued_msgs)--;
		goto error;
	}

	return 1;
 error:
	return -1;
}





int send_sip_msg_request(str *to, str *from_user, str *body)
{
	str msg_type = { "MESSAGE", 7};
	str from;
	str hdrs;
	int foo;
	char *p;

	from.s = hdrs.s = 0;
	from.len = hdrs.len = 0;

	/* From header */
	from.len = 6 /*"<sip:+"*/ +  from_user->len/*user*/ + 1/*"@"*/
		+ domain.len /*host*/ + 1 /*">"*/ ;
	from.s = (char*)pkg_malloc(from.len);
	if (!from.s)
		goto error;
	p=from.s;
	append_str(p,"<sip:+",6);
	append_str(p,from_user->s,from_user->len);
	*(p++)='@';
	append_str(p,domain.s,domain.len);
	*(p++)='>';

	/* hdrs = Contact header + Content-type */
	/* length */
	hdrs.len = CONTENT_TYPE_HDR_LEN + CRLF_LEN;
	if (use_contact)
		hdrs.len += 15 /*"Contact: <sip:+"*/ + from_user->len/*user*/ +
			1/*"@"*/ + domain.len/*host*/ + 1 /*">"*/ + CRLF_LEN;
	hdrs.s = (char*)pkg_malloc(hdrs.len);
	if (!hdrs.s)
		goto error;
	p=hdrs.s;
	append_str(p,CONTENT_TYPE_HDR,CONTENT_TYPE_HDR_LEN);
	append_str(p,CRLF,CRLF_LEN);
	if (use_contact) {
		append_str(p,"Contact: <sip:+",15);
		append_str(p,from_user->s,from_user->len);
		*(p++)='@';
		append_str(p,domain.s,domain.len);
		append_str(p,">"CRLF,1+CRLF_LEN);
	}

	/* sending the request */
	foo = tmb.t_request( &msg_type,   /* request type */
			0,                        /* Request-URI */
			to,                       /* To */
			&from,                    /* From */
			&hdrs,                    /* Additional headers including CRLF */
			body,                     /* Message body */
			0,                        /* Callback function */
			0                         /* Callback parameter */
		);
	if (from.s) pkg_free(from.s);
	if (hdrs.s) pkg_free(hdrs.s);
	return foo;
error:
	LOG(L_ERR,"ERROR:sms_build_and_send_sip: no free pkg memory!\n");
	if (from.s) pkg_free(from.s);
	if (hdrs.s) pkg_free(hdrs.s);
	return -1;
}




inline int send_error(struct sms_msg *sms_messg, char *msg1_s, int msg1_len,
													char *msg2_s, int msg2_len)
{
	str  body;
	char *p;
	int  foo;

	/* body */
	body.len = msg1_len + msg2_len;
	body.s = (char*)pkg_malloc(body.len);
	if (!body.s)
		goto error;
	p=body.s;
	append_str(p, msg1_s, msg1_len );
	append_str(p, msg2_s, msg2_len);

	/* sending */
	foo = send_sip_msg_request( &(sms_messg->from), &(sms_messg->to), &body);
	pkg_free( body.s );
	return foo;
error:
	LOG(L_ERR,"ERROR:sms_send_error: no free pkg memory!\n");
	return -1;

}



inline unsigned int split_text(str *text, unsigned char *lens,int nice)
{
	int  nr_chunks;
	int  k,k1,len;
	char c;

	nr_chunks = 0;
	len = 0;

	do{
		k = MAX_SMS_LENGTH-(nice&&nr_chunks?SMS_EDGE_PART_LEN:0);
		if ( len+k<text->len ) {
			/* is not the last piece :-( */
			if (nice && !nr_chunks) k -= SMS_EDGE_PART_LEN;
			if (text->len-len-k<=SMS_FOOTER_LEN+4)
				k = (text->len-len)/2;
			/* ->looks for a point to split */
			k1 = k;
			while( k>0 && (c=text->s[len+k-1])!='.' && c!=' ' && c!=';'
			&& c!='\r' && c!='\n' && c!='-' && c!='!' && c!='?' && c!='+'
			&& c!='=' && c!='\t' && c!='\'')
				k--;
			if (k<k1/2)
				/* wast of space !!!!*/
				k=k1;
			len += k;
			lens[nr_chunks] = k;
		}else {
			/*last chunk*/
			lens[nr_chunks] = text->len-len;
			len = text->len;
		}
		nr_chunks++;
	}while (len<text->len);

	return nr_chunks;
}




int send_as_sms(struct sms_msg *sms_messg, struct modem *mdm)
{
	static char   buf[MAX_SMS_LENGTH];
	unsigned int  buf_len;
	unsigned char len_array_1[256], len_array_2[256], *len_array;
	unsigned int  nr_chunks_1,  nr_chunks_2, nr_chunks;
	unsigned int  use_nice;
	str  text;
	char *p, *q;
	int  ret_code;
	int  i;

	text.s   = sms_messg->text.s;
	text.len = sms_messg->text.len;

	nr_chunks_1 = split_text( &text, len_array_1, 0);
	nr_chunks_2 = split_text( &text, len_array_2, 1);
	if (nr_chunks_1==nr_chunks_2) {
		len_array = len_array_2;
		nr_chunks = nr_chunks_2;
		use_nice = 1;
	} else {
		len_array = len_array_1;
		nr_chunks = nr_chunks_1;
		use_nice = 0;
	}

	sms_messg->ref = 1;
	for(i=0,p=text.s ; i<nr_chunks&&i<max_sms_parts ; p+=len_array[i++]) {
		if (use_nice) {
			q = buf;
			if (nr_chunks>1 && i)  {
				append_str(q,SMS_EDGE_PART,SMS_EDGE_PART_LEN);
				*(q-2)=nr_chunks+'0';
				*(q-4)=i+1+'0';
			}
			append_str(q,p,len_array[i]);
			if (nr_chunks>1 && !i)  {
				append_str(q,SMS_EDGE_PART,SMS_EDGE_PART_LEN);
				*(q-2)=nr_chunks+'0';
				*(q-4)=i+1+'0';
			}
			buf_len = q-buf;
		} else {
			q = buf;
			append_str(q,p,len_array[i]);
			buf_len = len_array[i];
		}
		if (i+1==max_sms_parts && i+1<nr_chunks) {
			/* simply override the end of the last allowed part */
			buf_len += SMS_TRUNCATED_LEN+SMS_FOOTER_LEN;
			if (buf_len>MAX_SMS_LENGTH) buf_len = MAX_SMS_LENGTH;
			q = buf + (buf_len-SMS_TRUNCATED_LEN-SMS_FOOTER_LEN);
			append_str(q,SMS_TRUNCATED,SMS_TRUNCATED_LEN);
			append_str(q,SMS_FOOTER,SMS_FOOTER_LEN);
			p += buf_len-SMS_TRUNCATED_LEN-SMS_FOOTER_LEN-SMS_EDGE_PART_LEN;
			send_error(sms_messg, ERR_TRUNCATE_TEXT, ERR_TRUNCATE_TEXT_LEN,
				p, text.len-(p-text.s)-SMS_FOOTER_LEN);
		}
		DBG("---%d--<%d><%d>--\n|%.*s|\n", i, len_array[i], buf_len,
										(int)buf_len, buf);
		sms_messg->text.s   = buf;
		sms_messg->text.len = buf_len;
		if ( (ret_code=putsms(sms_messg,mdm))<0)
			goto error;
		if (sms_report_type!=NO_REPORT)
			add_sms_into_report_queue(ret_code,sms_messg,
				p-use_nice*(nr_chunks>1)*SMS_EDGE_PART_LEN,len_array[i]);
	}

	sms_messg->ref--;
	/* put back the pointer to the beginning of the messsage*/
	sms_messg->text.s = text.s;
	sms_messg->text.len = text.len;
	/* remove the sms if nobody points to it */
	if (!sms_messg->ref){
		shm_free(sms_messg);
	}
	return 1;
error:
	if (ret_code==-1)
		/* bad number */
		send_error(sms_messg, sms_messg->to.s, sms_messg->to.len,
			ERR_NUMBER_TEXT, ERR_NUMBER_TEXT_LEN);
	else if (ret_code==-2)
		/* bad modem */
		send_error(sms_messg, ERR_MODEM_TEXT, ERR_MODEM_TEXT_LEN,
			text.s+SMS_HDR_BF_ADDR_LEN+sms_messg->from.len+SMS_HDR_AF_ADDR_LEN,
			text.len-SMS_FOOTER_LEN-SMS_HDR_BF_ADDR_LEN-sms_messg->from.len-
			SMS_HDR_AF_ADDR_LEN );

	if (!(--(sms_messg->ref)))
		shm_free(sms_messg);
	return -1;
}




int send_sms_as_sip( struct incame_sms *sms )
{
	str  sip_addr;
	str  sip_body;
	str  sip_from;
	int  is_pattern;
	int  in_address;
	int  k;
	char *p;

	/* first we have to parse the body ot try to get out
	   the sip destination address;
	   The sms body can to be in the following two formats:
	   1. The entire or part of the sent header still exists - we will
	      pars it and consider the start of the sip messge the first
	      character that doesn't match the header!
	   2. The sms body is totaly different of the send sms -> search for a
	      sip address inside; everything before it is ignored, only the
	      part followind the address being send as sip
	*/
	in_address = 0;
	sip_addr.len = 0;
	sip_body.len = 0;
	p = sms->ascii;

	/* is our logo (or a part of it) still there? */
	if (*p==SMS_HDR_BF_ADDR[0]) {
		is_pattern = 1;
		/* try to match SMS_HDR_BF_ADDR */
		k=0;
		while( is_pattern && p<sms->ascii+sms->userdatalength
		&& k<SMS_HDR_BF_ADDR_LEN)
			if (*(p++)!=SMS_HDR_BF_ADDR[k++])
				is_pattern = 0;
		if (!is_pattern) {
			/* first header part is broken -> let's give it a chance
			   and parse for the first word delimitator */
			while(p<sms->ascii+sms->userdatalength && no_sip_addr_begin(*p))
				p++;
			p++;
			if (p+9>=sms->ascii+sms->userdatalength) {
				LOG(L_ERR,"ERROR:send_sms_as_sip: unable to find sip_address"
					" start in sms body [%s]!\n",sms->ascii);
				goto error;
			}
			
		}
		/* lets get the address */
		if (p[0]!='s' || p[1]!='i' || p[2]!='p' || p[3]!=':') {
			LOG(L_ERR,"ERROR:send_sms_as_sip: wrong sip address fromat in"
				" sms body [%s]!\n",sms->ascii);
			goto error;
		}
		sip_addr.s = p;
		/* goes to the end of the address */
		while(p<sms->ascii+sms->userdatalength && is_in_sip_addr(*p) )
			p++;
		if (p>=sms->ascii+sms->userdatalength) {
			LOG(L_ERR,"ERROR:send_sms_as_sip: cannot find sip address end in"
				"sms body [%s]!\n",sms->ascii);
		}
		sip_addr.len = p-sip_addr.s;
		DBG("DEBUG:send_sms_as_sip: sip address found [%.*s]\n",
			sip_addr.len,sip_addr.s);
		/* try to match SMS_HDR_AF_ADDR */
		k=0;
		while( is_pattern && p<sms->ascii+sms->userdatalength
		&& k<SMS_HDR_AF_ADDR_LEN)
			if (*(p++)!=SMS_HDR_AF_ADDR[k++])
				is_pattern = 0;
	} else {
		/* no trace of the pattern sent along with the orig sms*/
		do {
			if ((p[0]=='s'||p[0]=='S') && (p[1]=='i'||p[1]=='I')
			&& (p[2]=='p'||p[2]=='P') && p[3]==':') {
				/* we got the address beginning */
				sip_addr.s = p;
				/* goes to the end of the address */
				while(p<sms->ascii+sms->userdatalength && is_in_sip_addr(*p) )
					p++;
				if (p==sms->ascii+sms->userdatalength) {
					LOG(L_ERR,"ERROR:send_sms_as_sip: cannot find sip"
						" address end in sms body [%s]!\n",sms->ascii);
					goto error;
				}
				sip_addr.len = p-sip_addr.s;
			} else {
				/* parse to the next word */
				/*DBG("*** Skipping word len=%d\n",sms->userdatalength);*/
				while(p<sms->ascii+sms->userdatalength&&no_sip_addr_begin(*p)){
					p++;
				}
				p++;
				if (p+9>=sms->ascii+sms->userdatalength) {
				LOG(L_ERR,"ERROR:send_sms_as_sip: unable to find sip "
						"address start in sms body [%s]!\n",sms->ascii);
					goto error;
				}
				/*DBG("*** Done\n");*/
			}
		}while (!sip_addr.len);
	}

	/* the rest of the sms (if any ;-)) is the body! */
	sip_body.s = p;
	sip_body.len = sms->ascii + sms->userdatalength - p;
	/* let's trim out all \n an \r from begining */
	while ( sip_body.len && sip_body.s
	&& (sip_body.s[0]=='\n' || sip_body.s[0]=='\r') ) {
		sip_body.s++;
		sip_body.len--;
	}
	if (sip_body.len==0) {
		LOG(L_WARN,"WARNING:send_sms_as_sip: empty body for sms [%s]",
			sms->ascii);
		goto error;
	}
	DBG("DEBUG:send_sms_as_sip: extracted body is: [%.*s]\n",
		sip_body.len, sip_body.s);

	/* finally, let's send it as sip message */
	sip_from.s = sms->sender;
	sip_from.len = strlen(sms->sender);
	/* patch the body with date and time */
	if (sms->userdatalength + CRLF_LEN + 1 /*'('*/ + DATE_LEN
	+ 1 /*','*/ + TIME_LEN + 1 /*')'*/< sizeof(sms->ascii)) {
		p = sip_body.s + sip_body.len;
		append_str( p, CRLF, CRLF_LEN);
		*(p++) = '(';
		append_str( p, sms->date, DATE_LEN);
		*(p++) = ',';
		append_str( p, sms->time, TIME_LEN);
		*(p++) = ')';
		sip_body.len += CRLF_LEN + DATE_LEN + TIME_LEN + 3;
	}
	send_sip_msg_request( &sip_addr, &sip_from, &sip_body);

	return 1;
error:
	return -1;
}




int check_sms_report( struct incame_sms *sms )
{
	struct sms_msg *sms_messg;
	str *s1, *s2;
	int old;
	int res;

	DBG("DEBUG:sms:check_sms_report: Report for sms number %d.\n",sms->sms_id);
	res=relay_report_to_queue( sms->sms_id, sms->sender, sms->ascii[0], &old);
	if (res==3) { /* error */
		/* the sms was confirmed with an error code -> we have to send a
		message to the SIP user */
		s1 = get_error_str(sms->ascii[0]);
		s2 = get_text_from_report_queue(sms->sms_id);
		sms_messg = get_sms_from_report_queue(sms->sms_id);
		send_error( sms_messg, s1->s, s1->len, s2->s, s2->len);
	} else if (res==1 && sms->ascii[0]==48 && old!=48) { /* provisional 48 */
		/* the sms was provisinal confirmed with a 48 code -> was stored
		by SMSC -> no further real-time tracing posible */
		s2 = get_text_from_report_queue(sms->sms_id);
		sms_messg = get_sms_from_report_queue(sms->sms_id);
		send_error( sms_messg, STORED_NOTE, STORED_NOTE_LEN, s2->s, s2->len);
	} else if (res==2 && old==48) {
		/* we received OK for a SMS that had received prev. an 48 code.
		The note that we send for 48 has to be now clarify */
		s2 = get_text_from_report_queue(sms->sms_id);
		sms_messg = get_sms_from_report_queue(sms->sms_id);
		send_error( sms_messg, OK_MSG, OK_MSG_LEN, s2->s, s2->len);
	}
	if (res>1) /* final response */
		remove_sms_from_report_queue(sms->sms_id);

	return 1;
}




int check_cds_report( struct modem *mdm, char *cds, int cds_len)
{
	struct incame_sms sms;

	if (cds2sms( &sms, mdm, cds, cds_len)==-1)
		return -1;
	check_sms_report( &sms );
	return 1;
}




void modem_process(struct modem *mdm)
{
	struct sms_msg    *sms_messg;
	struct incame_sms sms;
	struct network *net;
	int i,k,len;
	int counter;
	int dont_wait;
	int empty_pipe;
	int cpms_unsuported;
	int max_mem=0, used_mem=0;

	sms_messg = 0;
	cpms_unsuported = 0;

	/* let's open/init the modem */
	DBG("DEBUG:modem_process: openning modem\n");
	if (openmodem(mdm)==-1) {
		LOG(L_ERR,"ERROR:modem_process: cannot open modem %s!"
			" %s \n",mdm->name,strerror(errno));
		return;
	}

	setmodemparams(mdm);
	initmodem(mdm,check_cds_report);

	if ( (max_mem=check_memory(mdm,MAX_MEM))==-1 ) {
		LOG(L_WARN,"WARNING:modem_process: CPMS command unsuported!"
			" using default values (10,10)\n");
		used_mem = max_mem = 10;
		cpms_unsuported = 1;
	}
	DBG("DEBUG:modem_process: modem maximum memory is %d\n",max_mem);

	set_gettime_function();

	while(1)
	{
		dont_wait = 0;
		for (i=0;i<nr_of_networks && mdm->net_list[i]!=-1;i++)
		{
			counter = 0;
			empty_pipe = 0;
			net = &(networks[mdm->net_list[i]]);
			/*getting msgs from pipe*/
			while( counter<net->max_sms_per_call && !empty_pipe )
			{
				/* let's read a sms from pipe */
				len = read(net->pipe_out, &sms_messg,
					sizeof(sms_messg));
				if (len!=sizeof(sms_messg)) {
					if (len>=0)
						LOG(L_ERR,"ERROR:modem_process: truncated message"
						" read from pipe! -> discarted\n");
					else if (errno==EAGAIN)
						empty_pipe = 1;
					else
						LOG(L_ERR,"ERROR:modem_process: pipe reding failed: "
							" : %s\n",strerror(errno));
					sleep(1);
					counter++;
					continue;
				}
				(*queued_msgs)--;

				/* compute and send the sms */
				DBG("DEBUG:modem_process: %s processing sms for net %s:"
					" \n\tTo:[%.*s]\n\tBody=<%d>[%.*s]\n",
					mdm->device, net->name,
					sms_messg->to.len,sms_messg->to.s,
					sms_messg->text.len,sms_messg->text.len,sms_messg->text.s);
				send_as_sms( sms_messg , mdm);

				counter++;
				/* if I reached the limit -> set not to wait */
				if (counter==net->max_sms_per_call)
					dont_wait = 1;
			}/*while*/
		}/*for*/

		/* let's see if we have incomming sms */
		if ( !cpms_unsuported )
			if ((used_mem = check_memory(mdm,USED_MEM))==-1) {
				LOG(L_ERR,"ERROR:modem_process: CPMS command failed!"
					" cannot get used mem -> using 10\n");
				used_mem = 10;
			}

		/* if any, let's get them */
		if (used_mem)
			DBG("DEBUG:modem_process: %d new SMS on modem\n",used_mem);
			for(i=1,k=1;k<=used_mem && i<=max_mem;i++) {
				if (getsms(&sms,mdm,i)!=-1) {
					k++;
					DBG("SMS Get from location %d\n",i);
					/*for test ;-) ->  to be remove*/
					DBG("SMS RECEIVED:\n\rFrom: %s %s\n\r%.*s %.*s"
						"\n\r\"%.*s\"\n\r",sms.sender,sms.name,
						DATE_LEN,sms.date,TIME_LEN,sms.time,
						sms.userdatalength,sms.ascii);
					if (!sms.is_statusreport)
						send_sms_as_sip(&sms);
					else 
						check_sms_report(&sms);
				}
			}

		/* if reports are used, checks for expired records in report queue */
		if (sms_report_type!=NO_REPORT)
			check_timeout_in_report_queue();

		/* sleep -> if it's needed */
		if (!dont_wait) {
				sleep(mdm->looping_interval);
		}
	}/*while*/
}



