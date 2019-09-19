/*
 * Copyright (C) 2014 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */


#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "zlib.h"
#include "../../sr_module.h"
#include "../../db/db.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../action.h"
#include "../../script_var.h"
#include "../../dset.h"
#include "../../mem/mem.h"
#include "../../mi/mi.h"
#include "../../parser/parse_to.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_hname2.h"
#include "../../parser/sdp/sdp_helpr_funcs.h"
#include "../../mod_fix.h"
#include "../../data_lump.c"
#include "../../ut.h"
#include "../../msg_translator.h"
#include "../tm/tm_load.h"
#include "../../script_cb.h"
#include "../../context.h"
#include "../../parser/hf.h"

#include "compression.h"
#include "compression_helpers.h"
#include "gz_helpers.h"
#include "compression_api.h"


#define CL_NAME		"Content-Length: "
#define CL_NAME_LEN	(sizeof(CL_NAME) - 1)

#define CE_NAME		"Content-Encoding: "
#define CE_NAME_LEN	(sizeof(CE_NAME) - 1)

#define GZIP_CE 	"Content-Encoding: gzip\r\n"
#define GZIP_CE_LEN	(sizeof(GZIP_CE) - 1)

#define DEFLATE_CE	"Content-Encoding: deflate\r\n"
#define DEFLATE_CE_LEN	(sizeof(DEFLATE_CE) - 1)

#define COMP_HDRS	"Comp-Hdrs: "
#define COMP_HDRS_LEN	(sizeof(COMP_HDRS) - 1)

#define HDRS_ENCODING	"Headers-Encoding: "

#define GZIP_ALGO		"gzip"
#define DEFLATE_ALGO	"deflate"
#define BASE64_ALGO		"base64"

#define DELIM		": "
#define ATTR_DELIM	", "
#define DELIM_LEN	(sizeof(DELIM) - 1)
#define ATTR_DELIM_LEN	(sizeof(ATTR_DELIM) - 1)
#define NO_FORM		255

#define is_space(p) (*(p) == ' ')
#define veclen(_vec_, _type_) (sizeof(_vec_)/sizeof(_type_))


#define PARSE_CRLF 0x0a0d
#define WORD(p) (*(p + 0) + (*(p + 1) << 8))
#define DWORD(p) (*(p+0) + (*(p+1) << 8) + (*(p+2) << 16) + (*(p+3) << 24))

#define LOWER_CASE(p) (*(p) & 0x20)
#define BUFLEN 4096

#define COMPACT_FORMS	"cfiklmstvx"

#define TM_CB (1<<0)
#define PROCESSING_CB (1<<1)

#define COMPRESS_CB (1<<0)
#define COMPACT_CB (1<<1)

#define SET_GLOBAL_CTX(pos, value) \
	(context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx, pos, value))

#define GET_GLOBAL_CTX(pos) \
	(context_get_ptr(CONTEXT_GLOBAL, current_processing_ctx, pos))

static int mod_init(void);
static int child_init(int rank);
static void mod_destroy();

int mc_level = 6;
unsigned char* mnd_hdrs_mask = NULL;
unsigned char* compact_form_mask = NULL;
struct tm_binds tm_api;
int compress_ctx_pos, compact_ctx_pos;
int tm_compress_ctx_pos, tm_compact_ctx_pos;

static int fixup_whitelist_compact(void**);
static int fixup_whitelist_compress(void**);
static int fixup_whitelist_free(void **);

static int mc_compact(struct sip_msg* msg, mc_whitelist_p wh_list);
static int mc_compact_cb(char** buf, mc_whitelist_p wh_list, int, int*);

static int mc_compress(struct sip_msg* msg, int* algo, int* flags,
		mc_whitelist_p wh_list);
int mc_compress_cb(char** buf, void* param, int type, int* olen);
static inline int mc_ndigits(int x);
static inline void parse_algo_hdr(struct hdr_field* algo_hdr, int* algo, int* b64_required);

static int mc_decompress(struct sip_msg*);
void wrap_tm_func(struct cell* t, int type, struct tmcb_params* p);
int wrap_msg_func(str*, struct sip_msg*, int type);




static char body_buf[BUFLEN];
static char hdr_buf[BUFLEN/2];
struct cell* global_tran=NULL;

static str body_in  = {NULL, 0},
	   body_out = {NULL, 0},
	   hdr_in   = {NULL, 0},
	   hdr_out  = {NULL, 0},
	   buf_out  = {NULL, 0};

static param_export_t mod_params[]={
	{ "compression_level", INT_PARAM, &mc_level},
	{0,0,0}
};

static cmd_export_t cmds[]={
	{"mc_compact",	  (cmd_function)mc_compact, {
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL,
			fixup_whitelist_compact, fixup_whitelist_free},
		{0, 0, 0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|FAILURE_ROUTE},
	{"mc_compress",	  (cmd_function)mc_compress, {
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR, fixup_compression_flags,
			fixup_compression_flags_free},
		{CMD_PARAM_STR|CMD_PARAM_OPT,
			fixup_whitelist_compress, fixup_whitelist_free},
		{0, 0, 0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|FAILURE_ROUTE},
	{"mc_decompress",	(cmd_function)mc_decompress, {
		{0, 0, 0}},
		REQUEST_ROUTE|LOCAL_ROUTE|FAILURE_ROUTE},
	{"load_compression",(cmd_function)bind_compression, {
		{0, 0, 0}}, 0},
	{0,0,{{0,0,0}},0}
};

struct module_exports exports= {
	"compression",			/* module's name */
	MOD_TYPE_DEFAULT, /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,		/* dlopen flags */
	0,						/* load function */
	NULL,				/* module dependencies */
	cmds,			/* exported functions */
	0,				/* exported async functions */
	mod_params,		/* param exports */
	0,			/* exported statistics */
	0,			/* exported MI functions */
	0,			/* exported pseudo-variables */
	0,			/* exported transformations */
	0,			/* additional processes */
	0,				/* module pre-initialization function */
	mod_init,		/* module initialization function */
	0,			/* reply processing function */
	mod_destroy,
	child_init,	/* pre-child init function */
	0			/* reload confirm function */
};


int mnd_hdrs[]={
	HDR_VIA_T,
	HDR_VIA2_T,
	HDR_FROM_T,
	HDR_TO_T,
	HDR_CSEQ_T,
	HDR_ROUTE_T,
	HDR_RECORDROUTE_T,
	HDR_CONTENTTYPE_T,
	HDR_CALLID_T,
	HDR_CONTACT_T
};
int compact_form_hdrs[]={
	HDR_CALLID_T,
	HDR_CONTACT_T,
	HDR_CONTENTLENGTH_T,
	HDR_CONTENTTYPE_T,
	HDR_FROM_T,
	HDR_SUBJECT_T,
	HDR_TO_T,
	HDR_VIA_T,
	HDR_SUPPORTED_T,
	HDR_SESSION_EXPIRES_T,
	HDR_OTHER_T
};

/*
 * Function that builds a list which will contain the mandatory headers
 */
int build_hdr_masks(void)
{
	int len = veclen(mnd_hdrs, int), i;

	mnd_hdrs_mask = pkg_malloc(HDR_MASK_SIZE);

	if (!mnd_hdrs_mask)
		goto mem;

	memset(mnd_hdrs_mask, 0, HDR_MASK_SIZE);

	/* build initial array with mandatory headers mask */
	for (i = 0; i < len; i++) {
		mnd_hdrs_mask[mnd_hdrs[i] / MC_BYTE_SIZE] |=
			(unsigned char)1 << (mnd_hdrs[i] % MC_BYTE_SIZE);
	}

	compact_form_mask = pkg_malloc(HDR_MASK_SIZE);

	if (!compact_form_mask)
		goto mem;

	memset(compact_form_mask, 0, HDR_MASK_SIZE);

	len = veclen(compact_form_hdrs, int);

	/* Build mask with headers which will be reduced to short form */
	for (i = 0; i < len; i++) {
		compact_form_mask[compact_form_hdrs[i] / MC_BYTE_SIZE] |=
			(unsigned char)1 << (compact_form_hdrs[i] % MC_BYTE_SIZE);
	}

	return 0;
mem:
	LM_ERR("no more pkg mem\n");
	return -1;

}

void wrap_tm_compress(struct cell* t, int type, struct tmcb_params* p)
{
	wrap_tm_func( t, COMPRESS_CB, p);
}

void wrap_tm_compact(struct cell*t, int type, struct tmcb_params* p)
{
	wrap_tm_func( t, COMPACT_CB, p);
}

void wrap_tm_func(struct cell* t, int type, struct tmcb_params* p)
{
	int ret = 0;
	mc_whitelist_p wh_list = NULL;
	struct mc_comp_args* args = NULL;
	char* buf = t->uac[p->code].request.buffer.s;
	int olen = t->uac[p->code].request.buffer.len;

	switch (type) {
		case COMPRESS_CB:
			if ((args = GET_GLOBAL_CTX(compress_ctx_pos)) == NULL)
				break;

			if ((ret = mc_compress_cb(&buf, args, TM_CB, &olen)) < 0)
				LM_ERR("compression failed\n");

			wh_list = args->hdr2compress_list;
			pkg_free(args);
			SET_GLOBAL_CTX(compress_ctx_pos, NULL);
			break;

		case COMPACT_CB:
			/* if not registered yet we take from global context */
			if ((wh_list = GET_GLOBAL_CTX(compact_ctx_pos)) == NULL)
				break;

			if ((ret = mc_compact_cb(&buf, wh_list, TM_CB, &olen)) < 0)
				LM_ERR("compaction failed\n");

			SET_GLOBAL_CTX(compact_ctx_pos, NULL);

			break;

		default:
			LM_BUG("!!! invalid CB type arg!\n");
			return;
	}

	/* free whitelists for both actions */
	if (wh_list)
		free_whitelist(wh_list);
	if (ret < 0)
		return;

	t->uac[p->code].request.buffer.s = buf;
	t->uac[p->code].request.buffer.len = olen;
	/* we also need to compute the uri so that it points within the new buffer */
	t->uac[p->code].uri.s = buf + t->method.len + 1;
	/* uri.len should be the same, since it is not changed by compression */
}

int wrap_msg_compress(str* buf, struct sip_msg* p_msg) {
	return wrap_msg_func( buf, p_msg, COMPRESS_CB);
}

int wrap_msg_compact(str* buf, struct sip_msg* p_msg) {
	return wrap_msg_func( buf, p_msg, COMPACT_CB);
}

int wrap_msg_func(str* buf, struct sip_msg* p_msg, int type)
{
	int ret = 0;
	struct mc_comp_args* args;
	mc_whitelist_p wh_list = NULL;
	int olen=buf->len;

	if (current_processing_ctx == NULL) {
		LM_DBG("null context. cb shall not be removed\n");
		return 1;
	}

	switch (type) {
	case COMPRESS_CB:
		if ((args = GET_GLOBAL_CTX(compress_ctx_pos))==NULL)
			break;

		if ((ret = mc_compress_cb(&buf->s, args, PROCESSING_CB, &olen)) < 0)
			LM_ERR("compression failed. Probably not requested message\n");

		wh_list = args->hdr2compress_list;
		pkg_free(args);
		SET_GLOBAL_CTX(compress_ctx_pos, NULL);
		break;

	case COMPACT_CB:
		if ((wh_list = GET_GLOBAL_CTX(compact_ctx_pos))==NULL)
			break;

		if ((ret = mc_compact_cb(&buf->s, wh_list, PROCESSING_CB, &olen)) < 0)
			LM_ERR("compaction failed\n");

		SET_GLOBAL_CTX(compact_ctx_pos, NULL);
		break;
	}

	/* free whitelists for both actions */
	if (wh_list)
		free_whitelist(wh_list);
	if (ret < 0)
		return -1;

	buf->len = olen;

	return 0;
}

/*
 *
 */
static int mod_init(void)
{
	LM_INFO("Initializing module...\n");

	if (build_hdr_masks()) {
		LM_ERR("Cannot build initial mandatory headers mask\n");
		return -1;
	}

	if (mc_level > 9 || mc_level < 1) {
		LM_WARN("invalid level. using default 6\n");
		mc_level = 6;
	}

	compress_ctx_pos = context_register_ptr(CONTEXT_GLOBAL, NULL);
	LM_DBG("received compress context position %d\n", compress_ctx_pos);

	compact_ctx_pos = context_register_ptr(CONTEXT_GLOBAL, NULL);
	LM_DBG("received compact context position %d\n", compact_ctx_pos);

	memset(&tm_api, 0, sizeof(struct tm_binds));
	if (load_tm_api(&tm_api) != 0)
		LM_DBG("TM modules was not found\n");

	return 0;
}

/*
 *
 */
static int child_init(int rank)
{
	return 0;
}

/*
 *
 */
static void mod_destroy(void)
{
	return;
}

/*
 * Fixup function for 'mc_compact'
 */
static int fixup_whitelist_compact(void** param)
{
	return parse_whitelist((str *)(*param),
			(mc_whitelist_p *)param, mnd_hdrs_mask);
}

static int fixup_whitelist_compress(void** param)
{
	return parse_whitelist((str *)(*param),
			(mc_whitelist_p *)param, NULL);
}

static int fixup_whitelist_free(void **param)
{
	return free_whitelist(*param);
}


/*
 * Memcpy and update length wrapper
 */
static inline int wrap_copy_and_update(char** dest_p, const char* src, int cpy_len,
					int* dest_len)
{
	memcpy(*dest_p + *dest_len, src, cpy_len);
	*dest_len += cpy_len;

	return 0;
}

/*
 * Function that jumps over the first row of the message
 * with the received buffer and saves a pointer in the first
 * arg to the first row along with the length
 */
static int mc_parse_first_line(str* msg_start, char** buffer)
{
	char* buf = *buffer;
	int len=0;

	msg_start->s   = buf;
	msg_start->len = 0;

	/* Jump over initial row of the message */
	do {
		len++;
	} while (*(buf+len) != '\n');
	len++;

	msg_start->len = len;
	*buffer = buf+len;

	return 0;
}

/*
 *Function that checks if header is in whitelist
 */
static int mc_is_in_whitelist(struct hdr_field* hf, mc_whitelist_p wh_list)
{
	if (!wh_list)
		return 0;
	if (hf->type != HDR_OTHER_T) {
		return ((1 << (hf->type%MC_BYTE_SIZE))&
			(wh_list->hdr_mask[hf->type/MC_BYTE_SIZE]));
	} else {
		mc_other_hdr_lst_p other_hdr = wh_list->other_hdr;

		for ( ; other_hdr; other_hdr=other_hdr->next) {
			if (other_hdr->hdr_name.len != hf->name.len)
				continue;
			if (strncasecmp(hf->name.s, other_hdr->hdr_name.s,
						hf->name.len))
				continue;
			return 1;
		}
		return 0;
	}

	return 0;
}

/*
 * Append header to hdr_mask elemnt
 */
static int append_hf2lst(struct hdr_field** lst, struct hdr_field* hf,
							int* msg_total_len)
{
	struct hdr_field* temp = *lst;

	if (hf->type != HDR_OTHER_T) {
		while (temp->sibling)
			temp = temp->sibling;
		temp->sibling = hf;
		*msg_total_len += hf->body.len + ATTR_DELIM_LEN;
	} else {
		/* OTHER hdr type */
		while (temp) {
			/* Header already exists */
			if (!strncasecmp(temp->name.s, hf->name.s,
							temp->name.len)) {
				while (temp->sibling)
					temp = temp->sibling;

				temp->sibling = hf;
				*msg_total_len += hf->body.len + ATTR_DELIM_LEN;
				return 0;
			}

			if (!temp->next)
				break;

			temp = temp->next;
		}

		/* First occurence of this header */
		temp->next = hf;
		*msg_total_len += hf->name.len + DELIM_LEN;
		*msg_total_len += hf->body.len + CRLF_LEN;
	}

	return 0;
}

static mc_whitelist_p mc_dup_whitelist(mc_whitelist_p src)
{
	mc_other_hdr_lst_p hdr;

	mc_whitelist_p dst = pkg_malloc(sizeof(mc_whitelist_t));
	if (!dst) {
		LM_ERR("no more pkg memory!\n");
		return NULL;
	}
	memcpy(dst->hdr_mask, src->hdr_mask, sizeof(src->hdr_mask));
	dst->other_hdr = NULL;

	/* now copy other headers */
	for (hdr = src->other_hdr; hdr; hdr = hdr->next) {
		if (append_hdr(dst, &hdr->hdr_name)) {
			LM_ERR("could not add header to list!\n");
			goto error;
		}
	}
	return dst;
error:
	free_whitelist(dst);
	return NULL;
}

/*
 * Compaction function
 * 1) Headers of same type will be put together
 * 2) Header names with compact forms will be transformed to
 * compact form
 * 3) Headers which not in whitelist will be removed
 * 4) Unnecessary sdp body codec attributes lower than 96 removed
 */
static int mc_compact(struct sip_msg* msg, mc_whitelist_p wh_list)
{
	/* first check if anyone else has called mc_compact() on this msg */
	if (GET_GLOBAL_CTX(compact_ctx_pos))
		return -1;

	wh_list = mc_dup_whitelist(wh_list);
	SET_GLOBAL_CTX(compact_ctx_pos, (void*)wh_list);

	/* register stateless callbacks */
	if (register_post_raw_processing_cb(wrap_msg_compact, POST_RAW_PROCESSING, 1/*to be freed*/) < 0) {
		LM_ERR("failed to add raw processing cb\n");
		goto error;
	}

	if (tm_api.t_gett && msg->flags&FL_TM_CB_REGISTERED)
		goto error;

	/*register tm callback if tm api */
	if (tm_api.register_tmcb &&
			tm_api.register_tmcb( msg, 0, TMCB_PRE_SEND_BUFFER,
				wrap_tm_compact, NULL, 0) != 1) {
		LM_ERR("failed to add tm TMCB_PRE_SEND_BUFFER callback\n");
		msg->flags |= FL_TM_CB_REGISTERED;
		goto error;
	}

	/* we do not release the whitelist here, as it will be used later by the
	 * tm callbacks */
	return 1;

error:
	SET_GLOBAL_CTX(compact_ctx_pos, NULL);
	free_whitelist(wh_list);
	return -1;
}

/*
 *
 */
static int mc_compact_cb(char** buf_p, mc_whitelist_p wh_list, int type, int* olen)
{
	int i;
	int msg_total_len;
	int rtpmap_val=0, rtpmap_len;
	int new_body_len;
	int hdr_len;

	str msg_start;
	str new_buf;

	char *buf=*buf_p;
	char *buf_cpy;
	char *end=buf+*olen;

	struct hdr_field *hf;
	struct hdr_field** hdr_mask;

	body_frag_p frg;
	body_frag_p frg_head;
	body_frag_p temp;

	hdr_mask = pkg_malloc(HDR_EOH_T * sizeof(struct hdr_field*));

	if (!hdr_mask)
		goto memerr;

	memset(hdr_mask, 0, HDR_EOH_T * sizeof(struct hdr_field*));

	mc_parse_first_line( &msg_start, &buf);

	msg_total_len = msg_start.len;

	/* Start to parse the headers and print them*/
	while (1) {
		hf = pkg_malloc(sizeof(struct hdr_field));
		if (hf == NULL) {
			LM_ERR("no more pkg mem\n");
			goto memerr;
		}
		memset(hf, 0, sizeof(struct hdr_field));
		hf->type=HDR_ERROR_T;
		buf=get_hdr_field(buf, end, hf);

		if (hf->type == HDR_ERROR_T) {
			pkg_free(hf);
			goto free_mem;
		}

		if (hf->type == HDR_EOH_T) {
			pkg_free(hf);
			break;
		}

		if (mc_is_in_whitelist(hf, wh_list)) {
			if (hdr_mask[hf->type]) {
				/* If hdr already found or hdr of type other */
				if (append_hf2lst(&hdr_mask[hf->type], hf,
							&msg_total_len)) {
					LM_ERR("Cannot append hdr to lst\n");
					clean_hdr_field(hf);
					pkg_free(hf);
					goto free_mem;
				}
			} else {
				unsigned char c;

				/* Get the compact form of the header */
				if (hf->type != HDR_OTHER_T &&
					(c=get_compact_form(hf)) != NO_FORM) {

					hf->name.s = &COMPACT_FORMS[c];
					hf->name.len = 1;
				}

				/* update the len of the new buffer */
				msg_total_len += hf->name.len + DELIM_LEN;
				msg_total_len += hf->body.len + CRLF_LEN;

				hdr_mask[hf->type] = hf;
			}
		} else {
			clean_hdr_field(hf);
			pkg_free(hf);
		}

		hf = 0;
	}

	hdr_len = msg_total_len + CRLF_LEN/* sip headers end with 2 * CRLF */;

	buf_cpy = buf+CRLF_LEN;
	frg = frg_head = pkg_malloc(sizeof(body_frag_t));
	if (!frg)
		goto memerr;

	frg->begin = 0;
	frg->end = CRLF_LEN;
	frg->next = NULL;

	/* parse the body and extract fragments */
	while (buf_cpy != end) {
		while (*buf_cpy == ' ' || *buf_cpy == '\t')
				(buf_cpy++, frg->end++);

		if (*buf_cpy != 'a') {
			/* Jump over the entire row*/
			goto row_jump;
		}
		else if (strncmp(buf_cpy, "a=rtpmap:", 9))
			goto row_jump;
		/* found rtpmap */
		else {
			buf_cpy += 9;
			frg->end--; /* already on 'a' char */
			rtpmap_len = rtpmap_val = 0;

			while (*buf_cpy >= '0' && *buf_cpy <= '9') {
				rtpmap_val = rtpmap_val*10 + (*buf_cpy - '0');
				(buf_cpy++, rtpmap_len++);
			}

			if (rtpmap_val < 96) {
				msg_total_len += frg->end - frg->begin + 1;
				frg->next = pkg_malloc(sizeof(body_frag_t));
				if (!frg->next)
					goto memerr;

				frg = frg->next;
				frg->next = NULL;

				/* find the next line and set the start of the next fragment */
				while (*buf_cpy != '\n') buf_cpy++;
				buf_cpy++;

				frg->end = frg->begin = buf_cpy - buf;
				continue;
			} else {
				/*currently on \n before rtpmap. Need to jump over \nrtpmap:RT_VAL */
				frg->end += 9 + rtpmap_len + 1;
			}
		}

		row_jump:
			while (*buf_cpy != '\n') {
				if (*buf_cpy == '\0') {
					LM_ERR("BUG! Message body not containing '\\n' in the end\n");
					return -1;
				}
				(buf_cpy++, frg->end++);
			}
		(buf_cpy++, frg->end++);
	}

	int foo;

	/* not storing '\0' at the end of the message */
	(buf_cpy--, frg->end--);

	msg_total_len += frg->end - frg->begin + 1;

	new_body_len = msg_total_len - hdr_len;

	/* creating the new content length */
	hf = pkg_malloc(sizeof(struct hdr_field));
	if (hf == NULL)
		goto memerr;
	memset(hf, 0, sizeof(struct hdr_field));

	hf->type = HDR_CONTENTLENGTH_T;
	hf->name.s = &COMPACT_FORMS[get_compact_form(hf)];
	hf->name.len = 1;

	if (new_body_len <= CRLF_LEN)
		new_body_len = 0;

	hf->body.len = mc_ndigits(new_body_len);
	hf->body.s = int2str( new_body_len, &foo);
	if (hf->body.s == 0) {
		LM_ERR("failed to convert int to string\n");
		goto memerr;
	}

	/*
	 * If body is empty Content-Type is not necessary anymore
	 * But only if Content-Type exists
	 */
	if (hdr_mask[HDR_CONTENTTYPE_T] && new_body_len == 0) {
		clean_hdr_field(hdr_mask[HDR_CONTENTTYPE_T]);
		hdr_mask[HDR_CONTENTTYPE_T] = NULL;
	}

	msg_total_len += hf->name.len + DELIM_LEN + hf->body.len + CRLF_LEN;
	hdr_mask[hf->type] = hf;

	/* build the new buffer */
	if (wrap_realloc(&buf_out, msg_total_len))
		goto free_mem;

	new_buf.s = buf_out.s;
	new_buf.len = 0;

	/* Copy the beginning of the message */
	wrap_copy_and_update( &new_buf.s, msg_start.s, msg_start.len,
							&new_buf.len);

	/* Copy all the headers */
	for (i = HDR_VIA_T; i <= HDR_EOH_T; i++) {
		/* Just to put headers of type other after
			all the other headers */
		if (i == HDR_EOH_T)
			i = HDR_OTHER_T;
again:
		if (hdr_mask[i]) {
			/* Compact form name so the header have
				to be built */
			if (LOWER_CASE(hdr_mask[i]->name.s)) {
				/* Copy the name of the header */
				wrap_copy_and_update(&new_buf.s,
					hdr_mask[i]->name.s,
					hdr_mask[i]->name.len, &new_buf.len);

				/* Copy the ': ' delimiter*/
				wrap_copy_and_update(&new_buf.s, DELIM,
						DELIM_LEN, &new_buf.len);
				/* Copy the first field of the header*/
				wrap_copy_and_update(&new_buf.s,
					hdr_mask[i]->body.s,
					hdr_mask[i]->body.len, &new_buf.len);
			/* Normal form header so it can be copied in one step */
			} else {
				wrap_copy_and_update(
					&new_buf.s,
					hdr_mask[i]->name.s,
					/* Possible siblings. No CRLF yet */
					hdr_mask[i]->len - CRLF_LEN,
					&new_buf.len
				);
			}

			/* Copy the rest of the header fields(siblings)
							if they exist */
			struct hdr_field* temp = hdr_mask[i]->sibling,
								*hdr_field;
			while (temp) {
				/* Put ', ' delimiter before header body*/
				wrap_copy_and_update(&new_buf.s, ATTR_DELIM,
						ATTR_DELIM_LEN, &new_buf.len);

				/* Append the header content */
				wrap_copy_and_update(&new_buf.s, temp->body.s,
						temp->body.len, &new_buf.len);

				hdr_field = temp->sibling;
				clean_hdr_field(temp);
				pkg_free(temp);
				temp = hdr_field;
			}

			/* Copy CRLF to the end of the header */
			wrap_copy_and_update(&new_buf.s, CRLF, CRLF_LEN,
								&new_buf.len);

			if (hdr_mask[i]->next) {
				/* XXX: is this really getting here?! */
				/* If more other headers, put all of them in
					the new buffer and free every allocated
					member */
				temp = hdr_mask[i];
				hdr_mask[i] = hdr_mask[i]->next;
				clean_hdr_field(temp);
				pkg_free(temp);

				goto again;
			} else {
				clean_hdr_field(hdr_mask[i]);
				/* if it is not an OTHER_HDR or it is the last
					one in OTHER_HDR list */
				pkg_free(hdr_mask[i]);
				hdr_mask[i] = 0;
			}
		}

		if (i == HDR_OTHER_T)
			break;
	}
	/* Copy the body of the message */
	frg = frg_head;
	while (frg) {
		temp = frg;
		wrap_copy_and_update( &new_buf.s, buf + frg->begin,
					frg->end-frg->begin+1, &new_buf.len);
		frg = frg->next;
		pkg_free(temp);
	}

	switch (type) {
		case TM_CB:
			shm_free(*buf_p);
			*buf_p = shm_malloc(new_buf.len);
			if (*buf_p == NULL) {
				LM_ERR("no more sh mem\n");
				goto free_mem;
			}
			break;
		case PROCESSING_CB:
			*buf_p = pkg_malloc(new_buf.len);
			if (*buf_p == NULL) {
				LM_ERR("no more pkg mem\n");
				goto free_mem;
			}
			break;
		default:
			LM_ERR("invalid type\n");
			goto free_mem;
	}

	memcpy(*buf_p, new_buf.s, new_buf.len);
	*olen = new_buf.len;

	/* Free the vector */
	pkg_free(hdr_mask);

	return 0;
memerr:
	LM_ERR("No more pkg mem\n");
free_mem:
	free_hdr_mask(hdr_mask);
	return -1;
}

/*
 *
 */
static inline int mc_ndigits(int x)
{
	if (x == 0)
		return 1;

	if (x > 10)
		return 1 + mc_ndigits(x/10);
	else return 1;
}

/*
 * Compression function
 * 1) Only mandatory headers will be kept
 * 2) The rest of the headers along with the body
 * will form the new body which will be use for compression
 * 3) The Content-Encoding Header will set to gzip, probably
 * base64 also
 */
static int mc_compress(struct sip_msg* msg, int *algo_p, int *flags_p,
		mc_whitelist_p wh_list)
{
	int ret = -1;
	int index;
	int algo = (algo_p? *algo_p: 0);
	int flags = *flags_p;
	struct mc_comp_args* args;

	/* first check if anyone else has called mc_compact() on this msg */
	if (GET_GLOBAL_CTX(compress_ctx_pos))
		return -1;

	if (!(flags&BODY_COMP_FLG) && !(flags&HDR_COMP_FLG)) {
		LM_WARN("nothing requested to compress! "
				"please choose at least one of the 'b' or 'h' flags\n");
		return -1;
	}

	if (wh_list)
		wh_list = mc_dup_whitelist(wh_list);

	/* Simulate a whitelist which will contain only the Content-Length
		header in case BODY_COMP_FLG is set */
	if (flags&HDR_COMP_FLG && wh_list) {
		/* Remove mandatory headers if they have been set */
		for (index=0; index < veclen(mnd_hdrs, int); index++) {
			if (wh_list->hdr_mask[mnd_hdrs[index]/MC_BYTE_SIZE]
						& (1 << mnd_hdrs[index]%MC_BYTE_SIZE)) {
				wh_list->hdr_mask[mnd_hdrs[index]/MC_BYTE_SIZE] ^=
								1 << (mnd_hdrs[index]%MC_BYTE_SIZE);
			}
		}
	}


	/* Content Length must be encoded if asked for body to be encoded*/
	if (flags&BODY_COMP_FLG) {
		if (!wh_list && parse_whitelist(NULL, &wh_list, NULL) < 0) {
			LM_ERR("could not allocate new list!\n");
			goto end;
		}
		wh_list->hdr_mask[HDR_CONTENTLENGTH_T/MC_BYTE_SIZE] |=
					1 << (HDR_CONTENTLENGTH_T%MC_BYTE_SIZE);
	}

	args=pkg_malloc(sizeof(struct mc_comp_args));
	if (args==NULL) {
		LM_ERR("no more pkg mem\n");
		goto end;
	}

	args->hdr2compress_list = wh_list;
	args->flags = flags;
	args->algo = algo;
	SET_GLOBAL_CTX(compress_ctx_pos, (void*)args);

	/* register stateless callbacks */
	if (register_post_raw_processing_cb(wrap_msg_compress, POST_RAW_PROCESSING, 1/*to be freed*/) < 0) {
		LM_ERR("failed to add raw processing cb\n");
		goto end;
	}

	if (tm_api.t_gett && msg->flags&FL_TM_CB_REGISTERED) {
		ret = 1;
		goto end;
	}

	/*register tm callback if tm api */
	if (tm_api.register_tmcb &&
			tm_api.register_tmcb( msg, 0, TMCB_PRE_SEND_BUFFER,
				wrap_tm_compress, NULL, 0) != 1) {
		LM_ERR("failed to add tm TMCB_PRE_SEND_BUFFER callback\n");
		msg->flags |= FL_TM_CB_REGISTERED;
		goto end;
	}

	return 1;
end:
	if (wh_list)
		free_whitelist(wh_list);
	return ret;
}

/*
 *
 */
int mc_compress_cb(char** buf_p, void* param, int type, int* olen)
{
	int rc;
	int len;
	int algo;
	int flags;
	int ret = -1;
	int compress_len=0;
	int uncompress_len=0;
	int hdr_compress_len=0;

	str msg_start;

	char *buf=*buf_p;
	char *end=buf+strlen(buf);
	unsigned long temp;
	struct mc_comp_args *args=(struct mc_comp_args*)param;

	struct hdr_field *hf;
	struct hdr_field *mnd_hdrs=NULL;
	struct hdr_field *non_mnd_hdrs=NULL;
	struct hdr_field *mnd_hdrs_head=NULL;
	struct hdr_field *non_mnd_hdrs_head=NULL;

	mc_whitelist_p hdr2compress_list;

	hdr2compress_list = args->hdr2compress_list;
	algo = args->algo;
	flags = args->flags;

	mc_parse_first_line(&msg_start, &buf);

	uncompress_len = msg_start.len;

	/* Parse the message until the body is found
		Build two lists one of mandatory headers and one
			of non mandatory headers */

	while (1) {
		hf = pkg_malloc(sizeof(struct hdr_field));
		if (hf == NULL) {
			LM_ERR("no more pkg mem\n");
			goto free_mem_full;
		}
		memset(hf, 0, sizeof(struct hdr_field));
		hf->type=HDR_ERROR_T;
		buf=get_hdr_field(buf, end, hf);

		if (hf->type == HDR_ERROR_T) {
			goto free_mem_full;
		}

		if (hf->type == HDR_EOH_T) {
			compress_len += strlen(buf);
			compress_len = compress_len > CRLF_LEN ? compress_len : 0;
			pkg_free(hf);
			break;
		}

		/*if Content-Length=0 then header must remain*/
		if (hf->type == HDR_CONTENTLENGTH_T &&
				hf->body.s[0] == '0') {
			goto set_mandatory;
		}

		if (mc_is_in_whitelist(hf, hdr2compress_list)) {
			if (!non_mnd_hdrs) {
				non_mnd_hdrs_head = non_mnd_hdrs = hf;
			} else {
				non_mnd_hdrs->next = hf;
				non_mnd_hdrs = non_mnd_hdrs->next;
			}

			/* in case will have a separate compressed header */
			if ((flags&SEPARATE_COMP_FLG && flags&BODY_COMP_FLG &&
							flags&HDR_COMP_FLG) ||
				(flags&HDR_COMP_FLG && !(flags&BODY_COMP_FLG)))
				hdr_compress_len += hf->len;
			else
				compress_len += hf->len;

		} else {
		set_mandatory:
			if (!mnd_hdrs) {
				mnd_hdrs_head = mnd_hdrs = hf;
			} else {
				mnd_hdrs->next = hf;
				mnd_hdrs = mnd_hdrs->next;
			}
			uncompress_len += hf->len;
		}
		hf = 0;
	}

	str buf2compress={NULL, 0};
	str hdr_buf2compress={NULL, 0};

	/* Copy headers only if they exist and only if were asked*/
	non_mnd_hdrs = non_mnd_hdrs_head;
	if (!non_mnd_hdrs || !(flags&HDR_COMP_FLG))
		goto only_body;

	/* If body compression and header compression flags are set and
		they have to be together in the body */
	if ((flags&BODY_COMP_FLG && flags&HDR_COMP_FLG &&
						!(flags&SEPARATE_COMP_FLG)) ||
		(flags&BODY_COMP_FLG && !(flags&HDR_COMP_FLG))){

		if (wrap_realloc(&body_in, compress_len))
			goto free_mem_full;

		buf2compress.s = body_in.s;
		buf2compress.len = 0;

		for (hf = non_mnd_hdrs; hf; hf = hf->next) {
			wrap_copy_and_update( &buf2compress.s, hf->name.s,
						hf->len, &buf2compress.len);
		}
	/* body compression and header compression but separately or
		only header compression */
	} else if ((flags&BODY_COMP_FLG && flags&HDR_COMP_FLG &&
			flags&SEPARATE_COMP_FLG) ||
		    (!(flags&BODY_COMP_FLG) && flags&HDR_COMP_FLG)) {

		if (wrap_realloc(&hdr_in, hdr_compress_len))
			goto free_mem_full;

		hdr_buf2compress.s = hdr_in.s;

		for (hf = non_mnd_hdrs; hf; hf = hf->next) {
			wrap_copy_and_update( &hdr_buf2compress.s, hf->name.s,
						hf->len, &hdr_buf2compress.len);
		}
	}

only_body:
	/* Copy the body of the message only if body compression is asked */
	if (flags&BODY_COMP_FLG && compress_len) {
		if (!buf2compress.s) {
			if (wrap_realloc(&body_in, compress_len))
				goto free_mem_full;
			buf2compress.s = body_in.s;
		}

		wrap_copy_and_update( &buf2compress.s, buf, strlen(buf),
							&buf2compress.len);
	}

	if (!buf2compress.s && !hdr_buf2compress.s) {
		LM_WARN("Nothing to compress. Specified headers not found\n");
		ret = 0;
		goto free_mem_full;
	}

	/* Compress the message */
	str bufcompressed={NULL, 0};
	str hdr_bufcompressed={NULL, 0};

	switch (algo) {
	case 0: /* deflate */

		if (buf2compress.s) {
			bufcompressed.len = compressBound((unsigned long)buf2compress.len);
			if (wrap_realloc(&body_out, bufcompressed.len))
				goto free_mem_full;

			bufcompressed.s = body_out.s;
			temp = (unsigned long)bufcompressed.len;

			rc = compress2((unsigned char*)bufcompressed.s,
					&temp,
					(unsigned char*)buf2compress.s,
					(unsigned long)buf2compress.len,
					mc_level);

			bufcompressed.len = (int)temp;

			if (check_zlib_rc(rc)) {
				LM_ERR("Body compression failed\n");
				goto free_mem_full;
			}
		}

		if ((flags&HDR_COMP_FLG) && hdr_buf2compress.s) {
			hdr_bufcompressed.len = compressBound((unsigned long)hdr_buf2compress.len);
			if (wrap_realloc(&hdr_out, hdr_bufcompressed.len))
				goto free_mem_full;

			hdr_bufcompressed.s = hdr_out.s;
			temp = (unsigned long)hdr_bufcompressed.len;

			rc = compress2((unsigned char*)hdr_bufcompressed.s,
					&temp,
					(unsigned char*)hdr_buf2compress.s,
					(unsigned long)hdr_buf2compress.len,
					mc_level);

			hdr_bufcompressed.len = temp;

			if (check_zlib_rc(rc)) {
				LM_ERR("Header compression failed\n");
				goto free_mem_full;
			}
		}

		break;
	case 1: /* gzip */
		if (buf2compress.s) {
			rc = gzip_compress(
					(unsigned char*)buf2compress.s,
					(unsigned long)buf2compress.len,
					&body_out,
					&temp,
					mc_level);

			if (check_zlib_rc(rc)) {
				LM_ERR("Body compression failed\n");
				goto free_mem_full;
			}

			bufcompressed.s = body_out.s;
			bufcompressed.len = (int)temp;
		}

		if ((flags&HDR_COMP_FLG) && hdr_buf2compress.s) {
			rc = gzip_compress(
					(unsigned char*)hdr_buf2compress.s,
					(unsigned long)hdr_buf2compress.len,
					&hdr_out,
					&temp,
					mc_level);

			if (check_zlib_rc(rc)) {
				LM_ERR("Header compression failed\n");
				goto free_mem_full;
			}
			hdr_bufcompressed.s = hdr_out.s;
			hdr_bufcompressed.len = temp;
		}

		break;
	default:
		LM_WARN("Invalind algo! no compression made\n");
		goto free_mem_full;
	}

	str bufencoded={NULL, 0};
	str hdr_bufencoded={NULL, 0};

	if ((flags&B64_ENCODED_FLG) && bufcompressed.s) {
		bufencoded.len = calc_base64_encode_len(bufcompressed.len);
		if (wrap_realloc( &body_in, 2*CRLF_LEN + bufencoded.len))
			goto free_mem_full;
		bufencoded.s = body_in.s;

		memcpy(bufencoded.s, CRLF, CRLF_LEN);

		base64encode((unsigned char*)(bufencoded.s + CRLF_LEN),
				(unsigned char*)bufcompressed.s,
							bufcompressed.len);
	} else if (bufcompressed.s) {
		if (wrap_realloc(&body_in, bufcompressed.len + 2*CRLF_LEN))
			goto free_mem_full;

		/* !!! shift buf2compressed CRLF_LEN to the right !!! */
		memcpy(body_in.s+CRLF_LEN, bufcompressed.s, bufcompressed.len);
		memcpy(body_in.s, CRLF, CRLF_LEN);

		bufencoded.len = bufcompressed.len;
		bufencoded.s = body_in.s;
	}

	if (hdr_bufcompressed.s) {

		hdr_bufencoded.len = calc_base64_encode_len(hdr_bufcompressed.len);

		if (wrap_realloc( &hdr_in, hdr_bufencoded.len + CRLF_LEN))
			goto free_mem_full;
		hdr_bufencoded.s = hdr_in.s;

		base64encode((unsigned char*)hdr_bufencoded.s,
				(unsigned char*)hdr_bufcompressed.s,
							hdr_bufcompressed.len);

		wrap_copy_and_update(&hdr_bufencoded.s, CRLF, CRLF_LEN,
							&hdr_bufencoded.len);
	}

	/* Allocate the new buffer */
	int alloc_size;
	str buf2send={NULL, 0};

	alloc_size = msg_start.len + uncompress_len + CRLF_LEN/*the one before all headers*/;

	if (hdr_bufencoded.s) {
		alloc_size += COMP_HDRS_LEN + hdr_bufencoded.len;
		alloc_size += sizeof(HDRS_ENCODING) - 1;
	}

	/* if body compressed new content length and content encoding
	 * plus if required more space for base64 in content encoding header*/

	if (bufencoded.s) {
		alloc_size += CL_NAME_LEN + mc_ndigits(bufencoded.len) + CRLF_LEN;
		alloc_size += CE_NAME_LEN + CRLF_LEN;
		if (flags&B64_ENCODED_FLG) {
			alloc_size += ATTR_DELIM_LEN + (sizeof(BASE64_ALGO)-1);
		}
	}


	switch (algo) {
		case 0: /* deflate*/
			if (bufencoded.s)
				alloc_size += DEFLATE_CE_LEN;
			if (hdr_bufencoded.s)
				alloc_size += sizeof(DEFLATE_ALGO) - 1;
			break;
		case 1: /* gzip */
			if (bufencoded.s)
				alloc_size += GZIP_CE_LEN;
			if (hdr_bufencoded.s)
				alloc_size += sizeof(GZIP_ALGO) - 1;
			break;
		default:
			LM_ERR("compression algo not impelemented\n");
			goto free_mem_full;
	}

	if (bufencoded.s)
		alloc_size += bufencoded.len + CRLF_LEN;
	else
		alloc_size += strlen(buf);

	if (wrap_realloc(&buf_out, alloc_size))
		goto free_mem_full;

	buf2send.s = buf_out.s;

	/* Copy message start */
	wrap_copy_and_update( &buf2send.s, msg_start.s, msg_start.len,
							&buf2send.len);

	/* Copy mandatory headers */
	for (mnd_hdrs = mnd_hdrs_head; mnd_hdrs; mnd_hdrs = mnd_hdrs->next) {
		wrap_copy_and_update( &buf2send.s, mnd_hdrs->name.s,
						mnd_hdrs->len, &buf2send.len);
	}


	if ((flags&BODY_COMP_FLG) && bufencoded.s) {
		wrap_copy_and_update( &buf2send.s, CL_NAME,
						CL_NAME_LEN, &buf2send.len);

		wrap_copy_and_update( &buf2send.s, int2str(bufencoded.len, &len),
					mc_ndigits(bufencoded.len), &buf2send.len);
		wrap_copy_and_update( &buf2send.s, CRLF, CRLF_LEN, &buf2send.len);
	}

	if (hdr_bufencoded.s) {
		wrap_copy_and_update( &buf2send.s, COMP_HDRS, COMP_HDRS_LEN,
								&buf2send.len);

		wrap_copy_and_update( &buf2send.s, hdr_bufencoded.s,
					hdr_bufencoded.len, &buf2send.len);

	}

	switch (algo) {
	case 0: /* deflate */
		if (hdr_bufencoded.s) {
			str hdr_name = str_init(HDRS_ENCODING),
				hdr_value = str_init(DEFLATE_ALGO);
			wrap_copy_and_update(&buf2send.s, hdr_name.s,
						hdr_name.len, &buf2send.len);

			if (flags & B64_ENCODED_FLG) {
				wrap_copy_and_update(&buf2send.s, BASE64_ALGO,
						sizeof(BASE64_ALGO)-1, &buf2send.len);
				wrap_copy_and_update(&buf2send.s, ATTR_DELIM,
						ATTR_DELIM_LEN, &buf2send.len);
			}
			wrap_copy_and_update(&buf2send.s, hdr_value.s,
						hdr_value.len, &buf2send.len);
			wrap_copy_and_update(&buf2send.s, CRLF,
							CRLF_LEN, &buf2send.len);

		}

		if (bufencoded.s) {
			wrap_copy_and_update(&buf2send.s, CE_NAME,
						CE_NAME_LEN, &buf2send.len);

			if (flags & B64_ENCODED_FLG) {
				wrap_copy_and_update(&buf2send.s, BASE64_ALGO,
						sizeof(BASE64_ALGO)-1, &buf2send.len);
				wrap_copy_and_update(&buf2send.s, ATTR_DELIM,
						ATTR_DELIM_LEN, &buf2send.len);
			}
			wrap_copy_and_update(&buf2send.s, DEFLATE_ALGO,
							sizeof(DEFLATE_ALGO)-1, &buf2send.len);
			wrap_copy_and_update(&buf2send.s, CRLF,
							CRLF_LEN, &buf2send.len);
		}
		break;
	case 1: /* gzip */
		if (hdr_bufencoded.s) {
			str hdr_name = str_init(HDRS_ENCODING),
				hdr_value = str_init(GZIP_ALGO);
			if (flags & B64_ENCODED_FLG) {
				wrap_copy_and_update(&buf2send.s, BASE64_ALGO,
						sizeof(BASE64_ALGO)-1, &buf2send.len);
				wrap_copy_and_update(&buf2send.s, ATTR_DELIM,
						ATTR_DELIM_LEN, &buf2send.len);
			}
			wrap_copy_and_update(&buf2send.s, hdr_name.s,
						hdr_name.len, &buf2send.len);
			wrap_copy_and_update(&buf2send.s, hdr_value.s,
						hdr_value.len, &buf2send.len);
			wrap_copy_and_update(&buf2send.s, CRLF,
							CRLF_LEN, &buf2send.len);
		}

		if (bufencoded.s) {
			wrap_copy_and_update(&buf2send.s, CE_NAME,
						CE_NAME_LEN, &buf2send.len);
			if (flags & B64_ENCODED_FLG) {
				wrap_copy_and_update(&buf2send.s, BASE64_ALGO,
						sizeof(BASE64_ALGO)-1, &buf2send.len);
				wrap_copy_and_update(&buf2send.s, ATTR_DELIM,
						ATTR_DELIM_LEN, &buf2send.len);
			}
			wrap_copy_and_update(&buf2send.s, GZIP_ALGO,
							sizeof(GZIP_ALGO)-1, &buf2send.len);
			wrap_copy_and_update(&buf2send.s, CRLF,
							CRLF_LEN, &buf2send.len);
		}
		break;
	default:
		LM_ERR("compression algo not impelemented\n");
		goto free_mem_full;
	}


	/* Copy message body */
	if (bufencoded.s) {
		wrap_copy_and_update( &buf2send.s, bufencoded.s,
					bufencoded.len+CRLF_LEN, &buf2send.len);

		wrap_copy_and_update( &buf2send.s, CRLF,
						CRLF_LEN, &buf2send.len);
	} else {
		wrap_copy_and_update( &buf2send.s, buf, strlen(buf),
							&buf2send.len);
	}

	switch (type) {
		case TM_CB:
			shm_free(*buf_p);
			*buf_p = shm_malloc(buf2send.len+1);
			if (*buf_p == NULL) {
				LM_ERR("no more sh mem\n");
				goto free_mem_full;
			}
			break;
		case PROCESSING_CB:
			*buf_p = pkg_malloc(buf2send.len+1);
			if (*buf_p == NULL) {
				LM_ERR("no more pkg mem\n");
				goto free_mem_full;
			}
			break;
		default:
			LM_ERR("invalid type\n");
			goto free_mem_full;
	}

	memcpy(*buf_p, buf2send.s, buf2send.len);
	(*buf_p)[buf2send.len] = '\0';
	*olen = buf2send.len;
	ret = 0;

free_mem_full:
	free_hdr_list(&mnd_hdrs_head);
	free_hdr_list(&non_mnd_hdrs_head);

	return ret;
}

/*
 *
 */
static int is_content_encoding(struct hdr_field* hf)
{

	#define CONT 0x746e6f43
	#define ENT  0x2d746e65
	#define ENCO 0x6f636e45
	#define DING 0x676e6964

	char* name = hf->name.s;

	if (DWORD(name) == CONT) {
		name += 4;
		if (DWORD(name) == ENT) {
			name += 4;
			if (DWORD(name) == ENCO) {
				name += 4;
				if (DWORD(name) == DING) {
					return 1;
				}
			}
		}
	}
	return 0;
}

/*
 *
 */
static int get_algo(str* tok)
{
	#define GZIP 0x70697a67
	#define DEFL 0x6C666564
	#define ATE  0x00657461
	#define BASE 0x65736162
	#define B64  0x00003436 /* actually only 64 */
	#define FIRST_THREE(_str_) (_str_ & 0xFFFFFF)
	#define FIRST_TWO(_str_) (_str_ & 0xFFFF)

	switch (DWORD(tok->s)) {
		case DEFL:
			break;
		case GZIP:
			return 1;
		case BASE:
			goto check_b64;
		default:
			return -1;
	}

	if (FIRST_THREE(DWORD(tok->s+4)) == ATE)
		return 0;

	return -1;

check_b64:
	if (FIRST_TWO(DWORD(tok->s+4)) == B64)
		return 2;

	return -1;

	#undef GZIP
	#undef DEFL
	#undef ATE
	#undef BASE
	#undef B64
	#undef FIRST_TWO
	#undef FIRST_THREE
}


/*
 * Function to decompress a compressed message
 */
static int mc_decompress(struct sip_msg* msg)
{
	#define HDRS_TO_SKIP 4

	int i;
	int j;
	int rc;
	int algo=-1;
	int hdrs_algo=-1;
	int b64_required=-1;

	str msg_body;
	str msg_final;

	str b64_decode={NULL, 0};
	str hdr_b64_decode={NULL,0};
	str uncomp_body={NULL,0};
	str uncomp_hdrs={NULL,0};

	char *new_buf;

	unsigned long temp;

	/* hdr_vec allows to sort the headers. This will help skipping
		these headers when building the new message */
	struct hdr_field *hf;
	struct hdr_field *hdr_vec[HDRS_TO_SKIP];
					/*hdr_vec : 	0 Content-Length
							1 Comp-Hdrs
							2 Headers-Algo
							3 Content-Encoding*/

	memset(hdr_vec, 0, HDRS_TO_SKIP * sizeof(struct hdr_field*));

	if (parse_headers(msg, HDR_EOH_F, 0) != 0) {
		LM_ERR("failed to parse SIP message\n");
		return -1;
	}

	/*If compressed with this module there are great chances that Content-Encoding is last*/
	hdr_vec[3] = msg->last_header;

	if (!is_content_encoding(hdr_vec[3])) {
		hdr_vec[3] = NULL;
		for (hf = msg->headers; hf; hf = hf->next) {
			if (is_content_encoding(hf)) {
				hdr_vec[3] = hf;
				continue;
			}
			if (hf->type == HDR_OTHER_T &&
				!strncasecmp(hf->name.s, COMP_HDRS,COMP_HDRS_LEN)) {
				hdr_vec[1] = hf;
				continue;
			}

			if (hf->type == HDR_OTHER_T &&
				!strncasecmp(hf->name.s, HDRS_ENCODING,
						sizeof(HDRS_ENCODING)-1)) {
				hdr_vec[2] = hf;
			}

			if (hdr_vec[1] && hdr_vec[2] && hdr_vec[3])
					break;
		}
	} else {
		for (hf = msg->headers; hf; hf = hf->next) {
			if (!hdr_vec[1] && hf->type == HDR_OTHER_T &&
				!strncasecmp(hf->name.s, COMP_HDRS,COMP_HDRS_LEN)) {
				hdr_vec[1] = hf;
				continue;
			}

			if (!hdr_vec[2] && hf->type == HDR_OTHER_T &&
				!strncasecmp(hf->name.s, HDRS_ENCODING,
						sizeof(HDRS_ENCODING)-1))
				hdr_vec[2] = hf;

			if (hdr_vec[2] && hdr_vec[3] && hdr_vec[1])
					break;
		}
	}

	/* Only if content-encoding present, Content-Length will be replaced
		with the one in the compressed body or in compressed headers*/

	if (hdr_vec[3]) {
		hdr_vec[0] = msg->content_length;
		parse_algo_hdr(hdr_vec[3], &algo, &b64_required);
	}


	if (b64_required > 0 && hdr_vec[3]) {
		msg_body.s = msg->last_header->name.s + msg->last_header->len + CRLF_LEN;
		msg_body.len = strlen(msg_body.s);

		/* Cutting CRLF'S at the end of the message */
		while (WORD(msg_body.s + msg_body.len-CRLF_LEN) == PARSE_CRLF) {
			msg_body.len -= CRLF_LEN;
		}

		if (wrap_realloc(&body_in, calc_max_base64_decode_len(msg_body.len)))
			return -1;

		b64_decode.s = body_in.s;

		b64_decode.len = base64decode((unsigned char*)b64_decode.s,
						(unsigned char*)msg_body.s,
							msg_body.len);
	} else if (hdr_vec[3]) {
		if (get_body(msg, &msg_body) < 0) {
			LM_ERR("failed to get body\n");
			return -1;
		}

		b64_decode.s = msg_body.s;
		b64_decode.len = msg_body.len;
	}

	b64_required=0;
	if (hdr_vec[2]) {
		parse_algo_hdr(hdr_vec[3], &algo, &b64_required);
	}

	if (b64_required > 0 &&  hdr_vec[1]) {
		if (wrap_realloc(&hdr_in, calc_max_base64_decode_len(hdr_vec[1]->body.len)))
			return -1;

		hdr_b64_decode.s = hdr_in.s;

		hdr_b64_decode.len = base64decode(
					(unsigned char*)hdr_b64_decode.s,
					(unsigned char*)hdr_vec[1]->body.s,
							hdr_vec[1]->body.len
					);
	} else if (hdr_vec[1]) {
		hdr_b64_decode.s = hdr_vec[1]->body.s;
		hdr_b64_decode.len = hdr_vec[1]->body.len;
	}

	switch (hdrs_algo) {
		case 0: /* deflate */
			temp = (unsigned long)BUFLEN;

			rc = uncompress((unsigned char*)hdr_buf,
					&temp,
					(unsigned char*)hdr_b64_decode.s,
					(unsigned long)hdr_b64_decode.len);

			uncomp_hdrs.s = hdr_buf;
			uncomp_hdrs.len = temp;

			if (check_zlib_rc(rc)) {
				LM_ERR("header decompression failed\n");
				return -1;
			}
			break;
		case 1: /* gzip */
			rc = gzip_uncompress(
					(unsigned char*)hdr_b64_decode.s,
					(unsigned long)hdr_b64_decode.len,
					&hdr_out,
					&temp);

			if (check_zlib_rc(rc)) {
				LM_ERR("header decompression failed\n");
				return -1;
			}

			uncomp_hdrs.s = hdr_out.s;
			uncomp_hdrs.len = temp;

			break;
		case -1:
			break;
		default:
			return -1;
	}

	switch (algo) {
		case 0: /* deflate */
			temp = (unsigned long)BUFLEN;

			rc = uncompress((unsigned char*)body_buf,
					&temp,
					(unsigned char*)b64_decode.s,
					(unsigned long)b64_decode.len);

			if (check_zlib_rc(rc)) {
				LM_ERR("body decompression failed\n");
				return -1;
			}

			uncomp_body.s = body_buf;
			uncomp_body.len = temp;

			break;
		case 1: /* gzip */
			rc = gzip_uncompress(
					(unsigned char*)b64_decode.s,
					(unsigned long)b64_decode.len,
					&body_out,
					&temp);

			if (check_zlib_rc(rc)) {
				LM_ERR("body decompression failed\n");
				return -1;
			}

			uncomp_body.s = body_out.s;
			uncomp_body.len = temp;

			break;
		case -1:
			LM_DBG("no body\n");
			break;
		default:
			LM_ERR("invalid algo\n");
			return -1;
	}

	/* Sort to have the headers in order */
	for (i = 0; i < HDRS_TO_SKIP - 1; i++) {
		for (j = i + 1; j < HDRS_TO_SKIP; j++) {
			if (!hdr_vec[j])
				continue;

			if (!hdr_vec[i] && hdr_vec[j]) {
				hdr_vec[i] = hdr_vec[j];
				hdr_vec[j] = NULL;
			}

			if ((hdr_vec[i] && hdr_vec[j]) &&
				(hdr_vec[i]->name.s > hdr_vec[j]->name.s)) {
				hf = hdr_vec[i];
				hdr_vec[i] = hdr_vec[j];
				hdr_vec[j] = hf;
			}
		}
	}

	int msg_final_len = 0;
	int msg_ptr=0;

	for ( i = 0; i < HDRS_TO_SKIP; i++) {
		if (hdr_vec[i]) {
			msg_final_len += hdr_vec[i]->name.s - (msg->buf+msg_ptr);
			msg_ptr += hdr_vec[i]->name.s+hdr_vec[i]->len - (msg->buf+msg_ptr);
		}
	}

	msg_final_len += msg->last_header->name.s + msg->last_header->len -
				(msg->buf + msg_ptr);

	if (hdrs_algo >= 0)
		msg_final_len += uncomp_hdrs.len;

	if (algo >= 0)
		msg_final_len += uncomp_body.len;
	else
		msg_final_len += strlen(msg->eoh);

	if (wrap_realloc(&buf_out, msg_final_len))
		return -1;

	msg_ptr = 0;

	msg_final.len = 0;
	msg_final.s = buf_out.s;

	for ( i = 0; i < HDRS_TO_SKIP; i++) {
		if (hdr_vec[i]) {
			wrap_copy_and_update(&msg_final.s,
					msg->buf+msg_ptr,
					hdr_vec[i]->name.s-(msg->buf+msg_ptr),
					&msg_final.len);

			msg_ptr += (hdr_vec[i]->name.s+hdr_vec[i]->len) -
					(msg->buf+msg_ptr);
		}
	}

	wrap_copy_and_update(
			&msg_final.s,
			msg->buf+msg_ptr,
			(msg->last_header->name.s+msg->last_header->len)-
							(msg->buf+msg_ptr),
			&msg_final.len
		);

	if (hdrs_algo >= 0) {
		wrap_copy_and_update(&msg_final.s, uncomp_hdrs.s,
					uncomp_hdrs.len,&msg_final.len);
	}

	if (algo >= 0) {
		wrap_copy_and_update(&msg_final.s, uncomp_body.s,
					uncomp_body.len, &msg_final.len);
	} else {
		wrap_copy_and_update(&msg_final.s, msg->eoh, strlen(msg->eoh), &msg_final.len);
	}

	/* new buffer because msg_final(out_buf) will
	 * be overwritten at next iteration */
	new_buf = msg->buf;

	memcpy(new_buf, msg_final.s, msg_final.len);
	new_buf[msg_final.len] = '\0';

	struct sip_msg tmp;

	memcpy(&tmp, msg, sizeof(struct sip_msg));

	/*reset dst_uri and path_vec to avoid free*/
	if (msg->dst_uri.s != NULL) {
		msg->dst_uri.s = NULL;
		msg->dst_uri.len = 0;
	}
	if (msg->path_vec.s != NULL)
	{
		msg->path_vec.s = NULL;
		msg->path_vec.len = 0;
	}

	free_sip_msg(msg);
	memset(msg, 0, sizeof(struct sip_msg));

	/* restore msg fields */
	msg->id					= tmp.id;
	msg->rcv				= tmp.rcv;
	msg->set_global_address = tmp.set_global_address;
	msg->set_global_port    = tmp.set_global_port;
	msg->flags              = tmp.flags;
	msg->msg_flags          = tmp.msg_flags;
	msg->hash_index         = tmp.hash_index;
	msg->force_send_socket  = tmp.force_send_socket;
	msg->dst_uri            = tmp.dst_uri;
	msg->path_vec           = tmp.path_vec;
	/* set the new ones */
	msg->buf = new_buf;
	msg->len = msg_final.len;

	/* reparse the message */
	if (parse_msg(msg->buf, msg->len, msg) != 0)
		LM_ERR("parse_msg failed\n");

	return 1;
}


static inline void parse_algo_hdr(struct hdr_field* algo_hdr, int* algo, int* b64_required)
{
	int rc;
	char* delim=NULL;

	str tok;
	str s_tok;

	s_tok.s = algo_hdr->body.s;
	s_tok.len = algo_hdr->body.len;

	do {
		delim = q_memchr(s_tok.s, ATTR_DELIM[0], s_tok.len);

		if (delim==NULL) {
			trim_spaces_lr(s_tok);
			rc = get_algo(&s_tok);
		} else {
			tok.s = s_tok.s;
			tok.len = delim - s_tok.s;

			s_tok.s = delim+1;
			s_tok.len = (delim-tok.s+1);

			trim_spaces_lr(tok);
			rc = get_algo(&tok);
		}

		if (rc < 2 && rc >=0)
			*algo = rc;
		else
			*b64_required = rc;
	} while(delim);
}
