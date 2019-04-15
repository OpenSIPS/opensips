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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "compression_helpers.h"

#include "../../parser/hf.h"
#include "../../ut.h"
#include "../../parser/parse_hname2.h"
#include "../../mod_fix.h"
#include "zlib.h"
#include "../../parser/msg_parser.h"

#define CONTENT_ENCODING "Content-Encoding"
#define HDR_DELIM '|'
#define MAX_HDR_NAME 50
#define NO_FORM 	255
static char parse_hdr_name[MAX_HDR_NAME];




/*
 * Function that receives header type and returns the
 * compact form character if exists or '\0' instead
 */
unsigned char get_compact_form(struct hdr_field* hf)
{

//	str content_encoding = str_init(CONTENT_ENCODING);

	/* Less comparations*/
	if (!(compact_form_mask[hf->type/MC_BYTE_SIZE] &
		(1 << (hf->type%MC_BYTE_SIZE))))
		return NO_FORM;

	switch (hf->type) {
		case HDR_CONTENTTYPE_T :
			return 0;
		case HDR_FROM_T :
			return 1;
		case HDR_CALLID_T :
			return 2;
		case HDR_SUPPORTED_T :
			return 3;
		case HDR_CONTENTLENGTH_T :
			return 4;
		case HDR_CONTACT_T :
			return 5;
		case HDR_SUBJECT_T :
			return 6;
		case HDR_TO_T :
			return 7;
		case HDR_VIA_T :
			return 8;
		case HDR_SESSION_EXPIRES_T :
			return 9;
/*		case HDR_OTHER_T :
			if (strncasecmp(hf->name.s, content_encoding.s,
							content_encoding.len))
				break;
			return 'e';*/
		default :
			return NO_FORM;
	}

	return 255;
}

int append_hdr(mc_whitelist_p wh_list, str* hdr_name)
{
	mc_other_hdr_lst_p hdr_lst = NULL;
	hdr_lst = pkg_malloc(sizeof(mc_other_hdr_lst_t) + hdr_name->len);
	if (!hdr_lst) {
		LM_ERR("no more pkg mem\n");
		return E_OUT_OF_MEM;
	}
	hdr_lst->hdr_name.len = hdr_name->len;
	hdr_lst->hdr_name.s = (char *)(hdr_lst + 1);
	memcpy(hdr_lst->hdr_name.s, hdr_name->s, hdr_name->len);
	hdr_lst->next = wh_list->other_hdr;
	wh_list->other_hdr = hdr_lst;
	return 0;
}

/*
 * Function that gets header enum value
 * if exists
 */
int search_hdr(mc_whitelist_p wh_list, str* hdr_name)
{
	struct hdr_field hdr;
	str temp;

	temp.len = hdr_name->len;
	temp.s = parse_hdr_name;
	memcpy(temp.s, hdr_name->s, hdr_name->len);
	temp.s[temp.len++] = ':';

	if (parse_hname2(temp.s, temp.s + temp.len, &hdr) == 0) {
		LM_ERR("parsing header name\n");
		return E_UNSPEC;
	}

	if (hdr.type!=HDR_OTHER_T && hdr.type!=HDR_ERROR_T) {
		wh_list->hdr_mask[hdr.type/MC_BYTE_SIZE] |=
				(unsigned char)1 << (hdr.type % MC_BYTE_SIZE);
		LM_DBG("Using flag for hdr\n");
		return 0;
	}

	LM_DBG("Using str for hdr for %.*s\n", hdr_name->len, hdr_name->s);
	return append_hdr(wh_list, hdr_name);
}

/*
 * Function that parses whitelist string
 */
int parse_whitelist(str* param, mc_whitelist_p* wh_list_p, unsigned char* def_hdrs_mask)
{
	mc_whitelist_p wh_list;
	char *sparam, *sparam_end;
	str hdr_name;
	int new_hdr = 1, eoh=0;

	wh_list = pkg_malloc(sizeof(mc_whitelist_t));
	if (!wh_list) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(wh_list, 0, sizeof (*wh_list));

	if (def_hdrs_mask)
		memcpy(wh_list->hdr_mask, def_hdrs_mask, HDR_MASK_SIZE);

	if (param == NULL)
		goto end;

	sparam_end = param->s + param->len;
	for (sparam = param->s ; sparam != sparam_end; sparam++) {
		switch (*sparam) {
			case ' ' :
			case ';' :
			case HDR_DELIM :
				/* The first charcter after header name have
				have to be ':' for parse_hname2 */
				if (eoh) {
					eoh = 0;
					if (search_hdr(wh_list, &hdr_name)) {
						LM_ERR("cannot find given header [%.*s]\n",
								hdr_name.len, hdr_name.s);
						return -1;
					}
				}

				if (*sparam == ' ' || *sparam == ';')
					break;

				/* A new header name was found if ','*/
				new_hdr = 1;

				break;
			default :
				/* found the first char in header name */
				if (new_hdr) {
					new_hdr = 0;
					hdr_name.len  	= 1;
					hdr_name.s  	= sparam;
					eoh = 1;
				} else {
					hdr_name.len++;
				}
				break;
		}
	}

	/* Last header name which may not have been moved to wh_list */
	if (eoh) {
		if (search_hdr(wh_list, &hdr_name)) {
			LM_ERR("cannot find last given header\n");
			return -1;
		}
	}

end:
	*wh_list_p = wh_list;
	return 0;
}

/*
 *
 */
int fixup_compression_flags(void** param)
{

	int *flags;
	str *it;
	char *c, *end;

	if (!*param) {
		LM_ERR("NULL parameter given\n");
		return -1;
	}

	it = (str *)*param;
	flags = pkg_malloc(sizeof(*flags));
	if (!flags) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	*flags = 0;

	for (c = it->s, end = it->s + it->len; c < end; c++) {
		switch (*c) {
			case 'b' :
				*flags |= BODY_COMP_FLG;
				break;
			case 'e':
				*flags |= B64_ENCODED_FLG;
				break;
			case 'h' :
				*flags |= HDR_COMP_FLG;
				break;
			case 's' :
				*flags |= SEPARATE_COMP_FLG;
				break;
			default :
				LM_ERR("Unknown compression flag: %c\n", *c);
				break;
		}
	}

	*param = (void*)flags;

	return 0;
}

int free_hdr_list(struct hdr_field** hf_p)
{
	struct hdr_field *hf = *hf_p, *temp;

	while (hf) {
		temp = hf;
		hf = hf->next;
		clean_hdr_field(temp);
		pkg_free(temp);
	}

	return 0;
}

int free_whitelist(mc_whitelist_p whitelist)
{
	mc_other_hdr_lst_p temp;

	if (!whitelist)
		return 0;

	while (whitelist->other_hdr) {
		temp = whitelist->other_hdr;
		whitelist->other_hdr = whitelist->other_hdr->next;
		pkg_free(temp);
	}

	pkg_free(whitelist);

	return 0;

}

int fixup_compression_flags_free(void **param)
{
	pkg_free(*param);
	return 0;
}


int free_hdr_mask(struct hdr_field** hdr_mask)
{
	int i;
	struct hdr_field *hf1, *hf2;

	for (i = 0; i < HDR_EOH_T; i++) {
		if (hdr_mask[i]) {
		try_again:
			hf1 = hdr_mask[i];
			if (hf1->sibling) {
				hf2 = hf1->sibling;
				while (hf2) {
					hf1 = hf2;
					hf2 = hf2->sibling;
					pkg_free(hf1);
				}
			}


			hf1 = hdr_mask[i];

			if (hf1->name.s[0] >= 'a') {
				pkg_free(hf1->name.s);
			}

			if (hf1->next) {
				hdr_mask[i] = hf1->next;
				pkg_free(hf1);
				goto try_again;
			} else {
				pkg_free(hdr_mask[i]);
			}
		}
	}

	pkg_free(hdr_mask);
	return 0;
}

int check_zlib_rc(int rc)
{
	switch (rc) {
		case Z_OK:
			LM_DBG("compression successful\n");
			return 0;
		case Z_MEM_ERROR:
			LM_ERR("not enough memory in compressed buffer\n");
			return -1;
		case Z_BUF_ERROR:
			LM_ERR("not enough room in output buffer\n");
			return -1;
		case Z_STREAM_ERROR:
			LM_ERR("invalid compression level\n");
			return -1;
		case Z_DATA_ERROR:
			LM_ERR("input data incomplete or corrupted\n");
			return -1;
		default:
			LM_ERR("invalid return code from zlib\n");
			return -1;
	}
}

int wrap_realloc(str* buf, int new_len)
{
	if (buf->s==NULL) {
		buf->s = pkg_malloc(new_len);
		if (!buf->s)
			goto memerr;

		buf->len = new_len;
	} else if (buf->s != NULL && new_len > buf->len) {
		memset(buf->s, 0, buf->len);
		buf->s = pkg_realloc(buf->s, new_len);
		if (!buf->s)
			goto memerr;

		buf->len = new_len;
	}

	return 0;

memerr:
	LM_ERR("no more pkg mem\n");
	return -1;
}
