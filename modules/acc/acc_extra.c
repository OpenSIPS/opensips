/*
 * Copyright (C) 2004-2006 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
 *
 * History:
 * ---------
 *  2004-10-28  first version (ramona)
 *  2005-05-30  acc_extra patch commited (ramona)
 *  2005-07-13  acc_extra specification moved to use pseudo-variables (bogdan)
 *  2006-09-08  flexible multi leg accounting support added,
 *              code cleanup for low level functions (bogdan)
 *  2006-09-19  final stage of a masive re-structuring and cleanup (bogdan)
 */



#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../../dprint.h"
#include "../../ut.h"
#include "../../trim.h"
#include "../../usr_avp.h"
#include "../../socket_info.h"
#include "../../mem/mem.h"
#include "acc_extra.h"
#include "acc_logic.h"
#include "acc_mod.h"

#define EQUAL '='
#define SEPARATOR ';'
#define REPLY_STR_S  "reply"
#define REPLY_STR_LEN (sizeof(REPLY_STR_S)-1)


#if MAX_ACC_EXTRA<MAX_ACC_LEG
	#define MAX_ACC_INT_BUF MAX_ACC_LEG
#else
	#define MAX_ACC_INT_BUF MAX_ACC_EXTRA
#endif

extern struct acc_extra *log_extra_tags;
extern struct acc_extra *db_extra_tags;
extern struct acc_extra *aaa_extra_tags;
extern struct acc_extra *evi_extra_tags;

extern int    extra_tgs_len;
extern tag_t* extra_tags;

extern struct acc_extra *log_leg_tags;
extern struct acc_extra *db_leg_tags;
extern struct acc_extra *aaa_leg_tags;
extern struct acc_extra *evi_leg_tags;

extern int    leg_tgs_len;
extern tag_t* leg_tags;

static const str tag_delim = str_init("->");

/* here we copy the strings returned by int2str (which uses a static buffer) */
static char int_buf[MAX_ACC_BUFS][INT2STR_MAX_LEN*MAX_ACC_INT_BUF];

static char* static_detector[2] = {NULL,NULL};

typedef struct acc_extra** (*str2bkend)(str*);


void init_acc_extra(void)
{
	int i;
	/* ugly trick to get the address of the static buffer */
	static_detector[0] = int2str( (unsigned long)3, &i) + i;
	/* remember directly the static buffer returned by ip_addr2a()*/
	static_detector[1] = _ip_addr_A_buff;
}


/*
 * insert a tag int the tags vector
 * @param  tag to insert(str value)
 * @return inserted tag index
 */
/* add tag list param
 * tag list will differ for extra/leg */
static inline int add_tag(str* _stag, tag_t** tag_arr, int* tags_len)
{
	int ret=-1, i;

	if (*tags_len == 0) {
		(*tag_arr) = pkg_malloc(TAGS_FACTOR * sizeof(tag_t));
		if ((*tag_arr) == NULL)
			goto out_nomem;
	} else if ((*tags_len) % TAGS_FACTOR == 0) {
		(*tag_arr) = pkg_realloc((*tag_arr),
					(*tags_len + TAGS_FACTOR) * sizeof(tag_t));
		if ((*tag_arr) == NULL)
			goto out_nomem;
	}

	/* serach whether tag has already been inserted */
	for (i=0; i < *tags_len; i++) {
		if ((*tag_arr)[i].len == _stag->len &&
				!memcmp(_stag->s, (*tag_arr)[i].s, (*tag_arr)[i].len))
			return i;
	}

	ret = (*tags_len)++;
	(*tag_arr)[ret] = *_stag;

	return ret;

out_nomem:
	LM_ERR("no more pkg mem!\n");
	return ret;
}


/*
 * insert extra into it's list after creating the element
 * and adding the tag into the tag list
 * @param tag
 * @param value
 * @param insert list
 * @return 0(success)/ < 0 (error)
 */
static inline int add_extra(str* tag, str* value,
		struct acc_extra** bkend_list, tag_t** tag_arr, int* tags_len)
{
	int tag_idx;

	struct acc_extra *xel, *it;

	/* first try adding the tag */
	if ((tag_idx=add_tag(tag, tag_arr, tags_len)) < 0) {
		LM_ERR("failed to add tag\n");
		return -1;
	}

	if ((xel=pkg_malloc(sizeof(struct acc_extra))) == NULL) {
		LM_ERR("no more pkg mem!\n");
		return -1;
	}

	xel->tag_idx = tag_idx;
	xel->name = *value;


	xel->next  = NULL;

	if (*bkend_list == NULL) {
		*bkend_list = xel;
		return 0;
	}

	for ( it=*bkend_list; it; it=it->next) {
		/* check if someone is trying to define same tag twice
		 * for the same backend*/
		if (it->tag_idx == xel->tag_idx) {
			LM_WARN("Tag <%.*s> redefined for same backend!"
				" Previous definition for this tag in this backend"
				" will be overridden!\n",
				extra_tags[xel->tag_idx].len, extra_tags[xel->tag_idx].s);
			break;
		}

		/* add the element at the end of the list and exit */
		if (it->next == NULL) {
			it->next = xel;
			break;
		}
	}

	return 0;
}


static struct acc_extra** extra_str2bkend(str* bkend)
{
	str log_bkend_s = str_init("log");
	str db_bkend_s = str_init("db");
	str aaa_bkend_s = str_init("aaa");
	str evi_bkend_s = str_init("evi");

	if (str_match(bkend, &log_bkend_s))
		return &log_extra_tags;

	if (str_match(bkend, &db_bkend_s))
		return &db_extra_tags;

	if (str_match(bkend, &aaa_bkend_s))
		return &aaa_extra_tags;

	if (str_match(bkend, &evi_bkend_s))
		return &evi_extra_tags;

	return NULL;
}

static struct acc_extra** leg_str2bkend(str* bkend)
{
	str log_bkend_s = str_init("log");
	str db_bkend_s = str_init("db");
	str aaa_bkend_s = str_init("aaa");
	str evi_bkend_s = str_init("evi");

	if (str_match(bkend, &log_bkend_s))
		return &log_leg_tags;

	if (str_match(bkend, &db_bkend_s))
		return &db_leg_tags;

	if (str_match(bkend, &aaa_bkend_s))
		return &aaa_leg_tags;

	if (str_match(bkend, &evi_bkend_s))
		return &evi_leg_tags;

	return NULL;
}



/*
 * from a token in form of
 * tag->value extract the tag and the value
 * @param token
 * @param tag reference
 * @param value reference
 * @return 0 (success) / < 0 (error)
 *
 * tag and value must be allocated beforehand
 */
static int parse_extra_token(str* token, str* tag, str* value)
{

	/* insanity checks */
	if (token == NULL || token->len == 0 || token->s == NULL
							|| tag == NULL || value == NULL) {
		LM_ERR("bad input!\n");
		return -1;
	}

	/* remove tabs, newlines etc */
	while ( token->s[0] == '\n' || token->s[0] == '\t' || token->s[0] == ' ') {
		token->s++;
		token->len--;
	}

	/* value will not point exactly where the value is
	 * will point where the - character from the '->' delimiter will be */
	if ((value->s = str_strstr(token, &tag_delim)) == NULL) {
		/* if not found then the value is the same as the token */
		str_trim_spaces_lr(*token);

		/**
		 * FIXME null terminate the string
		 * quite insane to do this but it should be safe because after the token
		 * it's either a delimiter for another token or a '\0' that
		 * terminates the string
		 */
		token->s[token->len] = 0;
		*value = *tag = *token;
	} else {
		tag->s = token->s;
		tag->len = value->s - token->s;

		/* jump over '->' delimiter */
		value->s += tag_delim.len;
		value->len = token->len - (value->s - token->s);

		str_trim_spaces_lr(*tag);
		str_trim_spaces_lr(*value);

		/**
		 * FIXME null terminate the string
		 * safe because after the tag it's the tag-value delimiter
		 */
		tag->s[tag->len] = 0;

		/**
		 * FIXME null terminate the string
		 * quite insane to do this but it should be safe because after the token
		 * it's either a delimiter for another token or a '\0' that
		 * terminates the string
		 */
		value->s[value->len] = 0;
	}

	return 0;
}


/*
 * parse acc extra element in form of
 * <backend>:<tag1>=<value1>;<tag2>=<value2>[;]
 * last semicolon may miss
 * all tags shall be added (if not present) to the tag list
 * and be linked to all extra structures in acc_extra lists by
 * the index in the vector
 *
 * @param string to be parsed(char*)
 * @return 0(success) / < 0 (error)
 */
static int parse_acc_list_generic(void* val, str2bkend str2bk,
		tag_t** tag_arr, int* tags_len)
{

	str sent={(char*)val, strlen((char*)val)};
	str tok_list_s, backend_s;

	str token, tag, value;

	struct acc_extra** bkend_list;

	char* end;

	trim(&sent);

	if ((end=q_memchr(sent.s, ':', sent.len)) == NULL) {
		LM_ERR("Missing backend separator ':'!\n");
		return -1;
	}

	backend_s.s = sent.s;
	backend_s.len =  end-sent.s;
	str_trim_spaces_lr(backend_s);

	if ((bkend_list = str2bk(&backend_s)) == NULL) {
		LM_ERR("Invalid backend <%.*s>\n", backend_s.len, backend_s.s);
		return -1;
	}

	tok_list_s.s = end+1;
	tok_list_s.len = sent.len - (end - sent.s + 1);

	do {
		end=q_memchr(tok_list_s.s, ';', tok_list_s.len);

		/* get key=value parameter */
		token.s = tok_list_s.s;

		if (end != NULL) {
			token.len = end-tok_list_s.s;
			tok_list_s.len = tok_list_s.len - (end - tok_list_s.s + 1);
			tok_list_s.s = end + 1;
		} else {
			token.len = tok_list_s.len;
		}

		if (token.len <= 0)
			break;

		/* we reached the end or there are probably some trailing spaces
		 * after the last ';' */
		str_trim_spaces_lr(token);
		if (!token.len)
			break;

		if (parse_extra_token(&token, &tag, &value) < 0) {
			LM_ERR("failed to parse token!\n");
			return -1;
		}


		if (add_extra(&tag, &value, bkend_list, tag_arr, tags_len) < 0) {
			LM_ERR("failed to add extra!\n");
			return -1;
		}
	} while (end);

	return 0;
}

int parse_acc_extra(modparam_t type, void* val) {
	return parse_acc_list_generic(val, extra_str2bkend, &extra_tags, &extra_tgs_len);
}

int parse_acc_leg(modparam_t type, void* val) {
	return parse_acc_list_generic(val, leg_str2bkend, &leg_tags, &leg_tgs_len);
}


/*
 * build an array with pv_value_t type variables
 * that will store the extra variables
 */
int build_acc_extra_array(int array_len, extra_value_t** array_p)
{
	extra_value_t* array;

	if (array_p == NULL) {
		LM_ERR("bad usage!\n");
		return -1;
	}


	array = shm_malloc(array_len * sizeof(extra_value_t));
	if (array == NULL) {
		LM_ERR("no more shm!\n");
		return -1;
	}

	memset(array, 0, array_len * sizeof(extra_value_t));

	*array_p = array;

	return 0;

}

int build_acc_extra_array_pkg(int array_len, extra_value_t** array_p)
{
	extra_value_t* array;

	if (array_p == NULL) {
		LM_ERR("bad usage!\n");
		return -1;
	}


	array = pkg_malloc(array_len * sizeof(extra_value_t));
	if (array == NULL) {
		LM_ERR("no more shm!\n");
		return -1;
	}

	memset(array, 0, array_len * sizeof(extra_value_t));

	*array_p = array;

	return 0;
}

/*
 * create/add new row to the leg matrix
 * initialize all values in current row with null
 *
 * */
int push_leg(acc_ctx_t* ctx)
{
	if (ctx == NULL) {
		LM_ERR("bad usage!\n");
		return -1;
	}

	if (ctx->leg_values == NULL) {
		ctx->leg_values =
			shm_malloc(LEG_MATRIX_ALLOC_FACTOR * sizeof(leg_value_p));
		ctx->allocated_legs = LEG_MATRIX_ALLOC_FACTOR;
	} else if (ctx->legs_no + 1 == ctx->allocated_legs) {
		ctx->leg_values =
			shm_realloc(ctx->leg_values,
					(ctx->allocated_legs + LEG_MATRIX_ALLOC_FACTOR) *
						sizeof(leg_value_p));
		ctx->allocated_legs += LEG_MATRIX_ALLOC_FACTOR;
	}

	if (ctx->leg_values == NULL) {
		LM_ERR("no more shm!\n");
		return -1;
	}

	return build_acc_extra_array(leg_tgs_len, &ctx->leg_values[ctx->legs_no++]);
}

void destroy_extras( struct acc_extra *extra)
{
	struct acc_extra *foo;

	while (extra) {
		foo = extra;
		extra = extra->next;
		shm_free(foo);
	}
}


/* extra name is moved as string part of an attribute; str.len will contain an
 * index to the corresponding attribute
 */
int extra2attrs( struct acc_extra *extra, aaa_map *attrs, int offset)
{
	int i;

	for(i = 0 ; extra ; i++, extra=extra->next) {
		attrs[offset+i].name = extra->name.s;
	}
	return i;
}


/* converts the name of the extra from str to integer
 * and stores it over str.len ; str.s is freed and made zero
 */
int extra2int( struct acc_extra *extra, int *attrs )
{
	unsigned int ui;
	int i;

	for( i=0 ; extra ; i++,extra=extra->next ) {
		if (str2int( &extra->name, &ui)!=0) {
			LM_ERR("<%s> is not a number\n", extra->name.s);
			return -1;
		}
		attrs[i] = (int)ui;
	}
	return i;
}



int extra2strar( extra_value_t* values, str *val_arr, int idx)
{
	int n;
	int r;

	if (idx < 0 || idx > MAX_ACC_BUFS-2 /* last one is for legs */) {
		LM_ERR("Invalid buffer index %d - maximum %d\n", idx, MAX_ACC_BUFS-2);
		return 0;
	}

	for( n=0,r=0 ; n < extra_tgs_len ; n++) {
		/* get the value */
		/* check for overflow */
		if (n==MAX_ACC_EXTRA) {
			LM_WARN("array to short -> omitting extras for accounting\n");
			goto done;
		}

		if(values[n].value.s == NULL) {
			/* convert <null> to empty to have consistency */
			val_arr[n].s = 0;
			val_arr[n].len = 0;
		} else {
			/* set the value into the acc buffer */
			if (values[n].value.s+values[n].value.len==static_detector[0] ||
			values[n].value.s==static_detector[1]) {
				val_arr[n].s = int_buf[idx] + r*INT2STR_MAX_LEN;
				val_arr[n].len = values[n].value.len;
				memcpy(val_arr[n].s, values[n].value.s, values[n].value.len);
				r++;
			} else {
				val_arr[n] = values[n].value;
			}
		}
	}

done:
	return n;
}
