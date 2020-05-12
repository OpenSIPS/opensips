/*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2006 Voice Sistem SRL
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
 *  2003-03-19  replaced all mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2006-12-22  added script flags (bogdan)
 */

/*!
 * \file
 * \brief OpenSIPS configuration flag functions.
 */


#include "sr_module.h"
#include "dprint.h"
#include "parser/msg_parser.h"
#include "mem/mem.h"
#include "ut.h"
#include "flags.h"

/* several lists of maximum MAX_FLAG flags */
struct flag_entry *flag_lists[FLAG_LIST_COUNT];

/* buffer used to offer string representations of flag bitmasks */
static char print_buffer[PRINT_BUFFER_SIZE];

/*********************** msg flags ****************************/

int setflag(struct sip_msg* msg, flag_t flag)
{
#ifdef EXTRA_DEBUG
	LM_DBG("mflags for %p : (%u, %u)\n", msg, flag, msg->flags);
#endif
	msg->flags |= 1 << flag;
	return 1;
}

int resetflag(struct sip_msg* msg, flag_t flag)
{
#ifdef EXTRA_DEBUG
	LM_DBG("mflags for %p : (%u, %u)\n", msg, flag, msg->flags);
#endif
	msg->flags &= ~ (1 << flag);
	return 1;
}

int isflagset(struct sip_msg* msg, flag_t flag)
{
#ifdef EXTRA_DEBUG
	LM_DBG("mflags for %p : (%u, %u)\n", msg, flag, msg->flags);
#endif
	return (msg->flags & (1<<flag)) ? 1 : -1;
}

int flag_in_range( flag_t flag ) {
	if ( flag > MAX_FLAG ) {
		LM_ERR("message flag (%d) must be in range %d..%d\n",
			flag, 1, MAX_FLAG );
		return 0;
	}
	return 1;
}

int flag_idx2mask(int *flag)
{
	if (*flag<0) {
		*flag = 0;
	} else if (*flag>(int)MAX_FLAG) {
		LM_ERR("flag %d out of range\n",*flag);
		return -1;
	} else {
		*flag = 1<<(*flag);
	}
	return 0;
}

str bitmask_to_flag_list(enum flag_type type, int bitmask)
{
	struct flag_entry *entry;
	str ret;

#ifdef EXTRA_DEBUG
	LM_DBG("bitmask -> %u\n", bitmask);
#endif
	ret.s   = print_buffer;
	ret.len = 0;
	for (entry = flag_lists[type]; entry; entry = entry->next) {

		if (bitmask & (1 << entry->bit)) {
			memcpy(ret.s + ret.len, entry->name.s, entry->name.len);
			ret.len += entry->name.len;

			ret.s[ret.len++] = FLAG_DELIM;
		}
	}

	if (ret.len > 0)
		ret.len--;

	return ret;
}

int flag_list_to_bitmask(str *flags, enum flag_type type, char delim)
{
	char *p, *lim;
	char *crt_flag;
	str name;
	struct flag_entry *e;
	int ret = 0;

	if (flags->len < 0)
		return 0;

#ifdef EXTRA_DEBUG
	LM_DBG("flag_list -> '%.*s'\n", flags->len, flags->s);
#endif
	lim = flags->s + flags->len;
	crt_flag = flags->s;
	for (p = flags->s; p <= lim; p++) {

		if (p == lim || *p == delim) {

			name.s   = crt_flag;
			name.len = p - crt_flag;
			for (e = flag_lists[type]; e; e = e->next) {
				if (e->name.len == p - crt_flag &&
				    str_strcmp(&e->name, &name) == 0) {

					ret |= 1 << e->bit;
					break;
				}
			}

			crt_flag = p + 1;
		}
	}

	return ret;
}

/**
 * The function MUST be called only in the pre-forking phases of OpenSIPS
 * (mod_init() or in function fixups)
 */
int get_flag_id_by_name(int flag_type, char *flag_name, int flag_name_len)
{
	struct flag_entry *it, **flag_list;
	str fn;

	if (!flag_name) {
		LM_DBG("Flag name is null!\n");
		return -1;
	}

	fn.s = flag_name;
	fn.len = (flag_name_len<=0)?strlen(flag_name):flag_name_len;

	if (fn.len == 0) {
		LM_WARN("found empty string flag modparam! possible scripting error?\n");
		return -1;
	}

	if (flag_type < 0 || flag_type >= FLAG_LIST_COUNT) {
		LM_ERR("Invalid flag list: %d\n", flag_type);
		return -2;
	}

	flag_list = flag_lists + flag_type;

	if (*flag_list && (*flag_list)->bit == MAX_FLAG) {
		LM_CRIT("Maximum number of message flags reached! (32 flags)\n");
		return E_CFG;
	}

	/* Check if flag has been already defined */
	for (it = *flag_list; it; it = it->next) {
		if (str_strcmp(&it->name, &fn) == 0) {

			return it->bit;
		}
	}

	if (!(it = pkg_malloc(sizeof(*it) + fn.len))) {
		LM_CRIT("Out of memory!\n");
		return E_OUT_OF_MEM;
	}

	it->name.s = (char *)(it + 1);
	it->name.len = fn.len;
	memcpy(it->name.s, fn.s, fn.len);

	it->bit = (*flag_list ? (*flag_list)->bit + 1 : 0);

	it->next = *flag_list;
	*flag_list = it;

	LM_DBG("New flag: [ %.*s : %d ][%d]\n", fn.len, fn.s, it->bit, flag_type);
	return it->bit;
}

unsigned int fixup_flag(int flag_type, str *flag_name)
{
	int ret;

	ret = get_flag_id_by_name(flag_type, flag_name->s, flag_name->len);

	if (ret < 0) {
		LM_CRIT("Failed to get a flag id!\n");
		return NAMED_FLAG_ERROR;
	}

	if (flag_type != FLAG_TYPE_MSG)
		return 1 << ret;

	return ret;
}
