/**
 * Copyright (C) 2012 OpenSIPS Solutions
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
 * History
 * -------
 * 2012-11-21  created (Liviu)
 *
 */

#include "script_locks.h"

static static_lock *static_locks = NULL;
static gen_lock_set_t *dynamic_locks;

extern int lock_pool_size;

int create_dynamic_locks(void)
{
	dynamic_locks = lock_set_alloc(lock_pool_size);

	if (!dynamic_locks) {
		LM_ERR("SHM MEMORY depleted!\n");
		return -1;
	}

	lock_set_init(dynamic_locks);

	return 0;
}

int fixup_static_lock(void **param, int param_no)
{
	static_lock *lock_entry;

	if (param_no != 1) {
		LM_ERR("Invalid parameter!\n");
		return -1;
	}

	if (*param && *((char *)*param) == PV_MARKER) {
		LM_ERR("get_static_lock() only accepts string values!\n");
		return -1;
	}

	for (lock_entry = static_locks; lock_entry; lock_entry = lock_entry->next) {
		if (memcmp(lock_entry->name.s, *param, lock_entry->name.len) == 0) {

			*param = (void *)lock_entry->lock;
			return 1;
		}
	}

	lock_entry = shm_malloc(sizeof(*lock_entry));

	if (!lock_entry) {
		LM_ERR("SHM MEMORY depleted!\n");
		return -1;
	}

	lock_entry->name.s = (char *) *param;
	lock_entry->name.len = strlen(lock_entry->name.s);

	lock_entry->lock = lock_alloc();
	lock_init(lock_entry->lock);

	lock_entry->next = static_locks;
	static_locks = lock_entry;

	*param = (void *)lock_entry->lock;
	return 1;
}

int get_static_lock(struct sip_msg *msg, char *lock)
{
	LM_DBG("Getting static lock----- <%p>\n", lock);
	lock_get((gen_lock_t *)lock);
	LM_DBG("Got static lock----- <%p>\n", lock);

	return 1;
}

int release_static_lock(struct sip_msg *msg, char *lock)
{
	lock_release((gen_lock_t *)lock);
	LM_DBG("Released static lock----- <%p>\n", lock);

	return 1;
}

int get_dynamic_lock(struct sip_msg *msg, char *string)
{
	str ret;
	int hash;

	if (((gparam_p)string)->type == GPARAM_TYPE_STR) {
		LM_INFO("Static string given! get_static_lock() function is better!\n");
	}

	if (fixup_get_svalue(msg, (gparam_p)string, &ret) != 0) {
		LM_ERR("Get string from fixup param failed!\n");
		return -1;
	}

	hash = (int)core_hash(&ret, NULL, lock_pool_size);

	LM_DBG("Getting dynamic lock----- %d\n", hash);
	lock_set_get(dynamic_locks, hash);
	LM_DBG("Got dynamic lock----- %d\n", hash);

	return 1;
}

int release_dynamic_lock(struct sip_msg *msg, char *string)
{
	str ret;
	int hash;

	if (fixup_get_svalue(msg, (gparam_p)string, &ret) != 0) {
		LM_ERR("Get string from fixup param failed!\n");
		return -1;
	}

	hash = (int)core_hash(&ret, NULL, lock_pool_size);

	lock_set_release(dynamic_locks, hash);
	LM_DBG("Released dynamic lock----- %d\n", hash);

	return 1;
}

int strings_share_lock(struct sip_msg *msg, char *s1, char *s2)
{
	str ret1, ret2;

	if (fixup_get_svalue(msg, (gparam_p)s1, &ret1) != 0) {
		LM_ERR("Get string from fixup param failed!\n");
		return -1;
	}

	if (fixup_get_svalue(msg, (gparam_p)s2, &ret2) != 0) {
		LM_ERR("Get string from fixup param failed!\n");
		return -1;
	}

	if (core_hash(&ret1, NULL, lock_pool_size) ==
		core_hash(&ret2, NULL, lock_pool_size)) {

		return 1;
	}

	return -1;
}

void destroy_script_locks(void)
{
	static_lock *lock_entry;

	/* Free all static locks  */
	while (static_locks) {

		lock_entry = static_locks;
		static_locks = static_locks->next;

		if (lock_entry->lock)
			lock_dealloc(lock_entry->lock);
		shm_free(lock_entry);
	}

	/* Free all dynamic locks  */
	if (dynamic_locks)
		lock_set_dealloc(dynamic_locks);
}

