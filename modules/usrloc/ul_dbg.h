/*
 * Usrloc struct debugging
 *
 * Copyright (C) 2018-2020 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#ifndef USRLOC_DBG__
#define USRLOC_DBG__

#ifndef EXTRA_DEBUG
#define print_ucontact(...)
#define print_urecord(...)
#define print_udomain(...)
#define print_all_udomains(...)
#else

/*! \brief
 * Print contact, for debugging purposes only
 */
static inline void print_ucontact(ucontact_t* _c)
{
	time_t t = time(0);
	char* st;

	switch(_c->state) {
	case CS_NEW:   st = "CS_NEW";     break;
	case CS_SYNC:  st = "CS_SYNC";    break;
	case CS_DIRTY: st = "CS_DIRTY";   break;
	default:       st = "CS_UNKNOWN"; break;
	}

	LM_GEN1(L_DBG, "~~~Contact(%p)~~~\n", _c);
	LM_GEN1(L_DBG, "domain    : '%.*s'\n", _c->domain->len, ZSW(_c->domain->s));
	LM_GEN1(L_DBG, "aor       : '%.*s'\n", _c->aor->len, ZSW(_c->aor->s));
	LM_GEN1(L_DBG, "Contact   : '%.*s'\n", _c->c.len, ZSW(_c->c.s));
	LM_GEN1(L_DBG, "Expires   : \n");
	if (_c->expires == 0) {
		LM_GEN1(L_DBG, "Permanent\n");
	} else if (_c->expires == UL_EXPIRED_TIME) {
		LM_GEN1(L_DBG, "Deleted\n");
	} else if (t > _c->expires) {
		LM_GEN1(L_DBG, "Expired\n");
	} else {
		LM_GEN1(L_DBG, "%u\n", (unsigned int)(_c->expires - t));
	}
	LM_GEN1(L_DBG, "q         : %s\n", q2str(_c->q, 0));
	LM_GEN1(L_DBG, "Call-ID   : '%.*s'\n", _c->callid.len, ZSW(_c->callid.s));
	LM_GEN1(L_DBG, "CSeq      : %d\n", _c->cseq);
	LM_GEN1(L_DBG, "User-Agent: '%.*s'\n",
		_c->user_agent.len, ZSW(_c->user_agent.s));
	LM_GEN1(L_DBG, "received  : '%.*s'\n",
		_c->received.len, ZSW(_c->received.s));
	LM_GEN1(L_DBG, "Path      : '%.*s'\n",
		_c->path.len, ZSW(_c->path.s));
	LM_GEN1(L_DBG, "State     : %s\n", st);
	LM_GEN1(L_DBG, "Flags     : %u\n", _c->flags);
	LM_GEN1(L_DBG, "Attrs     : '%.*s'\n", _c->attr.len, _c->attr.s);
	LM_GEN1(L_DBG, "Latency   : %d\n", _c->sipping_latency);

	if (_c->sock) {
		LM_GEN1(L_DBG, "Sock      : %.*s (as %.*s )(%p)\n",
				_c->sock->sock_str.len,_c->sock->sock_str.s,
				_c->sock->adv_sock_str.len,ZSW(_c->sock->adv_sock_str.s),
				_c->sock);
	} else {
		LM_GEN1(L_DBG, "Sock      : none (null)\n");
	}

	LM_GEN1(L_DBG, "Methods   : %u\n", _c->methods);
	LM_GEN1(L_DBG, "next      : %p\n", _c->next);
	LM_GEN1(L_DBG, "prev      : %p\n", _c->prev);
	LM_GEN1(L_DBG, "~~~/Contact~~~~\n");
}

/*! \brief
 * Print a record
 */
static inline void print_urecord(urecord_t* _r)
{
	ucontact_t* ptr;

	LM_GEN1(L_DBG, "...Record(%p)...\n", _r);
	LM_GEN1(L_DBG, "domain : '%.*s'\n", _r->domain->len, ZSW(_r->domain->s));
	LM_GEN1(L_DBG, "aor    : '%.*s'\n", _r->aor.len, ZSW(_r->aor.s));
	LM_GEN1(L_DBG, "aorhash: '%u'\n", (unsigned)_r->aorhash);
	LM_GEN1(L_DBG, "slot:    '%d'\n",
	        _r->slot ? _r->aorhash&(_r->slot->d->size-1) : -1);

	if (_r->contacts) {
		ptr = _r->contacts;
		while(ptr) {
			print_ucontact(ptr);
			ptr = ptr->next;
		}
	}

	LM_GEN1(L_DBG, ".../Record...\n");
}

/*! \brief
 * Just for debugging
 */
static inline void print_udomain(udomain_t* _d)
{
	int i;
	int max=0, slot=0, n=0,count;
	map_iterator_t it;
	LM_GEN1(L_DBG, "---Domain---\n");
	LM_GEN1(L_DBG, "name : '%.*s'\n", _d->name->len, ZSW(_d->name->s));
	LM_GEN1(L_DBG, "size : %d\n", _d->size);
	LM_GEN1(L_DBG, "table: %p\n", _d->table);
	/*LM_GEN1(L_DBG, "lock : %d\n", _d->lock); -- can be a structure --andrei*/
	LM_GEN1(L_DBG, "\n");
	for(i=0; i<_d->size; i++)
	{
		count = map_size( _d->table[i].records);
		n += count;
		if(max<count){
			max= count;
			slot = i;
		}

		for ( map_first( _d->table[i].records, &it);
			iterator_is_valid(&it);
			iterator_next(&it) )
			print_urecord((struct urecord *)*iterator_val(&it));
	}

	LM_GEN1(L_DBG, "\nMax slot: %d (%d/%d)\n", max, slot, n);
	LM_GEN1(L_DBG, "\n---/Domain---\n");
}

/*! \brief
 * Just for debugging
 */
static inline void print_all_udomains(void)
{
	dlist_t* ptr;

	ptr = root;

	LM_GEN1(L_DBG, "===Domain list===\n");
	while (ptr) {
		print_udomain(ptr->d);
		ptr = ptr->next;
	}
	LM_GEN1(L_DBG, "===/Domain list===\n");
}

#endif /* EXTRA_DEBUG */

#endif /* USRLOC_DBG__ */
