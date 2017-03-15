/*
 * Header file for USRLOC MI functions
 *
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
 * ---------
 *
 * 2006-12-01  created (bogdan)
 */

/*! \file
 *  \brief USRLOC - Usrloc MI functions
 *  \ingroup usrloc
 */

#include <string.h>
#include <stdio.h>
#include "../../mi/mi.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../qvalue.h"
#include "../../ip_addr.h"
#include "../../rw_locking.h"
#include "ul_mi.h"
#include "dlist.h"
#include "udomain.h"
#include "utime.h"
#include "ul_mod.h"
#include "usrloc.h"



#define MI_UL_CSEQ 1
static str mi_ul_cid = str_init("dfjrewr12386fd6-343@opensips.mi");
static str mi_ul_ua  = str_init("OpenSIPS MI Server");
rw_lock_t *sync_lock = 0;




/************************ helper functions ****************************/

static inline udomain_t* mi_find_domain(str* table)
{
	dlist_t* dom;

	for( dom=root ; dom ; dom=dom->next ) {
		if ((dom->name.len == table->len) &&
		!memcmp(dom->name.s, table->s, table->len))
			return dom->d;
	}
	return 0;
}

static inline int mi_fix_aor(str *aor)
{
	char *p;

	p = memchr( aor->s, '@', aor->len);
	if (use_domain) {
		if (p==NULL)
			return -1;
	} else {
		if (p)
			aor->len = p - aor->s;
	}

	return 0;
}



static inline int mi_add_aor_node(struct mi_node *parent, urecord_t* r,
													time_t t, int short_dump)
{
	struct mi_node *anode;
	struct mi_node *cnode;
	struct mi_node *node;
	struct mi_attr *attr;
	ucontact_t* c;
	str st;
	char *p;
	int len;

	anode = add_mi_node_child( parent, MI_IS_ARRAY|MI_DUP_VALUE, "AOR", 3,
			r->aor.s, r->aor.len);
	if (anode==0)
		return -1;

	if (short_dump)
		return 0;

	for( c=r->contacts ; c ; c=c->next) {
		/* contact */
		cnode = add_mi_node_child( anode, MI_DUP_VALUE, "Contact", 7,
			c->c.s, c->c.len);
		if (cnode==0)
			return -1;

		/* contact ID */
		node = addf_mi_node_child( cnode, 0, "ContactID", 9,
			"%llu", c->contact_id);
		if (node==0)
			return -1;

		/* expires */
		if (c->expires == 0) {
			node = add_mi_node_child( cnode, 0, "Expires", 7, "permanent", 9);
		} else if (c->expires == UL_EXPIRED_TIME) {
			node = add_mi_node_child( cnode, 0, "Expires", 7, "deleted", 7);
		} else if (t > c->expires) {
			node = add_mi_node_child( cnode, 0, "Expires", 7, "expired", 7);
		} else {
			p = int2str((unsigned long)(c->expires - t), &len);
			node = add_mi_node_child( cnode, MI_DUP_VALUE, "Expires", 7,p,len);
		}
		if (node==0)
			return -1;

		/* q */
		p = q2str(c->q, (unsigned int*)&len);
		attr = add_mi_attr( cnode, MI_DUP_VALUE, "Q", 1, p, len);
		if (attr==0)
			return -1;

		/* callid */
		node = add_mi_node_child( cnode, MI_DUP_VALUE, "Callid", 6,
			c->callid.s, c->callid.len);
		if (node==0)
			return -1;

		/* cseq */
		p = int2str((unsigned long)c->cseq, &len);
		node = add_mi_node_child( cnode, MI_DUP_VALUE, "Cseq", 4, p, len);
		if (node==0)
			return -1;

		/* User-Agent */
		if (c->user_agent.len) {
			node = add_mi_node_child( cnode, MI_DUP_VALUE, "User-agent", 10,
				c->user_agent.s, c->user_agent.len);
			if (node==0)
				return -1;
		}

		/* received */
		if (c->received.len) {
			node = add_mi_node_child( cnode, MI_DUP_VALUE, "Received", 8,
				c->received.s, c->received.len);
			if (node==0)
				return -1;
		}

		/* path */
		if (c->path.len) {
			node = add_mi_node_child( cnode, MI_DUP_VALUE, "Path", 4,
				c->path.s, c->path.len);
			if (node==0)
				return -1;
		}

		/* state */
		if (c->state == CS_NEW) {
			node = add_mi_node_child( cnode, 0, "State", 5, "CS_NEW", 6);
		} else if (c->state == CS_SYNC) {
			node = add_mi_node_child( cnode, 0, "State", 5, "CS_SYNC", 7);
		} else if (c->state== CS_DIRTY) {
			node = add_mi_node_child( cnode, 0, "State", 5, "CS_DIRTY", 8);
		} else {
			node = add_mi_node_child( cnode, 0, "State", 5, "CS_UNKNOWN", 10);
		}
		if (node==0)
			return -1;

		/* flags */
		p = int2str((unsigned long)c->flags, &len);
		node = add_mi_node_child( cnode, MI_DUP_VALUE, "Flags", 5, p, len);
		if (node==0)
			return -1;

		/* cflags */
		st = bitmask_to_flag_list(FLAG_TYPE_BRANCH, c->cflags);
		node = add_mi_node_child( cnode, MI_DUP_VALUE, "Cflags", 6, st.s, st.len);
		if (node==0)
			return -1;

		/* socket */
		if (c->sock) {
			if(c->sock->adv_sock_str.len) {
				node = add_mi_node_child( cnode, 0, "Socket", 6,
					c->sock->adv_sock_str.s, c->sock->adv_sock_str.len);
			} else {
				node = add_mi_node_child( cnode, 0, "Socket", 6,
					c->sock->sock_str.s, c->sock->sock_str.len);
			}
			if (node==0)
				return -1;
		}

		/* methods */
		p = int2str((unsigned long)c->methods, &len);
		node = add_mi_node_child( cnode, MI_DUP_VALUE, "Methods", 7, p, len);
		if (node==0)
			return -1;

		/* additional information */
		if (c->attr.len) {
			node = add_mi_node_child( cnode, MI_DUP_VALUE, "Attr", 4,
				c->attr.s, c->attr.len);
			if (node==0)
				return -1;
		}

		/* sip_instance */
		if (c->instance.len && c->instance.s) {
			node = add_mi_node_child( cnode, MI_DUP_VALUE, "SIP_instance", 12,
				c->instance.s, c->instance.len);
			if (node==0)
				return -1;
		}

	} /* for */

	return 0;
}




/*************************** MI functions *****************************/

/*! \brief
 * Expects 2 nodes: the table name and the AOR
 */
struct mi_root* mi_usrloc_rm_aor(struct mi_root *cmd, void *param)
{
	struct mi_node *node;
	udomain_t *dom;
	str *aor;

	node = cmd->node.kids;
	if (node==NULL || node->next==NULL || node->next->next!=NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	/* look for table */
	dom = mi_find_domain( &node->value );
	if (dom==NULL)
		return init_mi_tree( 404, "Table not found", 15);

	/* process the aor */
	aor = &node->next->value;
	if ( mi_fix_aor(aor)!=0 )
		return init_mi_tree( 400, "Domain missing in AOR", 21);

	lock_udomain( dom, aor);
	if (delete_urecord( dom, aor, NULL, 0) < 0) {
		unlock_udomain( dom, aor);
		return init_mi_tree( 500, "Failed to delete AOR", 20);
	}

	unlock_udomain( dom, aor);
	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
}


/*! \brief
 * Expects 3 nodes: the table name, the AOR and contact
 */
struct mi_root* mi_usrloc_rm_contact(struct mi_root *cmd, void *param)
{
	struct mi_node *node;
	udomain_t *dom;
	urecord_t *rec;
	ucontact_t* con;
	str *aor;
	str *contact;
	int ret;

	node = cmd->node.kids;
	if (node==NULL || node->next==NULL || node->next->next==NULL ||
	node->next->next->next!=NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	/* look for table */
	dom = mi_find_domain( &node->value );
	if (dom==NULL)
		return init_mi_tree( 404, "Table not found", 15);

	/* process the aor */
	aor = &node->next->value;
	if ( mi_fix_aor(aor)!=0 )
		return init_mi_tree( 400, "Domain missing in AOR", 21);

	lock_udomain( dom, aor);

	ret = get_urecord( dom, aor, &rec);
	if (ret == 1) {
		unlock_udomain( dom, aor);
		return init_mi_tree( 404, "AOR not found", 13);
	}

	contact = &node->next->next->value;
	ret = get_simple_ucontact( rec, contact, &con);
	if (ret < 0) {
		unlock_udomain( dom, aor);
		return 0;
	}
	if (ret > 0) {
		unlock_udomain( dom, aor);
		return init_mi_tree( 404, "Contact not found", 17);
	}

	if (delete_ucontact(rec, con, 0) < 0) {
		unlock_udomain( dom, aor);
		return 0;
	}

	release_urecord(rec, 0);
	unlock_udomain( dom, aor);
	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
}


struct mi_root* mi_usrloc_dump(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *rpl;
	struct mi_node *node;
	struct mi_attr *attr;
	struct urecord* r;
	dlist_t* dl;
	udomain_t* dom;
	time_t t;
	char *p;
	int len;
	int n;
	int i;
	int short_dump;
	map_iterator_t it;
	void ** dest;

	node = cmd->node.kids;
	if (node && node->next)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (node && node->value.len==5 && !strncasecmp(node->value.s, "brief", 5)){
		/* short version */
		short_dump = 1;
	} else {
		short_dump = 0;
	}

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==NULL)
		return 0;
	rpl = &rpl_tree->node;
	/* all domains go under this node as array */
	rpl->flags |= MI_IS_ARRAY;
	t = time(0);

	for( dl=root ; dl ; dl=dl->next ) {
		/* add a domain node */
		node = add_mi_node_child( rpl, MI_IS_ARRAY|MI_NOT_COMPLETED,
					"Domain", 6, dl->name.s, dl->name.len);
		if (node==0)
			goto error;

		dom = dl->d;
		/* add some attributes to the domain node */
		p= int2str((unsigned long)dom->size, &len);
		attr = add_mi_attr( node, MI_DUP_VALUE, "table", 5, p, len);
		if (attr==0)
			goto error;

		/* add the entries per hash */
		for(i=0,n=0; i<dom->size; i++) {
			lock_ulslot( dom, i);


			for ( map_first( dom->table[i].records, &it);
				iterator_is_valid(&it);
				iterator_next(&it) ) {

				dest = iterator_val(&it);
				if( dest == NULL )
					goto error_unlock;
				r =( urecord_t * ) *dest;


				/* add entry */
				if (mi_add_aor_node( node, r, t, short_dump)!=0)
					goto error_unlock;
				n++;
				/* at each 50 AORs, flush the tree */
				if ( (n % 50) == 0 )
					flush_mi_tree(rpl_tree);
			}

			unlock_ulslot( dom, i);
		}

		/* add more attributes to the domain node */
		p= int2str((unsigned long)n, &len);
		attr = add_mi_attr( node, MI_DUP_VALUE, "records", 7, p, len);
		if (attr==0)
			goto error;

	}

	return rpl_tree;

error_unlock:
	unlock_ulslot( dom, i);
error:
	free_mi_tree(rpl_tree);
	return 0;
}


struct mi_root* mi_usrloc_flush(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==NULL)
		return 0;

	synchronize_all_udomains();
	return rpl_tree;
}


/*! \brief
 * Expects 7 nodes:
 *        table name,
 *        AOR
 *        contact
 *        expires
 *        Q
 *        useless - backward compat.
 *        flags
 *        cflags
 *        methods
 */
struct mi_root* mi_usrloc_add(struct mi_root *cmd, void *param)
{
	ucontact_info_t ci;
	urecord_t* r;
	ucontact_t* c;
	struct mi_node *node;
	udomain_t *dom;
	str *aor;
	str *contact;
	unsigned int ui_val;
	int n;

	for( n=0,node = cmd->node.kids; n<9 && node ; n++,node=node->next );
	if (n!=9 || node!=0)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	node = cmd->node.kids;

	/* look for table (param 1) */
	dom = mi_find_domain( &node->value );
	if (dom==NULL)
		return init_mi_tree( 404, "Table not found", 15);

	/* process the aor (param 2) */
	node = node->next;
	aor = &node->value;
	if ( mi_fix_aor(aor)!=0 )
		return init_mi_tree( 400, "Domain missing in AOR", 21);

	/* contact (param 3) */
	node = node->next;
	contact = &node->value;

	memset( &ci, 0, sizeof(ucontact_info_t));

	/* expire (param 4) */
	node = node->next;
	if (str2int( &node->value, &ui_val) < 0)
		goto bad_syntax;
	ci.expires = ui_val;

	/* q value (param 5) */
	node = node->next;
	if (str2q( &ci.q, node->value.s, node->value.len) < 0)
		goto bad_syntax;

	/* unused value (param 6) FIXME */
	node = node->next;

	/* flags value (param 7) */
	node = node->next;
	if (str2int( &node->value, (unsigned int*)&ci.flags) < 0)
		goto bad_syntax;

	/* branch flags value (param 8) */
	node = node->next;
	if (str2int( &node->value, (unsigned int*)&ci.cflags) < 0)
		goto bad_syntax;

	/* methods value (param 9) */
	node = node->next;
	if (str2int( &node->value, (unsigned int*)&ci.methods) < 0)
		goto bad_syntax;

	lock_udomain( dom, aor);

	n = get_urecord( dom, aor, &r);
	if ( n==1) {
		if (insert_urecord( dom, aor, &r, 0) < 0)
			goto lock_error;

		c = 0;
	} else {
		if (get_simple_ucontact( r, contact, &c) < 0)
			goto lock_error;
	}

	get_act_time();

	ci.user_agent = &mi_ul_ua;
	/* 0 expires means permanent contact */
	if (ci.expires!=0)
		ci.expires += act_time;

	if (c) {
		/* update contact record */
		ci.callid = &mi_ul_cid;
		ci.cseq = c->cseq;
		if (update_ucontact( r, c, &ci, 0) < 0)
			goto release_error;
	} else {
		/* new contact record */
		ci.callid = &mi_ul_cid;
		ci.cseq = MI_UL_CSEQ;
		if ( insert_ucontact( r, contact, &ci, &c, 0) < 0 )
			goto release_error;
	}

	release_urecord(r, 0);

	unlock_udomain( dom, aor);

	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
bad_syntax:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
release_error:
	release_urecord(r, 0);
lock_error:
	unlock_udomain( dom, aor);
	return init_mi_tree( 500, MI_INTERNAL_ERR_S, MI_INTERNAL_ERR_LEN);
}


/*! \brief
 * Expects 2 nodes: the table name and the AOR
 */
struct mi_root* mi_usrloc_show_contact(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *rpl;
	struct mi_node *node;
	udomain_t *dom;
	urecord_t *rec;
	str *aor;
	int ret;
	time_t t;

	node = cmd->node.kids;
	if (node==NULL || node->next==NULL || node->next->next!=NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	/* look for table */
	dom = mi_find_domain( &node->value );
	if (dom==NULL)
		return init_mi_tree( 404, "Table not found", 15);

	/* process the aor */
	aor = &node->next->value;
	if ( mi_fix_aor(aor)!=0 )
		return init_mi_tree( 400, "Domain missing in AOR", 21);

	t = time(0);

	lock_udomain( dom, aor);

	ret = get_urecord( dom, aor, &rec);
	if (ret == 1) {
		unlock_udomain( dom, aor);
		return init_mi_tree( 404, "AOR not found", 13);
	}

	get_act_time();

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==0)
		goto error;

	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;

	if (mi_add_aor_node(rpl, rec, t, 0)!=0)
		goto error;

	unlock_udomain( dom, aor);

	if (rpl_tree==0)
		return init_mi_tree( 404 , "AOR has no contacts", 18);

	return rpl_tree;
error:
	if (rpl_tree)
		free_mi_tree( rpl_tree );
	unlock_udomain( dom, aor);
	return 0;
}

static int mi_process_sync(void *param, str key, void *value)
{
	struct ucontact* c;
	struct urecord* rec = (struct urecord *)value;

	if (!rec) {
		LM_ERR("invalid record value for key '%.*s'\n", key.len, key.s);
		return -1;
	}

	for (c = rec->contacts; c; c = c->next) {
		c->state = CS_NEW;
	}
	return 0;
}

static struct mi_root * mi_sync_domain(udomain_t *dom)
{
	int i;
	static db_ps_t my_ps = NULL;

	/* delete whole table */
	if (ul_dbf.use_table(ul_dbh, dom->name) < 0) {
		LM_ERR("use_table failed\n");
		return 0;
	}

	CON_PS_REFERENCE(ul_dbh) = &my_ps;

	if (ul_dbf.delete(ul_dbh, 0, 0, 0, 0) < 0) {
		LM_ERR("failed to delete from database\n");
		return 0;
	}

	for(i=0; i < dom->size; i++) {
		lock_ulslot(dom, i);

		if (map_for_each(dom->table[i].records, mi_process_sync, 0)) {
			LM_ERR("cannot process sync\n");
			goto error;
		}

		unlock_ulslot(dom, i);
	}
	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
error:
	unlock_ulslot(dom, i);
	return 0;
}

static struct mi_root* mi_sync_aor(udomain_t *dom, str *aor)
{
	urecord_t *rec;

	lock_udomain( dom, aor);
	if (get_urecord( dom, aor, &rec) == 1) {
		unlock_udomain( dom, aor);
		return init_mi_tree( 404, "AOR not found", 13);
	}

	if (db_delete_urecord(rec) < 0) {
		LM_ERR("DB delete failed\n");
		goto error;
	}

	if (mi_process_sync(dom, *aor, rec))
		goto error;

	unlock_udomain( dom, aor);
	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
error:
	unlock_udomain( dom, aor);
	return 0;
}

/*! \brief
 * Expects the table name
 */
struct mi_root* mi_usrloc_sync(struct mi_root *cmd, void *param)
{
	struct mi_node *node;
	udomain_t *dom;

	if (db_mode == DB_ONLY || db_mode == NO_DB)
		return init_mi_tree( 200, MI_SSTR("Contacts already synced"));

	node = cmd->node.kids;
	if (!node)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	/* look for table */
	dom = mi_find_domain( &node->value );
	if (dom==NULL)
		return init_mi_tree( 404, MI_SSTR("Table not found"));

	node = node->next;
	if (node) {
		if (node->next)
			return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);
		return mi_sync_aor(dom, &node->value);
	} else {
		struct mi_root *ret;
		if (sync_lock)
			lock_start_write(sync_lock);
		ret = mi_sync_domain(dom);
		if (sync_lock)
			lock_stop_write(sync_lock);
		return ret;
	}
}
