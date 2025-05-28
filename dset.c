/*
 * Copyright (C) 2001-2004 FhG FOKUS
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
 */

/*!
 * \file
 * \brief Destination set handling functions
 */


#include <string.h>
#include "dprint.h"
#include "config.h"
#include "parser/parser_f.h"
#include "parser/msg_parser.h"
#include "ut.h"
#include "hash_func.h"
#include "error.h"
#include "context.h"
#include "dset.h"
#include "mem/mem.h"
#include "ip_addr.h"
#include "usr_avp.h"

#define CONTACT "Contact: "
#define CONTACT_LEN (sizeof(CONTACT) - 1)

#define CONTACT_DELIM ", "
#define CONTACT_DELIM_LEN (sizeof(CONTACT_DELIM) - 1)

#define Q_PARAM ";q="
#define Q_PARAM_LEN (sizeof(Q_PARAM) - 1)

#define DSET_INCREMENT 4


/* This is an extension of the `msg_branch` struct, bringing the
 * buffers to hold the strings
 */
struct msg_branch_wrap
{
	struct msg_branch branch;

	char tag[MAX_URI_SIZE];

	char uri[MAX_URI_SIZE];

	char dst_uri[MAX_URI_SIZE];

	char path[MAX_PATH_SIZE];
};


struct dset_ctx
{
	int enabled;

	/*! how many of them we currently have */
	int nr_branches;

	/*!
	 * Where we store URIs of additional transaction branches
	 * (-1 because of the default branch, #0)
	 */
	struct msg_branch_wrap *branches;

	/*!
	 * this is the set of attrs (brnach avps) corresponding to the
	 * RURI branch (the 0-branch); we do not want to keep them into the
	 * SIP msg (due to cloning issues), so we store them here (anyhow
	 * the lifespan of this hook is short, only during request route)
	 */
	struct usr_avp *ruri_attrs;
};

static int dset_ctx_idx = -1;

#define get_dset_ctx() \
	(!current_processing_ctx ? NULL : (struct dset_ctx *) \
		context_get_ptr(CONTEXT_GLOBAL, current_processing_ctx, dset_ctx_idx))

#define store_dset_ctx(value) \
	(context_put_ptr( \
		CONTEXT_GLOBAL, current_processing_ctx, dset_ctx_idx, value))



int get_dset_size(void)
{
	struct dset_ctx *dsct = get_dset_ctx();

	return !dsct ? 0 : dsct->nr_branches;
}

/* empties/frees the content of a dset without free'ing the dset itself */
static inline void _empty_branches(struct dset_ctx *dsct)
{
	int i;

	for( i = 0 ; i < dsct->nr_branches ; i++ )
		destroy_avp_list( &dsct->branches[i].branch.attrs );
	pkg_free( dsct->branches );
	dsct->branches = NULL;
}

/*! Frees a destination set which used to be stored in the global context */
static void dset_destroy(void *dsct)
{
	/* emptry all branches */
	_empty_branches( (struct dset_ctx *)dsct );
	/* free attrs/avp for the RURI/0 branch */
	destroy_avp_list( &((struct dset_ctx *)dsct)->ruri_attrs );
	pkg_free( dsct );
}


int init_dset(void)
{
	dset_ctx_idx = context_register_ptr(CONTEXT_GLOBAL, dset_destroy);
	if (dset_ctx_idx < 0)
		return -1;

	return 0;
}


/*! \brief Disable/Enables parallel branch usage (read and write)
 */
void set_dset_state(unsigned char enable)
{
	struct dset_ctx *dsct = get_dset_ctx();
	static unsigned int bk_nr_branches;

	if (!dsct)
		return;

	if (enable) {
		/* enable dset usage */
		if (dsct->enabled) return; /* already enabled */
		/* enable read */
		dsct->nr_branches = bk_nr_branches;
		bk_nr_branches = 0;
		/* enable write */
		dsct->enabled = 1;
	} else {
		/* disable dset usage */
		if (!dsct->enabled) return; /* already disabled */
		/* disable read */
		bk_nr_branches = dsct->nr_branches;
		dsct->nr_branches = 0;
		/* disabel write */
		dsct->enabled = 0;
	}
}


/*! \brief Find the next brand from the destination set
 * \return Return the next branch from the dset
 * array, 0 is returned if there are no
 * more branches
 */
struct msg_branch* get_msg_branch(unsigned int idx)
{
	struct dset_ctx *dsct = get_dset_ctx();

	if (dsct && idx < dsct->nr_branches) {
		return &dsct->branches[idx].branch;
	} else {
		return NULL;
	}
}


/*! \brief
 * Empty the dset array
 */
void clear_dset(void)
{
	struct dset_ctx *dsct = get_dset_ctx();

	if (dsct) {
		_empty_branches( dsct );
		dsct->nr_branches = 0;
	}
}


/* copies and fills in a branch_wrap with the values from a msg_branch 
 * IMPORTANT: if any attrs are attached the `branch`, they will be moved
 * into the dset!!! */
static inline int _set_msg_branch(struct msg_branch_wrap *br, 
													struct msg_branch *branch)
{
	/* be sure and clear the attrs from target branch */
	destroy_avp_list( &br->branch.attrs );

	/* do full copy, copy the buffers later */
	br->branch = *branch;

	/* copy ruri */
	if (ZSTR(branch->uri) || branch->uri.len > MAX_URI_SIZE - 1) {
		LM_ERR("too long uri: [%.*s]/%d\n", branch->uri.len, branch->uri.s,
			branch->uri.len);
		return -1;
	}
	br->branch.uri.s = br->uri;
	memcpy( br->branch.uri.s, branch->uri.s, branch->uri.len);

	/* copy the dst_uri */
	if (!ZSTR(branch->dst_uri)) {
		if (branch->dst_uri.len > MAX_URI_SIZE - 1) {
			LM_ERR("too long dst_uri: [%.*s]/%d\n",
				branch->dst_uri.len, branch->dst_uri.s, branch->dst_uri.len);
			return -1;
		}
		br->branch.dst_uri.s = br->dst_uri;
		memcpy( br->branch.dst_uri.s, branch->dst_uri.s, branch->dst_uri.len);
	}

	/* copy the path string */
	if (!ZSTR(branch->path)) {
		if (branch->path.len > MAX_PATH_SIZE - 1) {
			LM_ERR("too long path: [%.*s]/%d\n",
				branch->path.len, branch->path.s, branch->path.len);
			return -1;
		}
		br->branch.path.s = br->path;
		memcpy( br->branch.path.s, branch->path.s, branch->path.len);
	}
	return 0;
}


static inline int _dst_malloc(struct dset_ctx **dsct)
{
	*dsct = pkg_malloc(sizeof **dsct);
	if (*dsct==NULL) {
		LM_ERR("oom 1\n");
		return E_OUT_OF_MEM;
	}
	memset(*dsct, 0, sizeof **dsct);
	(*dsct)->enabled = 1;
	store_dset_ctx(*dsct);
	return 0;
}

/* ! \brief
 * Add a new branch to current transaction
 */
int append_msg_branch(struct msg_branch *branch)
{
	int idx;
	struct msg_branch_wrap *new_br;
	struct dset_ctx *dsct = get_dset_ctx();

	if (dsct && !dsct->enabled)
		return -1;

	if (dsct==NULL &&  _dst_malloc(&dsct)<0 )
		return -1;

	idx = dsct->nr_branches;

	/* if we have already set up the maximum number
	 * of branches, don't try new ones
	 */
	if (idx == MAX_BRANCHES - 1) {
		LM_ERR("max nr of branches exceeded\n");
		ser_error = E_TOO_MANY_BRANCHES;
		return -1;
	}

	if (idx % DSET_INCREMENT == 0) {
		new_br = pkg_realloc(dsct->branches,
                      (idx + DSET_INCREMENT) * sizeof *dsct->branches);
		if (!new_br) {
			LM_ERR("oom 2\n");
			return E_OUT_OF_MEM;
		}
		memset((char *)new_br + idx * sizeof *new_br, 0,
				DSET_INCREMENT * sizeof *new_br);

		dsct->branches = new_br;
	}

	if (_set_msg_branch( dsct->branches + idx, branch)<0)
		return -1;

	dsct->nr_branches++;
	return 1;
}


/* ! \brief
 * Updates URI of an already appended branch
 */
int update_msg_branch_uri(unsigned int idx, str *val)
{
	struct dset_ctx *dsct = get_dset_ctx();
	struct msg_branch_wrap *br;

	if (!dsct || !dsct->enabled || idx >= dsct->nr_branches || ZSTRP(val))
		return -1;

	br = dsct->branches + idx;

	if (val->len > MAX_URI_SIZE - 1) {
		LM_ERR("too long uri: [%.*s]/%d\n", val->len, val->s, val->len);
		return -1;
	}
	br->branch.uri.s = br->uri; /* internal buffer */
	br->branch.uri.len = val->len;
	memcpy( br->branch.uri.s, val->s, val->len);

	return 0;
}


/* ! \brief
 * Updates DST_URI of an already appended branch
 */
int update_msg_branch_dst_uri(unsigned int idx, str *val)
{
	struct dset_ctx *dsct = get_dset_ctx();
	struct msg_branch_wrap *br;

	if (!dsct || !dsct->enabled || idx >= dsct->nr_branches)
		return -1;

	br = dsct->branches + idx;

	if (ZSTRP(val)) {
		br->branch.dst_uri.s = NULL;
		br->branch.dst_uri.len = 0;
	} else {
		if (val->len > MAX_URI_SIZE - 1) {
			LM_ERR("too long dst_uri: [%.*s]/%d\n", val->len, val->s,val->len);
			return -1;
		}
		br->branch.dst_uri.s = br->dst_uri; /* internal buffer */
		br->branch.dst_uri.len = val->len;
		memcpy( br->branch.dst_uri.s, val->s, val->len);
	}
	return 0;
}



/* ! \brief
 * Updates PATH of an already appended branch
 */
int update_msg_branch_path(unsigned int idx, str *val)
{
	struct dset_ctx *dsct = get_dset_ctx();
	struct msg_branch_wrap *br;

	if (!dsct || !dsct->enabled || idx >= dsct->nr_branches)
		return -1;

	br = dsct->branches + idx;

	if (ZSTRP(val)) {
		br->branch.path.s = NULL;
		br->branch.path.len = 0;
	} else {
		if (val->len > MAX_PATH_SIZE - 1) {
			LM_ERR("too long path: [%.*s]/%d\n", val->len, val->s,val->len);
			return -1;
		}
		br->branch.path.s = br->path; /* internal buffer */
		br->branch.path.len = val->len;
		memcpy( br->branch.path.s, val->s, val->len);
	}
	return 0;
}


/* ! \brief
 * Updates PATH of an already appended branch
 */
int update_msg_branch_q(unsigned int idx, int val)
{
	struct dset_ctx *dsct = get_dset_ctx();
	struct msg_branch_wrap *br;

	if (!dsct || !dsct->enabled || idx >= dsct->nr_branches)
		return -1;

	br = dsct->branches + idx;

	br->branch.q = val;
	return 0;
}


/* ! \brief
 * Updates SOCKET of an already appended branch
 */
int update_msg_branch_socket(unsigned int idx, const struct socket_info* val)
{
	struct dset_ctx *dsct = get_dset_ctx();
	struct msg_branch_wrap *br;

	if (!dsct || !dsct->enabled || idx >= dsct->nr_branches)
		return -1;

	br = dsct->branches + idx;

	br->branch.force_send_socket = val;
	return 0;
}


/* ! \brief
 * Updates SOCKET of an already appended branch
 */
int update_msg_branch_bflags(unsigned int idx, unsigned int val)
{
	struct dset_ctx *dsct = get_dset_ctx();
	struct msg_branch_wrap *br;

	if (!dsct || !dsct->enabled || idx >= dsct->nr_branches)
		return -1;

	br = dsct->branches + idx;

	br->branch.bflags = val;
	return 0;
}


#define _post_copy_branch_update(_br)             \
	do {                                          \
		(_br)->branch.uri.s = (_br)->uri;         \
		(_br)->branch.dst_uri.s = (_br)->dst_uri; \
		(_br)->branch.path.s = (_br)->path;       \
	} while(0)

/*! \brief
 * Removes a msg branch by index. The whole array gets shifted, so the
 * indexes inside may change
 */
int remove_msg_branch(unsigned int idx)
{
	struct dset_ctx *dsct = get_dset_ctx();
	int i;

	if (!dsct || !dsct->enabled || idx >= dsct->nr_branches)
		return -1;

	/* destroy any attrs the branch may have */
	destroy_avp_list( &dsct->branches[idx].branch.attrs );

	/* not last branch? */
	if (idx + 1 != dsct->nr_branches) {
		memmove( dsct->branches + idx, dsct->branches + idx + 1,
			(dsct->nr_branches - idx - 1) * sizeof *dsct->branches);
		/* update internal links */
		for ( i=idx ; i<dsct->nr_branches-1 ; i++)
			_post_copy_branch_update( dsct->branches+i );
	}

	dsct->nr_branches--;
	/* cleanup the slot not used anymore */
	memset(  dsct->branches + dsct->nr_branches, 0, sizeof *dsct->branches );

	return 0;
}


/*! \brief
 * Create a Contact header field from the dset
 * array
 */
char* print_dset(struct sip_msg* msg, int* len)
{
	int cnt, i, idx;
	unsigned int qlen;
	char* p, *qbuf;
	static char *dset = NULL;
	static unsigned int dset_len = 0;
	struct msg_branch *br;

	if (msg->new_uri.s) {
		cnt = 1;
		*len = msg->new_uri.len+2 /*for <>*/;
		if (get_ruri_q(msg) != Q_UNSPECIFIED) {
			*len += Q_PARAM_LEN + len_q(get_ruri_q(msg));
		}
	} else {
		cnt = 0;
		*len = 0;
	}

	for( idx=0 ; (br=get_msg_branch(idx))!=NULL ; idx++ ) {
		cnt++;
		*len += br->uri.len+2 /*for <>*/ ;
		if (br->q != Q_UNSPECIFIED) {
			*len += Q_PARAM_LEN + len_q(br->q);
		}
	}

	if (cnt == 0) return 0;

	*len += CONTACT_LEN + CRLF_LEN + (cnt - 1) * CONTACT_DELIM_LEN;

	/* does the current buffer fit the new dset ? */
	if (*len + 1 > dset_len) {
		/* need to resize */
		dset = pkg_realloc(dset, *len + 1);
		if (!dset) {
			dset_len = 0;
			LM_ERR("failed to allocate redirect buffer for %d bytes\n", *len + 1);
			return NULL;
		}
		dset_len = *len + 1;
	}

	memcpy(dset, CONTACT, CONTACT_LEN);
	p = dset + CONTACT_LEN;
	if (msg->new_uri.s) {
		*p++ = '<';
		memcpy(p, msg->new_uri.s, msg->new_uri.len);
		p += msg->new_uri.len;
		*p++ = '>';

		if (get_ruri_q(msg) != Q_UNSPECIFIED) {
			memcpy(p, Q_PARAM, Q_PARAM_LEN);
			p += Q_PARAM_LEN;

			qbuf = q2str(get_ruri_q(msg), &qlen);
			memcpy(p, qbuf, qlen);
			p += qlen;
		}
		i = 1;
	} else {
		i = 0;
	}

	for( idx=0 ; (br=get_msg_branch(idx))!=NULL ; idx++ ) {
		if (i) {
			memcpy(p, CONTACT_DELIM, CONTACT_DELIM_LEN);
			p += CONTACT_DELIM_LEN;
		}

		*p++ = '<';
		memcpy(p, br->uri.s, br->uri.len);
		p += br->uri.len;
		*p++ = '>';

		if (br->q != Q_UNSPECIFIED) {
			memcpy(p, Q_PARAM, Q_PARAM_LEN);
			p += Q_PARAM_LEN;

			qbuf = q2str(br->q, &qlen);
			memcpy(p, qbuf, qlen);
			p += qlen;
		}
		i++;
	}

	memcpy(p, CRLF " ", CRLF_LEN + 1);
	return dset;
}


/*! \brief moves the uri to destination for all branches and
 * all uris are set to given uri */
int msg_branch_uri2dset( str *new_uri )
{
	struct dset_ctx *dsct = get_dset_ctx();
	struct msg_branch *branch;
	unsigned int b;

	/* no branches have been added yet */
	if (!dsct)
		return 0;

	if (new_uri->len+1 > MAX_URI_SIZE) {
		LM_ERR("new uri too long (%d)\n",new_uri->len);
		return -1;
	}

	for (b = 0; b < dsct->nr_branches; b++) {
		branch = &(dsct->branches[b].branch);
		/* move uri to dst */
		memcpy(branch->dst_uri.s, branch->uri.s, branch->uri.len + 1);
		branch->dst_uri.len = branch->uri.len;
		/* set new uri */
		memcpy(branch->uri.s, new_uri->s, new_uri->len);
		branch->uri.len =  new_uri->len;
		branch->uri.s[new_uri->len] = '\0';
	}

	return 0;
}


static inline int _branch_2_msg(struct dset_ctx *dsct,
							struct msg_branch_wrap *br,struct sip_msg *msg)
{
	if (set_ruri( msg, &br->branch.uri))
		return -1;

	if (set_dst_uri( msg, &br->branch.dst_uri))
		return -1;

	if (set_path_vector( msg, &br->branch.path))
		return -1;

	msg->ruri_q = br->branch.q;
	msg->force_send_socket = br->branch.force_send_socket;
	msg->ruri_bflags = br->branch.bflags;

	destroy_avp_list( &dsct->ruri_attrs );
	dsct->ruri_attrs = clone_avp_list(br->branch.attrs);

	return 0;
}


static inline int _msg_2_branch(struct dset_ctx *dsct,
							struct sip_msg *msg, struct msg_branch_wrap *br)
{
	struct msg_branch branch;

	/* run tests first */
	memset( &branch, 0, sizeof branch);
	branch.uri = *GET_RURI(msg);
	branch.dst_uri = msg->dst_uri;
	branch.path = msg->path_vec;
	branch.q = msg->ruri_q;
	branch.force_send_socket = msg->force_send_socket;
	branch.bflags = msg->ruri_bflags;
	branch.attrs = clone_avp_list(dsct->ruri_attrs);
	/* the cloned list ^^ will remain attached to the branch */

	if (_set_msg_branch( br, &branch)<0)
		return -1;

	return 0;
}


static inline int _copy_branch(struct sip_msg *msg, struct dset_ctx *dsct,
													int src_idx, int dst_idx)
{
	struct msg_branch_wrap *brs = dsct->branches;
	int ret = 0;

	if (dst_idx>=0) {
		/* we copy into a branch */
		if (src_idx>=0) {
			/* we copy from a branch */
			/* destroy the avps of the dst branch before the bulk copy */
			destroy_avp_list( &brs[dst_idx].branch.attrs );
			/* do the copy */
			brs[dst_idx] = brs[src_idx];
			_post_copy_branch_update( brs+dst_idx );
			/* clone the list of attrs from src to dst now */
			brs[dst_idx].branch.attrs =
				clone_avp_list( brs[src_idx].branch.attrs );
		} else {
			/* we copy from msg */
			ret = _msg_2_branch( dsct, msg, &brs[dst_idx]);
		}
	} else {
		/* we copy into msg */
		if (src_idx>=0) {
			/* we copy from a branch */
			ret = _branch_2_msg( dsct, &brs[src_idx], msg);
		} else {
			/* this should not happen, it is a NOP */
		}
	}

	return ret;
}


int move_msg_branch_to_ruri(int idx, struct sip_msg *msg)
{
	struct dset_ctx *dsct = get_dset_ctx();

	/* no branches have been added yet */
	if (!dsct) {
		LM_DBG("no branches found\n");
		return -1;
	}

	if (idx >= dsct->nr_branches) {
		LM_DBG("trying to move inexisting branch idx %d, out of %d\n",
			idx, dsct->nr_branches);
		return -1;
	}

	if (_branch_2_msg( dsct, &dsct->branches[idx], msg)!=0) {
		LM_ERR("failed to move brnach to RURI\n");
		return -1;
	}

	return 0;
}


int swap_msg_branches(struct sip_msg *msg, int src_idx, int dst_idx)
{
	struct dset_ctx *dsct = get_dset_ctx();
	struct msg_branch_wrap *brs;
	struct msg_branch_wrap bk;
	struct usr_avp *bk_attrs;

	if (src_idx==dst_idx)
		/* this is a NOP */
		return 0;

	/* no branches have been added yet */
	if (!dsct)
		return -1;

	if ( (src_idx>0 && src_idx>=dsct->nr_branches)
	|| (dst_idx>0 && dst_idx>=dsct->nr_branches) ) {
		LM_ERR("overflow in src [%d] or dst [%d] indexes (having %d)\n",
			src_idx, dst_idx, dsct->nr_branches);
		return -1;
	}

	brs = dsct->branches;

	/* to avoid useless cloning of the attr lists, better detach them
	 * before doing anything and swap them at the end */

	/* backup the info from dst branch, so we can write into it */
	if (dst_idx>=0) {
		/* detach the attrs */
		bk_attrs = brs[dst_idx].branch.attrs;
		brs[dst_idx].branch.attrs = NULL;
		/* backup the dst branch */
		bk = brs[dst_idx];
		_post_copy_branch_update( &bk );
	} else {
		/* detach the attrs */
		bk_attrs = dsct->ruri_attrs;
		dsct->ruri_attrs = NULL;
		/* backup the msg branch */
		if (_msg_2_branch(dsct, msg, &bk)<0)
			return -1;
	}

	/* copy dst over src */
	if (_copy_branch( msg, dsct, src_idx, dst_idx)<0)
		return -1;

	/* now copy the original dst (from bk) into src */
	if (src_idx>=0) {
		/* copy bk into a branch */
		brs[src_idx] = bk;
		_post_copy_branch_update( brs+src_idx );
		/* attach the dst list of attrs */
		brs[src_idx].branch.attrs = bk_attrs;
	} else {
		/* copy bk in msg */
		if (_branch_2_msg( dsct, &bk, msg)<0)
			return -1; //we may have an inconsistent msg branch :(
		/* attach the dst list of attrs */
		dsct->ruri_attrs = bk_attrs;
	}

	return 0;
}


int move_msg_branch(struct sip_msg *msg, int src_idx, int dst_idx,
															int keep_src)
{
	struct dset_ctx *dsct = get_dset_ctx();

	if (src_idx==dst_idx)
		/* this is a NOP */
		return 0;

	/* no branches have been added yet */
	if (!dsct)
		return -1;

	if ( (src_idx>0 && src_idx>=dsct->nr_branches)
	|| (dst_idx>0 && dst_idx>=dsct->nr_branches) ) {
		LM_ERR("overflow in src [%d] or dst [%d] indexes (having %d)\n",
			src_idx, dst_idx, dsct->nr_branches);
		return -1;
	}

	/* copy dst over src */
	if (_copy_branch( msg, dsct, src_idx, dst_idx)<0)
		return -1;

	if (!keep_src && src_idx>0)
		remove_msg_branch(src_idx);

	return 0;
}


/**** Functions to work with the members ****/

static inline unsigned int* get_ptr_bflags(struct sip_msg *msg,
														unsigned int b_idx)
{
	struct dset_ctx *dsct = get_dset_ctx();

	if (!dsct && b_idx != 0)
		return NULL;

	if (b_idx == 0) {
		return &getb0flags(msg);
	} else {
		if (b_idx - 1 < dsct->nr_branches) {
			return &dsct->branches[b_idx - 1].branch.bflags;
		} else {
			return 0;
		}
	}
}

int setbflag(struct sip_msg *msg, unsigned int b_idx, unsigned int mask)
{
	unsigned int *flags;

	flags = get_ptr_bflags( msg, b_idx );
#ifdef EXTRA_DEBUG
	LM_DBG("bflags for %p : (%u, %u)\n", msg, mask, *flags);
#endif
	if (flags==0)
		return -1;

	(*flags) |= mask;
	return 1;
}


/*! \brief
 * Tests the per branch flags
 */
int isbflagset(struct sip_msg *msg, unsigned int b_idx, unsigned int mask)
{
	unsigned int *flags;

	flags = get_ptr_bflags( msg, b_idx );
#ifdef EXTRA_DEBUG
	LM_DBG("bflags for %p : (%u, %u)\n", msg, mask, *flags);
#endif
	if (flags==0)
		return -1;

	return ( (*flags) & mask) ? 1 : -1;
}


/*! \brief
 * Resets the per branch flags
 */
int resetbflag(struct sip_msg *msg, unsigned int b_idx, unsigned int mask)
{
	unsigned int *flags;

	flags = get_ptr_bflags( msg, b_idx );
#ifdef EXTRA_DEBUG
	LM_DBG("bflags for %p : (%u, %u)\n", msg, mask, *flags);
#endif
	if (flags==0)
		return -1;

	(*flags) &= ~mask;
	return 1;
}


int get_msg_branch_attr(unsigned int b_idx, int name_id,
									unsigned short *flags, int_str *val)
{
	struct dset_ctx *dsct = get_dset_ctx();
	struct usr_avp **attrs;
	struct usr_avp *avp;
	struct usr_avp** old_list;

	if (!dsct)
		return -1;

	if (b_idx==0)
		attrs = &(dsct->ruri_attrs);
	else if (b_idx-1 < get_dset_size())
		attrs = &dsct->branches[b_idx - 1].branch.attrs;
	else {
		LM_DBG("index %d out of rante (available branches %d)\n",
			b_idx, get_dset_size() );
		return -1;
	}

	LM_DBG("getting attr [%d] on branch %d/ptr=%p\n",name_id, b_idx, attrs);

	/* operate on the list of ATTRS/AVPS of the branch */
	old_list = set_avp_list( attrs );

	avp = search_first_avp(0, name_id, val, 0);

	set_avp_list( old_list );

	if (avp)
		*flags = avp->flags;
	else
		*flags = AVP_VAL_NULL;

	return avp ? 1 : -1 ;
}


int set_msg_branch_attr(unsigned int b_idx, int name_id,
										unsigned short flags, int_str val)
{
	struct dset_ctx *dsct = get_dset_ctx();
	struct usr_avp **attrs;
	struct usr_avp *avp;
	struct usr_avp** old_list;

	/* if we have to set an ATTR for RURI branch, we need to have the dset
	 * allocated (as the attr holder is there) */
	if (dsct==NULL && (b_idx!=0 || (b_idx==0 && _dst_malloc(&dsct)<0)) )
		return -1;

	if (b_idx==0)
		attrs = &(dsct->ruri_attrs);
	else if (b_idx-1 < get_dset_size())
		attrs = &dsct->branches[b_idx - 1].branch.attrs;
	else {
		LM_DBG("index %d out of rante (available branches %d)\n",
			b_idx, get_dset_size() );
		return -1;
	}

	LM_DBG("setting attr [%d] on branch %d/ptr=%p\n",name_id, b_idx, attrs);

	/* operate on the list of ATTRS/AVPS of the branch */
	old_list = set_avp_list( attrs );

	if ( (avp=search_first_avp( 0, name_id, NULL, 0))!=NULL )
		destroy_avp(avp);

	if ( !(flags&AVP_VAL_NULL) )
		add_avp( flags, name_id, val);

	set_avp_list( old_list );

	return 1;
}


struct usr_avp **ruri_branch_attrs_head(void)
{
	struct dset_ctx *dsct = get_dset_ctx();

	if (!dsct)
		return NULL;

	return &dsct->ruri_attrs;
}
