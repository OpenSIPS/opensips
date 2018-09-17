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

#define CONTACT "Contact: "
#define CONTACT_LEN (sizeof(CONTACT) - 1)

#define CONTACT_DELIM ", "
#define CONTACT_DELIM_LEN (sizeof(CONTACT_DELIM) - 1)

#define Q_PARAM ";q="
#define Q_PARAM_LEN (sizeof(Q_PARAM) - 1)

#define DSET_INCREMENT 4

struct branch
{
	char uri[MAX_URI_SIZE];
	unsigned int len;

	/* Real destination of the request */
	char dst_uri[MAX_URI_SIZE];
	unsigned int dst_uri_len;

	/* Path vector of the request */
	char path[MAX_PATH_SIZE];
	unsigned int path_len;

	int q; /* Preference of the contact among contact within the array */
	struct socket_info* force_send_socket;
	unsigned int flags;
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
	struct branch *branches;
};

static int dset_ctx_idx = -1;

#define get_dset_ctx() \
	(!current_processing_ctx ? NULL : (struct dset_ctx *) \
		context_get_ptr(CONTEXT_GLOBAL, current_processing_ctx, dset_ctx_idx))

int get_nr_branches(void)
{
	struct dset_ctx *dsct = get_dset_ctx();

	return !dsct ? 0 : dsct->nr_branches;
}

#define store_dset_ctx(value) \
	(context_put_ptr( \
		CONTEXT_GLOBAL, current_processing_ctx, dset_ctx_idx, value))

/*! Frees a destination set which used to be stored in the global context */
static void dset_destroy(void *dsct)
{
	pkg_free(((struct dset_ctx *)dsct)->branches);
	pkg_free(dsct);
}

int init_dset(void)
{
	dset_ctx_idx = context_register_ptr(CONTEXT_GLOBAL, dset_destroy);
	if (dset_ctx_idx < 0)
		return -1;

	return 0;
}

static inline unsigned int* get_ptr_bflags(struct sip_msg *msg, unsigned int b_idx)
{
	struct dset_ctx *dsct = get_dset_ctx();

	if (!dsct && b_idx != 0)
		return NULL;

	if (b_idx == 0) {
		return &getb0flags(msg);
	} else {
		if (b_idx - 1 < dsct->nr_branches) {
			return &dsct->branches[b_idx - 1].flags;
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
char* get_branch(unsigned int idx, int* len, qvalue_t* q, str* dst_uri,
		str* path, unsigned int *flags, struct socket_info** force_socket)
{
	struct dset_ctx *dsct = get_dset_ctx();
	struct branch *branches;

	if (dsct && idx < dsct->nr_branches) {
		branches = dsct->branches;
		*len = branches[idx].len;
		*q = branches[idx].q;

		if (dst_uri) {
			dst_uri->len = branches[idx].dst_uri_len;
			dst_uri->s = (dst_uri->len)?branches[idx].dst_uri : NULL;
		}
		if (path) {
			path->len = branches[idx].path_len;
			path->s = (path->len)?branches[idx].path : NULL;
		}
		if (force_socket)
			*force_socket = branches[idx].force_send_socket;
		if (flags)
			*flags = branches[idx].flags;
		return branches[idx].uri;
	} else {
		*len = 0;
		*q = Q_UNSPECIFIED;
		if (dst_uri) {
			dst_uri->s = NULL;
			dst_uri->len = 0;
		}
		if (force_socket)
			*force_socket = NULL;
		if (flags)
			*flags = 0;
		return NULL;
	}
}


/*! \brief
 * Empty the dset array
 */
void clear_branches(void)
{
	struct dset_ctx *dsct = get_dset_ctx();

	if (dsct)
		dsct->nr_branches = 0;
}


/* ! \brief
 * Add a new branch to current transaction
 */
int append_branch(struct sip_msg* msg, str* uri, str* dst_uri, str* path,
		qvalue_t q, unsigned int flags, struct socket_info* force_socket)
{
	str luri;
	int nr_branches;
	struct branch *branches, *new_br;
	struct dset_ctx *dsct = get_dset_ctx();

	if (dsct && !dsct->enabled)
		return -1;

	if (!dsct) {
		dsct = pkg_malloc(sizeof *dsct);
		if (!dsct) {
			LM_ERR("oom 1\n");
			return E_OUT_OF_MEM;
		}
		memset(dsct, 0, sizeof *dsct);
		dsct->enabled = 1;
		store_dset_ctx(dsct);
	}

	nr_branches = dsct->nr_branches;

	/* if we have already set up the maximum number
	 * of branches, don't try new ones
	 */
	if (nr_branches == MAX_BRANCHES - 1) {
		LM_ERR("max nr of branches exceeded\n");
		ser_error = E_TOO_MANY_BRANCHES;
		return -1;
	}

	if (nr_branches % DSET_INCREMENT == 0) {
		new_br = pkg_realloc(dsct->branches,
                      (nr_branches + DSET_INCREMENT) * sizeof *dsct->branches);
		if (!new_br) {
			LM_ERR("oom 2\n");
			return E_OUT_OF_MEM;
		}

		dsct->branches = new_br;
	}

	/* if not parameterized, take current uri */
	if (ZSTRP(uri)) {
		if (msg->new_uri.s)
			luri = msg->new_uri;
		else
			luri = msg->first_line.u.request.uri;
	} else {
		luri = *uri;
	}

	if (luri.len > MAX_URI_SIZE - 1) {
		LM_ERR("too long uri: %.*s\n", luri.len, luri.s);
		return -1;
	}

	branches = dsct->branches;

	/* copy the dst_uri */
	if (ZSTRP(dst_uri)) {
		branches[nr_branches].dst_uri[0] = '\0';
		branches[nr_branches].dst_uri_len = 0;
	} else {
		if (dst_uri->len > MAX_URI_SIZE - 1) {
			LM_ERR("too long dst_uri: %.*s\n", dst_uri->len, dst_uri->s);
			return -1;
		}
		memcpy(branches[nr_branches].dst_uri, dst_uri->s, dst_uri->len);
		branches[nr_branches].dst_uri[dst_uri->len] = '\0';
		branches[nr_branches].dst_uri_len = dst_uri->len;
	}

	/* copy the path string */
	if (ZSTRP(path)) {
		branches[nr_branches].path[0] = '\0';
		branches[nr_branches].path_len = 0;
	} else {
		if (path->len > MAX_PATH_SIZE - 1) {
			LM_ERR("too long path: %.*s\n", path->len, path->s);
			return -1;
		}
		memcpy(branches[nr_branches].path, path->s, path->len);
		branches[nr_branches].path[path->len] = 0;
		branches[nr_branches].path_len = path->len;
	}

	/* copy the ruri */
	memcpy(branches[nr_branches].uri, luri.s, luri.len);
	branches[nr_branches].uri[luri.len] = '\0';
	branches[nr_branches].len = luri.len;
	branches[nr_branches].q = q;

	branches[nr_branches].force_send_socket = force_socket;
	branches[nr_branches].flags = flags;

	dsct->nr_branches++;
	return 1;
}



/* ! \brief
 * Updates one or more fields of an already appended branch
 */
int update_branch(unsigned int idx, str** uri, str** dst_uri, str** path,
		qvalue_t* q, unsigned int* flags, struct socket_info** force_socket)
{
	struct dset_ctx *dsct = get_dset_ctx();
	struct branch *branches;

	if (!dsct || !dsct->enabled || idx >= dsct->nr_branches)
		return -1;

	branches = dsct->branches;

	/* uri ? */
	if (uri) {
		/* set uri */
		if (*uri==NULL || (*uri)->len>MAX_URI_SIZE-1) {
			LM_ERR("empty or too long uri\n");
			return -1;
		}
		memcpy(branches[idx].uri, (*uri)->s, (*uri)->len);
		branches[idx].uri[(*uri)->len] = '\0';
		branches[idx].len = (*uri)->len;
	}

	/* duri ? */
	if (dst_uri) {
		if (ZSTRP(*dst_uri)) {
			branches[idx].dst_uri[0] = '\0';
			branches[idx].dst_uri_len = 0;
		} else {
			if ((*dst_uri)->len > MAX_URI_SIZE - 1) {
				LM_ERR("too long dst_uri: %.*s\n",
					(*dst_uri)->len, (*dst_uri)->s);
				return -1;
			}
			memcpy(branches[idx].dst_uri, (*dst_uri)->s, (*dst_uri)->len);
			branches[idx].dst_uri[(*dst_uri)->len] = '\0';
			branches[idx].dst_uri_len = (*dst_uri)->len;
		}
	}

	/* path ? */
	if (path) {
		if (ZSTRP(*path)) {
			branches[idx].path[0] = '\0';
			branches[idx].path_len = 0;
		} else {
			if ((*path)->len > MAX_PATH_SIZE - 1) {
				LM_ERR("too long path: %.*s\n", (*path)->len, (*path)->s);
				return -1;
			}
			memcpy(branches[idx].path, (*path)->s, (*path)->len);
			branches[idx].path[(*path)->len] = '\0';
			branches[idx].path_len = (*path)->len;
		}
	}

	/* Q value ? */
	if (q)
		branches[idx].q = *q;

	/* flags ? */
	if (flags)
		branches[idx].flags = *flags;

	/* socket ? */
	if (force_socket)
		branches[idx].force_send_socket = *force_socket;

	return 0;
}


int remove_branch(unsigned int idx)
{
	struct dset_ctx *dsct = get_dset_ctx();

	if (!dsct || !dsct->enabled || idx >= dsct->nr_branches)
		return -1;

	/* not last branch? */
	if (idx + 1 != dsct->nr_branches)
		memmove(dsct->branches + idx, dsct->branches + idx + 1,
			(dsct->nr_branches - idx - 1) * sizeof *dsct->branches);

	dsct->nr_branches--;

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
	qvalue_t q;
	str uri;
	char* p, *qbuf;
	static char *dset = NULL;
	static unsigned int dset_len = 0;

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

	for( idx=0 ; (uri.s=get_branch(idx,&uri.len,&q,0,0,0,0))!=0 ; idx++ ) {
		cnt++;
		*len += uri.len+2 /*for <>*/ ;
		if (q != Q_UNSPECIFIED) {
			*len += Q_PARAM_LEN + len_q(q);
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

	for( idx=0 ; (uri.s=get_branch(idx,&uri.len,&q,0,0,0,0))!=0 ; idx++ ) {
		if (i) {
			memcpy(p, CONTACT_DELIM, CONTACT_DELIM_LEN);
			p += CONTACT_DELIM_LEN;
		}

		*p++ = '<';
		memcpy(p, uri.s, uri.len);
		p += uri.len;
		*p++ = '>';

		if (q != Q_UNSPECIFIED) {
			memcpy(p, Q_PARAM, Q_PARAM_LEN);
			p += Q_PARAM_LEN;

			qbuf = q2str(q, &qlen);
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
int branch_uri2dset( str *new_uri )
{
	struct dset_ctx *dsct = get_dset_ctx();
	struct branch *branches;
	unsigned int b;

	/* no branches have been added yet */
	if (!dsct)
		return 0;

	branches = dsct->branches;

	if (new_uri->len+1 > MAX_URI_SIZE) {
		LM_ERR("new uri too long (%d)\n",new_uri->len);
		return -1;
	}

	for (b = 0; b < dsct->nr_branches; b++) {
		/* move uri to dst */
		memcpy(branches[b].dst_uri, branches[b].uri, branches[b].len + 1);
		branches[b].dst_uri_len = branches[b].len;
		/* set new uri */
		memcpy(branches[b].uri, new_uri->s, new_uri->len);
		branches[b].len =  new_uri->len;
		branches[b].uri[new_uri->len] = '\0';
	}

	return 0;
}


int move_branch_to_ruri(int idx, struct sip_msg *msg)
{
	struct dset_ctx *dsct = get_dset_ctx();
	struct branch *branch;
	str s;

	/* no branches have been added yet */
	if (!dsct) {
		LM_DBG("no branches found\n");
		return -1;
	}

	/* */
	if (idx >= dsct->nr_branches) {
		LM_DBG("trying to move inexisting branch idx %d, out of %d\n",
			idx, dsct->nr_branches);
		return -1;
	}

	branch = &dsct->branches[idx];

	/* move RURI */
	s.s = branch->uri;
	s.len = branch->len;
	if (set_ruri( msg, &s)<0) {
		LM_ERR("failed to set new RURI\n");
		return -1;
	}

	/* move DURI (empty is accepted as reset) */
	s.s = branch->dst_uri;
	s.len = branch->dst_uri_len;
	if (set_dst_uri( msg, &s)<0) {
		LM_ERR("failed to set DST URI\n");
		return -1;
	}

	/* move PATH  (empty is accepted as reset) */
	s.s = branch->path;
	s.len = branch->path_len;
	if (set_path_vector( msg, &s)<0) {
		LM_ERR("failed to set PATH\n");
		return -1;
	}

	/* Qval */
	set_ruri_q( msg, branch->q );

	/* BFLAGS */
	setb0flags( msg, branch->flags );

	/* socket info */
	msg->force_send_socket = branch->force_send_socket;

	return 0;
}
