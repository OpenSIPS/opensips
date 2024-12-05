 /*
￼ * Trie Module
￼ *
￼ * Copyright (C) 2024 OpenSIPS Project
￼ *
￼ * opensips is free software; you can redistribute it and/or modify
￼ * it under the terms of the GNU General Public License as published by
￼ * the Free Software Foundation; either version 2 of the License, or
￼ * (at your option) any later version.
￼ *
￼ * opensips is distributed in the hope that it will be useful,
￼ * but WITHOUT ANY WARRANTY; without even the implied warranty of
￼ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
￼ * GNU General Public License for more details.
￼ *
￼ * You should have received a copy of the GNU General Public License
￼ * along with this program; if not, write to the Free Software
￼ * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
￼ *
￼ * History:
￼ * --------
￼ * 2024-12-03 initial release (vlad)
￼ */

#include <stdlib.h>
#include <stdio.h>

#include "../../str.h"
#include "../../mem/shm_mem.h"
#include "../../time_rec.h"

#include "prefix_tree.h"
#include "trie_partitions.h"

#define DR_PREFIX_ARRAY_SIZE 128
static unsigned char *trie_char2idx = NULL;

/* number of children under a prefix node */
int ptree_children = 0;

#define IDX_OF_CHAR(_c) \
	trie_char2idx[ (unsigned char)(_c) ]

#define IS_VALID_PREFIX_CHAR(_c) \
	((((unsigned char)(_c))<DR_PREFIX_ARRAY_SIZE) && (char)IDX_OF_CHAR(_c)!=-1 )

int init_prefix_tree( char *extra_prefix_chars )
{
	int i;

	trie_char2idx = (unsigned char *)pkg_malloc
		( DR_PREFIX_ARRAY_SIZE * sizeof(unsigned char) );
	if (trie_char2idx==NULL) {
		LM_ERR("not enought pkg mem for the prefix array\n");
		return -1;
	}
	memset( trie_char2idx, -1, DR_PREFIX_ARRAY_SIZE * sizeof(char));

	/* init the arrary with the '0'..'9' range */
	for( i='0' ; i<='9' ; i++)
		trie_char2idx[i] = ptree_children++;

	/* and now the extras */
	if (extra_prefix_chars) {
		for( i=0 ; extra_prefix_chars[i] ; i++) {
			if ((unsigned char)extra_prefix_chars[i]>=DR_PREFIX_ARRAY_SIZE) {
				LM_ERR("extra prefix char <%c/%d> out of range (max=%d),"
					" ignoring\n",extra_prefix_chars[i],extra_prefix_chars[i],
					DR_PREFIX_ARRAY_SIZE);
				continue;
			}
			IDX_OF_CHAR( extra_prefix_chars[i] ) = ptree_children++;
		}
	}
	LM_INFO("counted %d possible chars under a node\n", ptree_children);

	return 0;
}

trie_node_t *get_child(trie_node_t *parent, int child_index) {
	char *first_child_ptr;

	if (child_index < 0 || child_index >= ptree_children) {
		LM_ERR("Out of bounds child %d requested \n",child_index);
		return NULL;
	}

	/* get first child allocated right after current node */
	first_child_ptr = ((char*)parent) + sizeof(trie_node_t);
	/* offset it to get to the right child_index */
	return *(trie_node_t**)(first_child_ptr + child_index * sizeof(trie_node_t*));
}

trie_info_t*
get_trie_prefix(
	trie_node_t *ptree,
	str* prefix,
	unsigned int *matched_len,
	int enabled_only
	)
{
	char *tmp=NULL,*last_valid_tmp;
	char local=0;
	int idx=0;
	trie_info_t *last_valid = NULL;
	trie_node_t *current = NULL;

	if(NULL == ptree)
		goto err_exit;
	if(NULL == prefix)
		goto err_exit;
	tmp = prefix->s;
	if (tmp == NULL)
		goto err_exit;

	current = ptree;

	/* go the tree down to the last digit in the
	 * prefix string or down to a leaf */
	while(tmp< (prefix->s+prefix->len)) {
		local=*tmp;
		idx = IDX_OF_CHAR(local);
		if (!IS_VALID_PREFIX_CHAR(*tmp) || (current = get_child(current,idx)) == NULL) {
			break;
		}

		if (current->info && (!enabled_only || current->info->enabled)) {
			/* found a valid node, store it */
 			last_valid = current->info;
			last_valid_tmp = tmp;
		}
		tmp++;
	}

	if (last_valid && matched_len) { 
		*matched_len = last_valid_tmp + 1 - prefix->s;
	}

	return last_valid;

err_exit:
	return NULL;
}

int add_trie_info(
	trie_node_t *pn,
	trie_info_t* r,
	osips_malloc_f malloc_f,
	osips_free_f free_f
	)
{
	pn->info = r;
	return 0;
}

int add_trie_prefix(trie_node_t *ptree, str *prefix, trie_info_t *r, osips_malloc_f malloc_f, osips_free_f free_f) 
{
	char* tmp=NULL;
	int res = 0;
	trie_node_t *child;

	if (ptree == NULL || prefix == NULL || prefix->s == NULL) {
		LM_ERR("ptree or no prefix\n");
		return -1;
	}

	tmp = prefix->s;
	while(tmp < (prefix->s+prefix->len)) {
		if(NULL == tmp) {
			LM_ERR("prefix became null\n");
			goto err_exit;
		}
		if( !IS_VALID_PREFIX_CHAR(*tmp) ) {
			/* unknown character in the prefix string */
			LM_ERR("%c is not valid char in the prefix\n", *tmp);
			goto err_exit;
		}

		/* process the current digit in the prefix */
		if( (child = get_child(ptree,IDX_OF_CHAR(*tmp))) == NULL) {
			/* allocate new node */
			INIT_TRIE_NODE(malloc_f,child);
			SET_TRIE_CHILD(ptree,IDX_OF_CHAR(*tmp),child);
		}

		ptree = get_child(ptree,IDX_OF_CHAR(*tmp));

		if( tmp == (prefix->s+prefix->len-1) ) {
			/* last digit in the prefix string */
			LM_DBG("adding info %p, at: "
				"%p (%d)\n", r, ptree,
				IDX_OF_CHAR(*tmp));
			res = add_trie_info(ptree,r, malloc_f, free_f);
			if(res < 0 ) {
				LM_ERR("adding rt info doesn't work\n");
				goto err_exit;
			}
			res = 1;
			goto ok_exit;
		}

		tmp++;
	}

ok_exit:
	return 0;

err_exit:
	return -1;
}

int del_tree(trie_node_t* t, osips_free_f free_f) {
    if (t == NULL) {
        return 0;
    }

    for (int i = 0; i < ptree_children; i++) {
        trie_node_t *child = get_child(t, i);
        if (child != NULL) {
            if (child->info != NULL) {
                free_trie_info(child->info, free_f);
            }
            del_tree(child, free_f);
        }
    }

    func_free(free_f, t);

    return 0;
}

void
free_trie_info(
		trie_info_t *rl,
		osips_free_f f
		)
{
	if (NULL!=rl->attrs.s)
		shm_free(rl->attrs.s);
	func_free(f, rl);
	return;
}

trie_data_t*
build_trie_data(struct head_db *part)
{
	trie_data_t *rdata=NULL;

	if( NULL==(rdata=func_malloc(part->malloc, sizeof(trie_data_t)))) {
		LM_ERR("no more shm mem\n");
		goto err_exit;
	}
	memset(rdata, 0, sizeof(trie_data_t));

	/* empty trie with no children */
	INIT_TRIE_NODE(part->malloc, rdata->pt);
	return rdata;
err_exit:
	if (rdata)
		func_free(part->free, rdata);
	return 0;
}

trie_info_t*
build_trie_info(
	str* attrs,
	int enabled,
	osips_malloc_f mf,
	osips_free_f ff
	)
{
	trie_info_t* rt = NULL;

	rt = (trie_info_t*)func_malloc(mf, sizeof(trie_info_t));
	if (rt==NULL) {
		LM_ERR("no more mem(1)\n");
		goto err_exit;
	}
	memset(rt, 0, sizeof(trie_info_t));
	rt->enabled = enabled;

	if (attrs && attrs->s && attrs->len) {
		rt->attrs.s = func_malloc(mf,attrs->len);
		if (rt->attrs.s == NULL) {
			LM_ERR("no more shm mem(1)\n");
			goto err_exit;
		}
		rt->attrs.len = attrs->len;
		memcpy(rt->attrs.s,attrs->s,rt->attrs.len);
	}

	return rt;

err_exit:
	if (NULL!=rt->attrs.s)
		func_free(ff,rt->attrs.s);
	if ((NULL != rt) ) {
		func_free(ff, rt);
	}
	return NULL;
}


void free_trie_data(
	trie_data_t* rt_data,
	osips_free_f free_f
	)
{
	if(NULL!=rt_data) {
		del_tree(rt_data->pt, free_f);
		rt_data->pt = 0 ;

		/* del top level */
		func_free(free_f, rt_data);
	}
}
