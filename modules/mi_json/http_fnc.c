/*
 * This file is part of Open SIP Server (opensips).
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
 * History:
 * ---------
 *  2013-10-31  first version (shimaore)
 */


#include "../../str.h"
#include "../../ut.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mi/mi.h"
#include "../../config.h"
#include "../../globals.h"
#include "../../locking.h"

#include "http_fnc.h"

extern str http_root;

mi_json_page_data_t html_page_data;

gen_lock_t* mi_json_lock;

struct page_buf {
  char *current;
  char *buf;
  int max_page_len;
  short status;
};

static inline void MI_JSON_COPY(struct page_buf* pb, const str s) {
  if ( pb->status ) {
    return;
  }
  if ( s.s == NULL || s.len == 0 ) {
    return;
  }
  if ( (int)(pb->current - pb->buf) + s.len > pb->max_page_len) {
    pb->status = -1;
  } else {
    memcpy(pb->current, s.s, s.len);
    pb->current += s.len;
  }
}

static const str MI_JSON_ESC =  str_init("\\");

static inline void MI_JSON_ESC_COPY(struct page_buf* pb, const str s) {
  str temp_holder;
  int temp_counter;
  if( pb->status ) {
    return;
  }
  if( s.s == NULL || s.len == 0 ) {
    return;
  }
  temp_holder.s = s.s;
  temp_holder.len = 0;
  for(temp_counter=0;temp_counter<s.len;temp_counter++) {
    switch(s.s[temp_counter]) {
    case '"':
    case '\\':
      temp_holder.len = temp_counter - temp_holder.len;
      MI_JSON_COPY(pb, temp_holder);
      MI_JSON_COPY(pb, MI_JSON_ESC);
      temp_holder.s = s.s + temp_counter;
      temp_holder.len = temp_counter;
      break;
    }
  }
  temp_holder.len = temp_counter - temp_holder.len;
  MI_JSON_COPY(pb, temp_holder);
}


static const str MI_JSON_KEY_NAME = str_init("\"name\":");
static const str MI_JSON_KEY_VALUE = str_init("\"value\":");
static const str MI_JSON_KEY_ATTRIBUTES = str_init("\"attributes\":");
static const str MI_JSON_KEY_CHILDREN = str_init("\"children\":");

static const str MI_JSON_NULL = str_init("null");

static const str MI_JSON_COMMA = str_init(", ");
static const str MI_JSON_COLON = str_init(": ");

static const str MI_JSON_OBJECT_START = str_init("{");
static const str MI_JSON_OBJECT_STOP = str_init("}");
static const str MI_JSON_ARRAY_START = str_init("[");
static const str MI_JSON_ARRAY_STOP = str_init("]");

static const str MI_JSON_SQUOT =  str_init("\""); /* " */

static int mi_json_recur_write_tree(struct page_buf* pb,
          struct mi_node *tree, unsigned int flags);

int mi_json_init_async_lock(void)
{
  mi_json_lock = lock_alloc();
  if (mi_json_lock==NULL) {
    LM_ERR("failed to create lock\n");
    return -1;
  }
  if (lock_init(mi_json_lock)==NULL) {
    LM_ERR("failed to init lock\n");
    return -1;
  }
  return 0;
}

void mi_json_destroy_async_lock(void)
{
  if (mi_json_lock) {
    lock_destroy(mi_json_lock);
    lock_dealloc(mi_json_lock);
  }
}


static int mi_json_recur_flush_tree(struct page_buf* pb, struct mi_node *tree);
int mi_json_flush_content(str *page, int max_page_len,
        struct mi_root* tree);



int mi_json_flush_tree(void* param, struct mi_root *tree)
{
  if (param==NULL) {
    LM_CRIT("null param\n");
    return 0;
  }
  mi_json_page_data_t* html_p_data = (mi_json_page_data_t*)param;
  mi_json_flush_content(&html_p_data->page,
        html_p_data->buffer.len,
        tree);
  return 0;
}


static void mi_json_close_async(struct mi_root *mi_rpl, struct mi_handler *hdl, int done)
{
  struct mi_root *shm_rpl = NULL;
  gen_lock_t* lock;
  mi_json_async_resp_data_t *async_resp_data;
  int x;

  if (hdl==NULL) {
    LM_CRIT("null mi handler\n");
    return;
  }

  LM_DBG("mi_root [%p], hdl [%p], hdl->param [%p] and done [%u]\n",
    mi_rpl, hdl, hdl->param, done);

  if (!done) {
    /* we do not pass provisional stuff (yet) */
    if (mi_rpl) free_mi_tree( mi_rpl );
    return;
  }

  async_resp_data = (mi_json_async_resp_data_t*)(hdl+1);
  lock = async_resp_data->lock;

  if (mi_rpl==NULL || (shm_rpl=clone_mi_tree( mi_rpl, 1))==NULL) {
    LM_WARN("Unable to process async reply [%p]\n", mi_rpl);
    /* mark it as invalid */
    shm_rpl = MI_JSON_ASYNC_FAILED;
  }
  if (mi_rpl) free_mi_tree(mi_rpl);

  lock_get(lock);
  if (hdl->param==NULL) {
    hdl->param = shm_rpl;
    x = 0;
  } else {
    x = 1;
  }
  LM_DBG("shm_rpl [%p], hdl [%p], hdl->param [%p]\n",
    shm_rpl, hdl, hdl->param);
  lock_release(lock);

  if (x) {
    if (shm_rpl!=MI_JSON_ASYNC_FAILED)
      free_shm_mi_tree(shm_rpl);
    shm_free(hdl);
  }


  return;
}

static inline struct mi_handler* mi_json_build_async_handler(void)
{
  struct mi_handler *hdl;
  mi_json_async_resp_data_t *async_resp_data;
  unsigned int len;

  len = sizeof(struct mi_handler)+sizeof(mi_json_async_resp_data_t);
  hdl = (struct mi_handler*)shm_malloc(len);
  if (hdl==NULL) {
    LM_ERR("oom\n");
    return NULL;
  }

  memset(hdl, 0, len);
  async_resp_data = (mi_json_async_resp_data_t*)(hdl+1);

  hdl->handler_f = mi_json_close_async;
  hdl->param = NULL;

  async_resp_data->lock = mi_json_lock;

  LM_DBG("hdl [%p], hdl->param [%p], mi_json_lock=[%p]\n",
    hdl, hdl->param, async_resp_data->lock);

  return hdl;
}

struct mi_root* mi_json_run_mi_cmd(struct mi_cmd *f, const str* miCmd,
	const str* params, str *page, str *buffer, struct mi_handler **async_hdl,
	union sockaddr_union* cl_socket)
{
  struct mi_node *node;
  struct mi_root *mi_cmd = NULL;
  struct mi_root *mi_rpl = NULL;
  struct mi_handler *hdl = NULL;
  str val;
  int i, j;

  LM_DBG("got command=%.*s\n", miCmd->len, miCmd->s);

  if (f->flags&MI_ASYNC_RPL_FLAG) {
    LM_DBG("command=%.*s is async\n", miCmd->len, miCmd->s);
    /* We need to build an async handler */
    hdl = mi_json_build_async_handler();
    if (hdl==NULL) {
      LM_ERR("failed to build async handler\n");
      goto error;
    }
  } else {
    hdl = NULL;
  }

  if (f->flags&MI_NO_INPUT_FLAG) {
    LM_DBG("command=%.*s requires no parameters\n", miCmd->len, miCmd->s);
    mi_cmd = NULL;
  } else {
    LM_DBG("command=%.*s accepts parameters\n", miCmd->len, miCmd->s);
    if (params->s) {
      mi_cmd = init_mi_tree(0,0,0);
      if (mi_cmd==NULL) {
        LM_ERR("the MI tree cannot be initialized!\n");
        goto error;
      }
      i = 0;
      j = 0;
      for( i = 0; i < params->len; i++ ) {
        if (params->s[i] == ',') {
          val.s = params->s + j;
          val.len = i-j;
          LM_DBG("got string param [%.*s]\n", val.len, val.s);
          node = &mi_cmd->node;
          if(!add_mi_node_child(node,0,NULL,0,val.s,val.len)){
            LM_ERR("cannot add the child node to the tree\n");
            free_mi_tree(mi_cmd);
            goto error;
          }
          j = i+1;
        }
      }
      if( j < params->len ) {
        val.s = params->s + j;
        val.len = params->len-j;
        LM_DBG("got string param [%.*s]\n", val.len, val.s);
        node = &mi_cmd->node;
        if(!add_mi_node_child(node,0,NULL,0,val.s,val.len)){
          LM_ERR("cannot add the child node to the tree\n");
          free_mi_tree(mi_cmd);
          goto error;
        }
      }
      mi_cmd->async_hdl = hdl;
    } else {
      LM_DBG("but no parameters were found\n");
      mi_cmd = init_mi_tree(0,0,0);
      if (mi_cmd==NULL) {
        LM_ERR("the MI tree cannot be initialized!\n");
        goto error;
      }
    }
  }


  html_page_data.page.s = buffer->s;
  html_page_data.page.len = 0;
  html_page_data.buffer.s = buffer->s;
  html_page_data.buffer.len = buffer->len;

  /* FIXME: find a proper way for handling flushing */
  mi_rpl = run_mi_cmd(f, mi_cmd,
        NULL, &html_page_data);
  if (mi_rpl == NULL) {
    LM_ERR("failed to process the command\n");
    goto error;
  } else {
    *page = html_page_data.page;
  }
  LM_DBG("got mi_rpl=[%p]\n",mi_rpl);

  trace_json_request( f, cl_socket, miCmd->s, mi_cmd);

  *async_hdl = hdl;

  if (mi_cmd) free_mi_tree(mi_cmd);
  return mi_rpl;

error:
  trace_json_request( f, cl_socket, miCmd->s, mi_cmd);

  if (mi_cmd) free_mi_tree(mi_cmd);
  if (hdl) shm_free(hdl);
  *async_hdl  = NULL;
  return NULL;
}


static inline int ALLOW_UNUSED mi_json_write_node_array(struct page_buf* pb,
          struct mi_node *node)
{
  LM_DBG("start\n");
  MI_JSON_COPY(pb, MI_JSON_SQUOT);
  MI_JSON_ESC_COPY(pb, node->value);
  MI_JSON_COPY(pb, MI_JSON_SQUOT);

  node->flags |= MI_WRITTEN;
  return pb->status;
}
static inline int mi_json_write_node_hash(struct page_buf* pb,
          struct mi_node *node)
{
  LM_DBG("start\n");

  MI_JSON_COPY(pb, MI_JSON_SQUOT);
  MI_JSON_ESC_COPY(pb, node->name);
  MI_JSON_COPY(pb, MI_JSON_SQUOT);
  MI_JSON_COPY(pb, MI_JSON_COLON);
  if (node->value.s!=NULL) {
    MI_JSON_COPY(pb, MI_JSON_SQUOT);
    MI_JSON_ESC_COPY(pb, node->value);
    MI_JSON_COPY(pb, MI_JSON_SQUOT);
  } else {
    MI_JSON_COPY(pb, MI_JSON_NULL);
  }

  node->flags |= MI_WRITTEN;
  return pb->status;
}

static inline int ALLOW_UNUSED mi_json_write_node(struct page_buf* pb,
          struct mi_node *node)
{
  struct mi_attr *attr;
  LM_DBG("start\n");

  /* name */
  MI_JSON_COPY(pb, MI_JSON_KEY_NAME);
  if (node->name.s!=NULL) {
    MI_JSON_COPY(pb, MI_JSON_SQUOT);
    MI_JSON_ESC_COPY(pb, node->name);
    MI_JSON_COPY(pb, MI_JSON_SQUOT);
  } else {
    MI_JSON_COPY(pb, MI_JSON_NULL);
  }
  MI_JSON_COPY(pb, MI_JSON_COMMA);

  /* value */
  MI_JSON_COPY(pb, MI_JSON_KEY_VALUE);
  if (node->value.s!=NULL) {
    MI_JSON_COPY(pb, MI_JSON_SQUOT);
    MI_JSON_ESC_COPY(pb, node->value);
    MI_JSON_COPY(pb, MI_JSON_SQUOT);
  } else {
    MI_JSON_COPY(pb, MI_JSON_NULL);
  }
  MI_JSON_COPY(pb, MI_JSON_COMMA);

  /* attributes */
  MI_JSON_COPY(pb, MI_JSON_KEY_ATTRIBUTES);
  MI_JSON_COPY(pb, MI_JSON_OBJECT_START);
  for(attr=node->attributes;attr!=NULL;attr=attr->next) {
    if (attr->name.s!=NULL) {
      /* attribute name */
      MI_JSON_COPY(pb, MI_JSON_SQUOT);
      MI_JSON_ESC_COPY(pb, attr->name);
      MI_JSON_COPY(pb, MI_JSON_SQUOT);
      MI_JSON_COPY(pb, MI_JSON_COLON);

      /* attribute value */
      if (attr->value.s!=NULL) {
        MI_JSON_COPY(pb, MI_JSON_SQUOT);
        MI_JSON_ESC_COPY(pb, attr->value);
        MI_JSON_COPY(pb, MI_JSON_SQUOT);
      } else {
        MI_JSON_COPY(pb, MI_JSON_NULL);
      }
    }
    if (attr->next!=NULL) {
      MI_JSON_COPY(pb, MI_JSON_COMMA);
    }
  }
  MI_JSON_COPY(pb, MI_JSON_OBJECT_STOP);

  return pb->status;
}

/* sync case */
#if 0
static int mi_json_recur_write_tree(struct page_buf* pb,
          struct mi_node *tree, unsigned int flags)
{
  int names = 0;
  int values = 0;
  int attributes = 0;
  int kids = 0;
  struct mi_node* t;
  LM_DBG("start\n");
  for( t = tree; t ; t=t->next ) {
    if(t->name.s) {
      names++;
    }
    if(t->value.s) {
      values++;
    }
    if(t->attributes) {
      attributes++;
    }
    if(t->kids) {
      kids++;
    }
  }

  if(names == 0 && values > 0 && attributes == 0 && kids == 0) {
    LM_DBG("Treat as an array\n");
    /* Treat as an array */
    MI_JSON_COPY(pb, MI_JSON_ARRAY_START);
    for( t = tree; t; t=t->next ) {
      mi_json_write_node_array(pb,t);
      t->flags |= MI_WRITTEN;
      if(t->next) {
        MI_JSON_COPY(pb, MI_JSON_COMMA);
      }
    }
    MI_JSON_COPY(pb, MI_JSON_ARRAY_STOP);
    LM_DBG("done\n");
    return 0;
  }
  if(names >= values && attributes == 0 && kids == 0) {
    LM_DBG("Treat as a hash\n");
    /* Treat as a hash */
    MI_JSON_COPY(pb, MI_JSON_OBJECT_START);
    for( t = tree; t; t=t->next ) {
      LM_DBG("t = %p\n",t);
      mi_json_write_node_hash(pb,t);
      t->flags |= MI_WRITTEN;
      if(t->next) {
        MI_JSON_COPY(pb, MI_JSON_COMMA);
      }
    }
    MI_JSON_COPY(pb, MI_JSON_OBJECT_STOP);
    LM_DBG("done\n");
    return 0;
  }
  if(names == 0 && values == 0 && attributes == 0 && kids > 0) {
    LM_DBG("Treat as an array of objects\n");
    /* Treat as an array of objects */
    MI_JSON_COPY(pb, MI_JSON_ARRAY_START);
    for( t = tree; t; t=t->next ) {
      mi_json_recur_write_tree(pb,t->kids, t->flags);
      t->flags |= MI_WRITTEN;
      if(t->next) {
        MI_JSON_COPY(pb, MI_JSON_COMMA);
      }
    }
    MI_JSON_COPY(pb, MI_JSON_ARRAY_STOP);
    LM_DBG("done\n");
    return 0;
  }

  /* Otherwise */
  LM_DBG("Treat as a complex array of hashes\n");
  /* Treat as a complex array of hashes */
  MI_JSON_COPY(pb, MI_JSON_ARRAY_START);
  for( t = tree; t; t=t->next ) {
    MI_JSON_COPY(pb, MI_JSON_OBJECT_START);
    mi_json_write_node(pb,t);
    if (t->kids) {
      MI_JSON_COPY(pb, MI_JSON_COMMA);
      MI_JSON_COPY(pb, MI_JSON_KEY_CHILDREN);
      mi_json_recur_write_tree(pb, t->kids, t->flags);
    }
    MI_JSON_COPY(pb, MI_JSON_OBJECT_STOP);
    if(t->next) {
      MI_JSON_COPY(pb, MI_JSON_COMMA);
    }
  }
  MI_JSON_COPY(pb, MI_JSON_ARRAY_STOP);
  LM_DBG("done\n");
  return pb->status;
}
#endif

static void mi_json_recur_write_node(struct page_buf* pb, struct mi_node *node,
		int dump_name)
{
  struct mi_attr *attr;
  int first = 1;

  /* if we only have name and value, then dump it like hash */
  if (dump_name && node->name.s && node->value.s && !node->attributes && !node->kids) {
    mi_json_write_node_hash(pb, node);
	return;
  }

  if (dump_name && node->name.s) {
	MI_JSON_COPY(pb, MI_JSON_SQUOT);
	MI_JSON_ESC_COPY(pb, node->name);
	MI_JSON_COPY(pb, MI_JSON_SQUOT);
	MI_JSON_COPY(pb, MI_JSON_COLON);
    MI_JSON_COPY(pb, MI_JSON_OBJECT_START);
  }

  /* value */
  if (node->value.s) {
    MI_JSON_COPY(pb, MI_JSON_KEY_VALUE);
    MI_JSON_COPY(pb, MI_JSON_SQUOT);
    MI_JSON_ESC_COPY(pb, node->value);
    MI_JSON_COPY(pb, MI_JSON_SQUOT);
	first = 0;
  }

  /* attributes */
  if (node->attributes) {
    if (!first)
      MI_JSON_COPY(pb, MI_JSON_COMMA);

    MI_JSON_COPY(pb, MI_JSON_KEY_ATTRIBUTES);
	MI_JSON_COPY(pb, MI_JSON_OBJECT_START);
    for(attr=node->attributes;attr!=NULL;attr=attr->next) {
      if (attr->name.s!=NULL) {
        /* attribute name */
        MI_JSON_COPY(pb, MI_JSON_SQUOT);
        MI_JSON_ESC_COPY(pb, attr->name);
        MI_JSON_COPY(pb, MI_JSON_SQUOT);
        MI_JSON_COPY(pb, MI_JSON_COLON);

        /* attribute value */
        if (attr->value.s!=NULL) {
          MI_JSON_COPY(pb, MI_JSON_SQUOT);
          MI_JSON_ESC_COPY(pb, attr->value);
          MI_JSON_COPY(pb, MI_JSON_SQUOT);
        } else {
          MI_JSON_COPY(pb, MI_JSON_NULL);
        }
      }
      if (attr->next!=NULL) {
        MI_JSON_COPY(pb, MI_JSON_COMMA);
      }
    }
	MI_JSON_COPY(pb, MI_JSON_OBJECT_STOP);
	first = 0;
  }

  /* kids */
  if (node->kids) {
    if (!first)
      MI_JSON_COPY(pb, MI_JSON_COMMA);
    MI_JSON_COPY(pb, MI_JSON_KEY_CHILDREN);
    mi_json_recur_write_tree(pb, node->kids, node->flags);
  }

  if (dump_name && node->name.s) {
    MI_JSON_COPY(pb, MI_JSON_OBJECT_STOP);
  }
}

static int mi_json_recur_write_tree(struct page_buf* pb,
          struct mi_node *tree, unsigned int flags)
{
  struct mi_node* t;
  if (!tree)
    return pb->status;


  if (flags & MI_IS_ARRAY) {
    LM_DBG("Treat as an array\n");
    MI_JSON_COPY(pb, MI_JSON_OBJECT_START);
    MI_JSON_COPY(pb, MI_JSON_SQUOT);
    if (tree->name.s) {
      MI_JSON_ESC_COPY(pb, tree->name);
    }
    MI_JSON_COPY(pb, MI_JSON_SQUOT);
    MI_JSON_COPY(pb, MI_JSON_COLON);
    MI_JSON_COPY(pb, MI_JSON_ARRAY_START);
    for( t = tree; t; t=t->next ) {
      MI_JSON_COPY(pb, MI_JSON_OBJECT_START);
      mi_json_recur_write_node(pb,t,0);
      MI_JSON_COPY(pb, MI_JSON_OBJECT_STOP);
      t->flags |= MI_WRITTEN;
      if(t->next) {
        MI_JSON_COPY(pb, MI_JSON_COMMA);
      }
    }
    MI_JSON_COPY(pb, MI_JSON_ARRAY_STOP);
    MI_JSON_COPY(pb, MI_JSON_OBJECT_STOP);
  } else {
    LM_DBG("Treat as a hash\n");
    MI_JSON_COPY(pb, MI_JSON_OBJECT_START);
    for( t = tree; t; t=t->next ) {
      mi_json_recur_write_node(pb,t,1);
      t->flags |= MI_WRITTEN;
      if(t->next) {
        MI_JSON_COPY(pb, MI_JSON_COMMA);
      }
    }
    MI_JSON_COPY(pb, MI_JSON_OBJECT_STOP);
  }
  LM_DBG("done\n");
  return pb->status;
}


int mi_json_build_content(str *page, int max_page_len,
        struct mi_root* tree)
{
  struct page_buf pb;
  LM_DBG("start\n");

  pb.buf = page->s;
  pb.current = page->s + page->len;
  pb.max_page_len = max_page_len;
  pb.status = 0;

  if (tree) { /* Build mi reply */
    mi_json_recur_write_tree(&pb, tree->node.kids, tree->node.flags);
    page->len = pb.current - page->s;
  }
  LM_DBG("done\n");
  return pb.status;
}


int mi_json_build_page(str *page, int max_page_len,
        struct mi_root *tree)
{
  LM_DBG("start\n");
  return mi_json_build_content(page, max_page_len, tree);
}


/* async case */
static int mi_json_recur_flush_tree(struct page_buf* pb,
          struct mi_node *tree)
{
  struct mi_node *kid;
  LM_DBG("start\n");

  for(kid = tree->kids ; kid ; ){
    if (kid->flags & MI_NOT_COMPLETED) {
      return 1;
    }
  }

  mi_json_recur_write_tree(pb,tree,0);
  LM_DBG("done\n");
  return pb->status;
}

int mi_json_flush_content(str *page, int max_page_len,
        struct mi_root* tree)
{
  struct page_buf pb;
  LM_DBG("start\n");
  pb.buf = page->s;
  pb.current = page->s + page->len;
  pb.max_page_len = max_page_len;
  pb.status = 0;

  if (tree) { /* Build mi reply */
    mi_json_recur_flush_tree(&pb, &tree->node);
    page->len = pb.current - page->s;
  }
  LM_DBG("done\n");
  return pb.status;
}
