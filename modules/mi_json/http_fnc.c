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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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

#define MI_JSON_COPY(p,str)  \
do{  \
  if ((int)((p)-buf)+(str).len>max_page_len) {  \
    goto error;  \
  }  \
  memcpy((p), (str).s, (str).len); (p) += (str).len;  \
}while(0)

#define MI_JSON_COPY_2(p,str1,str2)  \
do{  \
  if ((int)((p)-buf)+(str1).len+(str2).len>max_page_len) {  \
    goto error;  \
  }  \
  memcpy((p), (str1).s, (str1).len); (p) += (str1).len;  \
  memcpy((p), (str2).s, (str2).len); (p) += (str2).len;  \
}while(0)

#define MI_JSON_ESC_COPY(p,str,temp_holder,temp_counter)  \
do{  \
  (temp_holder).s = (str).s;  \
  (temp_holder).len = 0;  \
  for((temp_counter)=0;(temp_counter)<(str).len;(temp_counter)++) {  \
    switch((str).s[(temp_counter)]) {  \
    case '"':  \
      (temp_holder).len = (temp_counter) - (temp_holder).len;  \
      MI_JSON_COPY_2(p, (temp_holder), MI_JSON_ESC_QUOT);  \
      (temp_holder).s += (temp_counter) + 1;  \
      (temp_holder).len = (temp_counter) + 1;  \
      break;  \
    }  \
  }  \
  (temp_holder).len = (temp_counter) - (temp_holder).len;  \
  MI_JSON_COPY(p, (temp_holder));  \
}while(0)


static const str MI_JSON_CR = str_init("\n");

static const str MI_JSON_NAME = str_init("\"name\":");
static const str MI_JSON_VALUE = str_init("\"value\":");
static const str MI_JSON_ATTRIBUTES = str_init("\"attributes\":");

static const str MI_JSON_VAL_SEPARATOR = str_init(": ");

static const str MI_JSON_OBJECT_START = str_init("{\n");
static const str MI_JSON_OBJECT_STOP = str_init("}\n");
static const str MI_JSON_ARRAY_START = str_init("[\n");
static const str MI_JSON_ARRAY_STOP = str_init("]\n");

static const str MI_JSON_ESC_QUOT =  str_init("\\\""); /* " */
static const str MI_JSON_SQUOT =  str_init("\""); /* " */


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


static int mi_json_recur_flush_tree(char** pointer, char *buf, int max_page_len,
          struct mi_node *tree, int level);

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

  if (hdl==NULL) {
    LM_CRIT("null mi handler\n");
    return;
  }

  LM_DBG("mi_root [%p], hdl [%p], hdl->param [%p], "
    "*hdl->param [%p] and done [%u]\n",
    mi_rpl, hdl, hdl->param, *(struct mi_root **)hdl->param, done);

  if (!done) {
    /* we do not pass provisional stuff (yet) */
    if (mi_rpl) free_mi_tree( mi_rpl );
    return;
  }

  async_resp_data =
    (mi_json_async_resp_data_t*)((char*)hdl+sizeof(struct mi_handler));
  lock = async_resp_data->lock;
  lock_get(lock);
  if (mi_rpl!=NULL && (shm_rpl=clone_mi_tree( mi_rpl, 1))!=NULL) {
    *(struct mi_root **)hdl->param = shm_rpl;
  } else {
    LM_WARN("Unable to process async reply [%p]\n", mi_rpl);
    /* mark it as invalid */
    hdl->param = NULL;
  }
  LM_DBG("shm_rpl [%p], hdl [%p], hdl->param [%p], *hdl->param [%p]\n",
    shm_rpl, hdl, hdl->param,
    (hdl->param)?*(struct mi_root **)hdl->param:NULL);
  lock_release(lock);

  if (mi_rpl) free_mi_tree(mi_rpl);

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
  async_resp_data =
    (mi_json_async_resp_data_t*)((char*)hdl+sizeof(struct mi_handler));

  hdl->handler_f = mi_json_close_async;
  hdl->param = (void*)&async_resp_data->tree;

  async_resp_data->lock = mi_json_lock;

  LM_DBG("hdl [%p], hdl->param [%p], *hdl->param [%p] mi_json_lock=[%p]\n",
    hdl, hdl->param, (hdl->param)?*(struct mi_root **)hdl->param:NULL,
    async_resp_data->lock);

  return hdl;
}

struct mi_root* mi_json_run_mi_cmd(const str* arg,
    str *page, str *buffer, struct mi_handler **async_hdl)
{
  struct mi_cmd *f;
  struct mi_node *node;
  struct mi_root *mi_cmd;
  struct mi_root *mi_rpl;
  struct mi_handler *hdl;
  str miCmd;
  str val;

  //LM_DBG("arg [%p]->[%.*s]\n", arg->s, arg->len, arg->s);
  miCmd.s = "which";
  miCmd.len = strlen(miCmd.s);
  LM_DBG("got command=%.*s\n", miCmd.len, miCmd.s);

  f = lookup_mi_cmd(miCmd.s, miCmd.len);
  if (f == NULL) {
    LM_ERR("unable to find mi command [%.*s]\n", miCmd.len, miCmd.s);
    goto error;
  }

  if (f->flags&MI_ASYNC_RPL_FLAG) {
    /* We need to build an async handler */
    hdl = mi_json_build_async_handler();
    if (hdl==NULL) {
      LM_ERR("failed to build async handler\n");
      goto error;
    }
  } else {
    hdl = NULL;
  }
  *async_hdl = hdl;

  if (f->flags&MI_NO_INPUT_FLAG) {
    mi_cmd = NULL;
  } else {
    if (arg->s) {
      mi_cmd = init_mi_tree(0,0,0);
      if (mi_cmd==NULL) {
        LM_ERR("the MI tree cannot be initialized!\n");
        goto error;
      }
      /*
        for params... {
          val.s = (char*).....;
          if(val.s==NULL){
            LM_ERR("No content for node [%s]\n",
                string_node->name);
            goto error;
          }
          val.len = strlen(val.s);
          if(val.len==0){
            LM_ERR("Empty content for node [%s]\n",
                string_node->name);
            goto error;
          }
          LM_DBG("got string param [%.*s]\n", val.len, val.s);
          node = &mi_cmd->node;
          if(!add_mi_node_child(node,0,NULL,0,val.s,val.len)){
            LM_ERR("cannot add the child node to the tree\n");
            free_mi_tree(mi_cmd);
            goto error;
          }
        }
      */
      mi_cmd->async_hdl = hdl;
    } else {
      mi_cmd = NULL;
    }
  }

  html_page_data.page.s = buffer->s;
  html_page_data.page.len = 0;
  html_page_data.buffer.s = buffer->s;
  html_page_data.buffer.len = buffer->len;

  mi_rpl = run_mi_cmd(f, mi_cmd,
        (mi_flush_f *)mi_json_flush_tree, &html_page_data);
  if (mi_rpl == NULL) {
    LM_ERR("failed to process the command\n");
    if (mi_cmd) free_mi_tree(mi_cmd);
    goto error;
  } else if (mi_rpl != MI_ROOT_ASYNC_RPL) {
    *page = html_page_data.page;
  }
  LM_DBG("got mi_rpl=[%p]\n",mi_rpl);

  if (mi_cmd) free_mi_tree(mi_cmd);
  return mi_rpl;

error:
  return NULL;
}


static inline int mi_json_write_node(char** pointer, char* buf, int max_page_len,
          struct mi_node *node, int level)
{
  struct mi_attr *attr;
  str temp_holder;
  int temp_counter;

  MI_JSON_COPY(*pointer, MI_JSON_OBJECT_START);
  /* name and value */
  if (node->name.s!=NULL) {
    MI_JSON_COPY(*pointer, MI_JSON_NAME);
    MI_JSON_COPY(*pointer, MI_JSON_SQUOT);
    MI_JSON_ESC_COPY(*pointer, node->name,
        temp_holder, temp_counter);
    MI_JSON_COPY(*pointer, MI_JSON_SQUOT);
  }
  if (node->value.s!=NULL) {
    MI_JSON_COPY(*pointer, MI_JSON_VALUE);
    MI_JSON_COPY(*pointer, MI_JSON_SQUOT);
    MI_JSON_ESC_COPY(*pointer, node->value,
        temp_holder, temp_counter);
    MI_JSON_COPY(*pointer, MI_JSON_SQUOT);
  }
  /* attributes */
  MI_JSON_COPY(*pointer, MI_JSON_ATTRIBUTES);
  MI_JSON_COPY(*pointer, MI_JSON_ARRAY_START);
  for(attr=node->attributes;attr!=NULL;attr=attr->next) {
    if (attr->name.s!=NULL) {
      MI_JSON_COPY(*pointer, MI_JSON_SQUOT);
      MI_JSON_ESC_COPY(*pointer, attr->name,
          temp_holder, temp_counter);
      MI_JSON_COPY(*pointer, MI_JSON_SQUOT);
      MI_JSON_COPY(*pointer, MI_JSON_VAL_SEPARATOR);
      MI_JSON_COPY(*pointer, MI_JSON_SQUOT);
      MI_JSON_ESC_COPY(*pointer, attr->value,
          temp_holder, temp_counter);
      MI_JSON_COPY(*pointer, MI_JSON_SQUOT);
    }
  }
  MI_JSON_COPY(*pointer, MI_JSON_ARRAY_STOP);
  MI_JSON_COPY(*pointer, MI_JSON_OBJECT_STOP);
  return 0;
error:
  LM_ERR("buffer 2 small: *pointer=[%p] buf=[%p] max_page_len=[%d]\n",
      *pointer, buf, max_page_len);
  return -1;
}


static int mi_json_recur_flush_tree(char** pointer, char *buf, int max_page_len,
          struct mi_node *tree, int level)
{
  struct mi_node *kid, *tmp;
  int ret;

  for(kid = tree->kids ; kid ; ){
    if (!(kid->flags & MI_WRITTEN)) {
      if (mi_json_write_node(pointer, buf, max_page_len,
              kid, level)!=0)
        return -1;
      kid->flags |= MI_WRITTEN;
    }
    if ((ret = mi_json_recur_flush_tree(pointer, buf, max_page_len,
              tree->kids, level+1))<0){
      return -1;
    } else if (ret > 0) {
      return ret;
    }
    if (!(kid->flags & MI_NOT_COMPLETED)){
      tmp = kid;
      kid = kid->next;
      tree->kids = kid;

      if(!tmp->kids){
        /* this node does not have any kids */
        free_mi_node(tmp);
      }
    } else {
      /* the node will have more kids =>
       * to keep the tree shape,
       * do not flush any other node for now */
      return 1;
    }
  }
  return 0;
}


static int mi_json_recur_write_tree(char** pointer, char *buf, int max_page_len,
          struct mi_node *tree, int level)
{
  for( ; tree ; tree=tree->next ) {
    if (!(tree->flags & MI_WRITTEN)) {
      if (mi_json_write_node(pointer, buf, max_page_len,
                  tree, level)!=0){
        return -1;
      }
    }
    if (tree->kids) {
      if (mi_json_recur_write_tree(pointer, buf, max_page_len,
            tree->kids, level+1)<0){
        return -1;
      }
    }
  }
  return 0;
}


int mi_json_build_header(str *page, int max_page_len,
        struct mi_root *tree, int flush)
{
  char *p, *buf;

  if (page->s == NULL) {
    LM_ERR("Please provide a valid page\n");
    return -1;
  }
  p = buf = page->s;

  if (tree) {
    LM_DBG("return code: %d\n", tree->code);
    if (!(tree->node.flags & MI_WRITTEN)) {
      MI_JSON_COPY(p, MI_JSON_ARRAY_START);
      tree->node.flags |= MI_WRITTEN;
    }
    if (flush) {
      if (mi_json_recur_flush_tree(&p, buf, max_page_len,
              &tree->node, 0)<0)
        return -1;
    } else {
      if (mi_json_recur_write_tree(&p, buf, max_page_len,
              tree->node.kids, 0)<0)
        return -1;
    }
    MI_JSON_COPY(p, MI_JSON_ARRAY_STOP);
  }

  page->len = p - page->s;
  return 0;
error:
  LM_ERR("buffer 2 small\n");
  page->len = p - page->s;
  return -1;
}


int mi_json_build_content(str *page, int max_page_len,
        struct mi_root* tree)
{
  char *p, *buf;

  if (page->len==0) {
    if (0!=mi_json_build_header(page, max_page_len, tree, 0))
      return -1;
  } else {
    buf = page->s;
    p = page->s + page->len;

    if (tree) { /* Build mi reply */
      if (mi_json_recur_write_tree(&p, buf, max_page_len,
              tree->node.kids, 0)<0)
        return -1;
      page->len = p - page->s;
    }
  }
  return 0;
}


int mi_json_build_page(str *page, int max_page_len,
        struct mi_root *tree)
{
  char *p, *buf;

  if (0!=mi_json_build_content(page, max_page_len, tree))
    return -1;
  buf = page->s;
  p = page->s + page->len;

  return 0;
}


int mi_json_flush_content(str *page, int max_page_len,
        struct mi_root* tree)
{
  char *p, *buf;

  if (page->len==0)
    if (0!=mi_json_build_header(page, max_page_len, tree, 1))
      return -1;
  buf = page->s;
  p = page->s + page->len;

  if (tree) { /* Build mi reply */
    if (mi_json_recur_flush_tree(&p, buf, max_page_len,
            &tree->node, 0)<0)
      return -1;
    page->len = p - page->s;
  }
  return 0;
}
