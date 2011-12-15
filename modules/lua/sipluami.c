/*
 *
 * Copyright (c) 2008, 2009
 * 	     Eric Gouyer <folays@folays.net>
 * Copyright (c) 2008, 2009, 2010, 2011
 *	     Arnaud Chong <shine@achamo.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "../../mi/mi.h"

#include "sipwatch.h"
#include "sipluami.h"

#define SIPLUAMI_USAGE	"usage: watch [add | delete | show] [extension]"

struct mi_root *siplua_mi_reload(struct mi_root *cmd_tree, void *param)
{
  struct mi_root *answer;

  answer = init_mi_tree(200, "xOK", 3);
  addf_mi_node_child(&answer->node, 0, "pid", 3, "%d", (int)getpid());
  return answer;
}

struct mi_root *siplua_mi_bla(struct mi_root *cmd_tree, void *param)
{
  return init_mi_tree(200, MI_OK_S, MI_OK_LEN);
}

struct mi_root *siplua_mi_watch(struct mi_root *cmd_tree, void *param)
{
  struct mi_root *answer;
  struct mi_node *node;
  str action;

  node = cmd_tree->node.kids;
  if (!node)
    return init_mi_tree(200, SIPLUAMI_USAGE, sizeof(SIPLUAMI_USAGE) - 1);
  action = node->value;
  node = node->next;
  if (action.len == 3 && !strncmp("add", action.s, action.len))
    {
      if (!node)
	return init_mi_tree(200, "usage: missing extension", 24);
      sipwatch_add(node->value.s, node->value.len);
    }
  if (action.len == 6 && !strncmp("delete", action.s, action.len))
    {
      if (!node)
	return init_mi_tree(200, "usage: missing extension", 24);
      sipwatch_delete(node->value.s, node->value.len);
    }
  if (action.len == 4 && !strncmp("show", action.s, action.len))
    {
      int i;

      answer = init_mi_tree(200, "xOK", 3);
      sipwatch_lock();
      for (i = 0; i < siplua_watch->nb; ++i)
	addf_mi_node_child(&answer->node, 0, "extension", 9, "%s",
			   siplua_watch->ext[i].str);
      sipwatch_unlock();
      return answer;
    }
  answer = init_mi_tree(200, "xOK", 3);
  return answer;
}
