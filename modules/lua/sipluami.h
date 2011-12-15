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

#include "../../mi/mi.h"

#ifndef SIPLUAMI_H_
# define SIPLUAMI_H_

struct mi_root *siplua_mi_reload(struct mi_root *cmd_tree, void *param);
struct mi_root *siplua_mi_bla(struct mi_root *cmd_tree, void *param);
struct mi_root *siplua_mi_watch(struct mi_root *cmd_tree, void *param);

#endif /* !SIPLUAMI_H_ */
