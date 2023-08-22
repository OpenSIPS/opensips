/*
 * Copyright (C) 2023 Sippy Software, Inc., http://www.sippysoft.com
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
 */

#pragma once

typedef int (*pred_cmp_f)(int, int);

struct main_script {
        int (*hndlr)(void);
        int pval;
        int pred;
        const char *desc;
};

static int op_neq(int r, int e) { return (r != e); }
static int op_eq(int r, int e) { return (r == e); }
static int op_lt(int r, int e) { return (r < e); }
static int op_lte(int r, int e) { return (r <= e); }
static int op_gt(int r, int e) { return (r > e); }
static int op_gte(int r, int e) { return (r >= e); }

#define opidx(lop) (((0 lop 0) << 2) | ((0 lop 1) << 1) | (1 lop 0))

static const pred_cmp_f cmps_ops[] = {
        [opidx(!=)] = op_neq,
        [opidx(==)] = op_eq,
        [opidx(<)] = op_lt,
        [opidx(>)] = op_gt,
        [opidx(<=)] = op_lte,
        [opidx(>=)] = op_gte
};

#define FN_HNDLR(h, lop, p, d) (struct main_script){ \
        .hndlr = (h), \
        .pval = opidx(lop), \
        .pred = (p), \
        .desc = (d), \
}
