/*
 *$Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#ifndef _mod_fix_h_
#define _mod_fix_h_

int fixup_str_null(void** param, int param_no);
int fixup_str_str(void** param, int param_no);

int fixup_free_str_null(void** param, int param_no);
int fixup_free_str_str(void** param, int param_no);

int fixup_uint_null(void** param, int param_no);
int fixup_uint_uint(void** param, int param_no);

#if 0
int fixup_sint_null(void** param, int param_no);
int fixup_sint_sint(void** param, int param_no);
int fixup_sint_uint(void** param, int param_no);
int fixup_uint_sint(void** param, int param_no);
#endif

int fixup_regexp_null(void** param, int param_no);
int fixup_free_regexp_null(void** param, int param_no);
int fixup_regexp_none(void** param, int param_no);
int fixup_free_regexp_none(void** param, int param_no);

int pvar_fixup(void **param, int param_no);

int free_pvar_fixup(void** param, int param_no);

#endif
