/*
 * back-to-back entities module
 *
 * Copyright (C) 2011 Free Software Fundation
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
 * --------
 *  2011-04-04  initial version (Anca Vamanu)
 */

#ifndef  _B2BE_DB_H_
#define  _B2BE_DB_H_

#include "dlg.h"

void b2b_entities_dump(int no_lock);
int b2b_entities_restore(void);
int b2be_db_insert(b2b_dlg_t* dlg, int type);
int b2be_db_update(b2b_dlg_t* dlg, int type);
void b2be_initialize(void);
void b2b_db_delete(str param);
void b2b_entity_db_delete(int type, b2b_dlg_t* dlg);

#define UPDATE_DBFLAG(dlg) do{ \
	if(b2be_db_mode == WRITE_BACK && dlg->db_flag==NO_UPDATEDB_FLAG) \
			dlg->db_flag = UPDATEDB_FLAG; \
	} while(0)

#endif
