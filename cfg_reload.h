/*
 * Copyright (C) 2019 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#ifndef __OSS_CFG_RELOAD_H__
#define __OSS_CFG_RELOAD_H__

#define REACTOR_RELOAD_TAINTED_FLAG   (1<<1)

extern int _running_old_script;
extern int _have_old_script;

int init_script_reload(void);

int reload_routing_script(void);

/* sets as active the old/previous cfg (after a reload) */
void reload_swap_old_script(void);

/* sets as active the current cfg (after a reload) */
void reload_swap_current_script(void);

/* frees the in-memory old/previous script (after a reload) */
void reload_free_old_cfg(void);

#define pre_run_handle_script_reload(_flags) \
	do { \
		if ( _have_old_script && (_flags)&REACTOR_RELOAD_TAINTED_FLAG ) { \
			LM_DBG("triggered FD requires old/prev cfg, switching\n"); \
			reload_swap_old_script();\
			_running_old_script = 1; \
		} \
	}while(0)

#define post_run_handle_script_reload(_flags) \
	do { \
		if ( _have_old_script ) { \
			if ( _running_old_script ) {\
				reload_swap_current_script(); \
				_running_old_script = 0; \
			} \
			if (!reactor_check_app_flag(REACTOR_RELOAD_TAINTED_FLAG)) \
				reload_free_old_cfg(); \
		} \
	}while(0)



#endif /* __OSS_CFG_RELOAD_H__ */
