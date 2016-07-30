/*
 * mem (malloc) info
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
/*
 * History:
 * --------
 *  2005-03-02  created (andrei)
 *  2006-01-05  renamed meminfo to mem_info due to name conflict on solaris
 */

#ifndef meminfo_h
#define meminfo_h

struct mem_info{
	unsigned long total_size;
	unsigned long free;
	unsigned long used;
	unsigned long real_used; /*used + overhead*/
	unsigned long max_used;
	unsigned long min_frag;
	unsigned long total_frags; /* total fragment no */
};

#if defined(PKG_MALLOC) && defined(STATISTICS)
// threshold percentage checked
extern long event_pkg_threshold;
// events are used only if STATISTICS are used
void pkg_threshold_check(void);
#else
 #define pkg_threshold_check()
#endif /* STATISTICS */


#endif

