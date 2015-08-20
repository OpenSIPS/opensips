/*
 * back-to-back logic module
 *
 * Copyright (C) 2009 Free Software Fundation
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
 *  2009-08-03  initial version (Anca Vamanu)
 */

#ifndef _B2BL_PIDF_H_
#define _B2BL_PIDF_H_

unsigned char *xmlNodeGetAttrContentByName(xmlNodePtr node, const char *name);

xmlNodePtr xmlNodeGetChildByName(xmlNodePtr node, const char *name);

xmlNodePtr xmlDocGetNodeByName(xmlDocPtr doc, const char *name, const char *ns);

char *xmlNodeGetNodeContentByName(xmlNodePtr root, const char *name,
		const char *ns);

#endif
