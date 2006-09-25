/*
 *$Id$
 *
 * - various general purpose functions
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
 *
 * History
 * ------
 * 2006-09-25  created by movind user2uid and group2gid from main.c (bogdan)
 */


#include <stdlib.h>
#include <pwd.h>
#include <grp.h>

/* converts a username into uid:gid,
 * returns -1 on error & 0 on success */
int user2uid(int* uid, int* gid, char* user)
{
	char* tmp;
	struct passwd *pw_entry;
	
	if (user){
		*uid=strtol(user, &tmp, 10);
		if ((tmp==0) ||(*tmp)){
			/* maybe it's a string */
			pw_entry=getpwnam(user);
			if (pw_entry==0){
				goto error;
			}
			*uid=pw_entry->pw_uid;
			if (gid) *gid=pw_entry->pw_gid;
		}
		return 0;
	}
error:
	return -1;
}


int group2gid(int* gid, char* group)
{
	char* tmp;
	struct group  *gr_entry;
	
	if (group){
		*gid=strtol(group, &tmp, 10);
		if ((tmp==0) ||(*tmp)){
			/* maybe it's a string */
			gr_entry=getgrnam(group);
			if (gr_entry==0){
				goto error;
			}
			*gid=gr_entry->gr_gid;
		}
		return 0;
	}
error:
	return -1;
}

