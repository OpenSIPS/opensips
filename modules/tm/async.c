/*
 * Copyright (C) 2014 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 *
 * history:
 * ---------
 *  2014-10-16  created (bogdan)
 */

#include "../../dprint.h"
#include "../../async.h"
#include "../../reactor_defs.h"


/* function triggered from reactor in order to continue the processing
 */
int t_resume_async(int fd, void *param)
{
	/* call the resume function (param) in order to read and handle data */

	/* start the resume_route[] */

	return 0;
}


int t_handle_async(struct sip_msg *msg, struct action* a , int resume_route)
{
	/* create transaction and save everything into transactio */

	/* run the function (the action) and get back from it the FD and resume function */

	/* place the FD + resume function (as param) into reactor */

	/* done, break the script */
	return 0;
}
