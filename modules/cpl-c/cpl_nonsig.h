/*
 * $Id$
 *
 * Copyright (C) 2001-2003 Fhg Fokus
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * -------
 * 2003-06-27: file created (bogdan)
 */

#ifndef _CPL_NONSIG_H_
#define _CPL_NONSIG_H_

#include <unistd.h>

#include "../../str.h"

struct cpl_cmd {
	unsigned int code;
	str s1;
	str s2;
	str s3;
};


#define CPL_LOG_CMD    1
#define CPL_MAIL_CMD   2

#define MAX_LOG_DIR_SIZE    256


extern int cpl_cmd_pipe[2];


void cpl_aux_process( int cmd_out, char *log_dir);


static inline void write_cpl_cmd(unsigned int code, str *s1, str *s2, str *s3)
{
	static struct cpl_cmd cmd;

	cmd.code = code;
	cmd.s1 = *s1;
	cmd.s2 = *s2;
	cmd.s3 = *s3;

	if (write( cpl_cmd_pipe[1], &cmd, sizeof(struct cpl_cmd) )==-1)
		LOG(L_ERR,"ERROR:cpl_c:write_cpl_cmd: write ret: %s\n",
			strerror(errno));
}



#endif
