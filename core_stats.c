/*
 * $Id$
 *
 * Copyright (C) 2006 Voice Sistem SRL
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * History:
 * ---------
 *  2006-01-23  first version (bogdan)
 */


#include <string.h>

#include "statistics.h"


#ifdef STATISTICS

stat_var* rcv_reqs;
stat_var* rcv_rpls;
stat_var* fwd_reqs;
stat_var* fwd_rpls;
stat_var* drp_reqs;
stat_var* drp_rpls;
stat_var* err_reqs;
stat_var* err_rpls;

stat_export_t core_stats[] = {
	{"rcv_requests" ,         0,  &rcv_reqs      },
	{"rcv_replies" ,          0,  &rcv_rpls      },
	{"fwd_requests" ,         0,  &fwd_reqs      },
	{"fwd_replies" ,          0,  &fwd_rpls      },
	{"drop_requests" ,        0,  &drp_reqs      },
	{"drop_replies" ,         0,  &drp_rpls      },
	{"err_requests" ,         0,  &err_reqs      },
	{"err_replies" ,          0,  &err_rpls      },
	{0,0,0}
};

#endif
