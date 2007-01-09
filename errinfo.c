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

#include <stdlib.h>
#include <string.h>

#include "dprint.h"
#include "errinfo.h"

/* global error info */
err_info_t _oser_err_info;

/**
 *
 */
err_info_t* get_err_info() { return &_oser_err_info; }

/**
 *
 */
void init_err_info()
{
	memset(&_oser_err_info, 0, sizeof(err_info_t));
}

/**
 *
 */
void set_err_info(int ec, int el, char *info)
{
	DBG("set_err_info: ec: %d, el: %d, ei: '%s'\n", ec, el,
			(info)?info:"");
	_oser_err_info.eclass = ec;
	_oser_err_info.level = el;
	if(info)
	{
		_oser_err_info.info.s   = info;
		_oser_err_info.info.len = strlen(info);
	}
}

/**
 *
 */
void set_err_reply(int rc, char *rr)
{
	_oser_err_info.rcode = rc;
	if(rr)
	{
		_oser_err_info.rreason.s   = rr;
		_oser_err_info.rreason.len = strlen(rr);
	}
}

