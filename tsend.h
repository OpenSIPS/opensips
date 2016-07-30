/*
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
 *  History:
 * --------
 *  2004-02-26  created by andrei
 */

#ifndef __tsend_h
#define __tsend_h


int tsend_stream(int fd, char* buf, unsigned int len, int timeout);
int tsend_dgram(int fd, char* buf, unsigned int len,
				const struct sockaddr* to, socklen_t tolen, int timeout);
int tsend_stream_ev(int fd, const struct iovec *iov, int iovcnt, int timeout);
int tsend_dgram_ev(int fd, const struct iovec* v, int count, int timeout);



#endif


