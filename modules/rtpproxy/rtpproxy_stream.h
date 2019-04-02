/*
 * Copyright (C) 2008 Sippy Software, Inc., http://www.sippysoft.com
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 */

#ifndef _RTPPROXY_STREAM_H
#define  _RTPPROXY_STREAM_H

int rtpproxy_stream2uac4_f(struct sip_msg* msg, str *pname, int *count,
                nh_set_param_t *setid, pv_spec_t *var);
int rtpproxy_stream2uas4_f(struct sip_msg* msg, str *pname, int *count,
                nh_set_param_t *setid, pv_spec_t *var);
int rtpproxy_stop_stream2uac2_f(struct sip_msg* msg, nh_set_param_t *setid, pv_spec_t *var);
int rtpproxy_stop_stream2uas2_f(struct sip_msg* msg, nh_set_param_t *setid, pv_spec_t *var);

#endif
