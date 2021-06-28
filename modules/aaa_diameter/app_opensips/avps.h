/*********************************************************************************************************
* Software License Agreement (BSD License)                                                               *
* Author: Liviu Chircu <liviu@opensips.org>								 *
*													 *
* Copyright (c) 2021, OpenSIPS Solutions								 *
* All rights reserved.											 *
* 													 *
* Redistribution and use of this software in source and binary forms, with or without modification, are  *
* permitted provided that the following conditions are met:						 *
* 													 *
* * Redistributions of source code must retain the above 						 *
*   copyright notice, this list of conditions and the 							 *
*   following disclaimer.										 *
*    													 *
* * Redistributions in binary form must reproduce the above 						 *
*   copyright notice, this list of conditions and the 							 *
*   following disclaimer in the documentation and/or other						 *
*   materials provided with the distribution.								 *
* 													 *
* * Neither the name of the WIDE Project or NICT nor the 						 *
*   names of its contributors may be used to endorse or 						 *
*   promote products derived from this software without 						 *
*   specific prior written permission of WIDE Project and 						 *
*   NICT.												 *
* 													 *
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED *
* WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A *
* PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR *
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 	 *
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 	 *
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR *
* TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF   *
* ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.								 *
*********************************************************************************************************/

#ifndef _APP_OPENSIPS_AVPS_H
#define _APP_OPENSIPS_AVPS_H

#ifndef FD_CHECK
#define __FD_CHECK(__call__, __retok__, __retval__) \
	do { \
		int __ret__; \
		__ret__ = (__call__); \
		if (__ret__ > 0) \
			__ret__ = -__ret__; \
		if (__ret__ != (__retok__)) { \
			fd_log_error("error in %s: %d\n", #__call__, __ret__); \
			return __retval__; \
		} \
	} while (0)
#define _FD_CHECK(__call__, __retok__) \
	__FD_CHECK((__call__), (__retok__), __ret__)
#define FD_CHECK(__call__) _FD_CHECK((__call__), 0)
#endif

#ifndef FD_CHECK_dict_new
#define FD_CHECK_dict_new(type, data, parent, ref) \
	FD_CHECK(fd_dict_new(fd_g_config->cnf_dict, (type), \
				(data), (parent), (ref)))
#endif

#ifndef FD_CHECK_dict_search
#define FD_CHECK_dict_search(type, criteria, what, result) \
	FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, (type), \
				(criteria), (what), (result), ENOENT))
#endif

int register_osips_avps(void);
int parse_extra_avps(const char *extra_avps_file);

#endif /* _APP_OPENSIPS_AVPS_H */
