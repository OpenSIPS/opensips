/*
 * Web3 Authentication - API Header
 *
 * Copyright (C) 2025 Cellact B.V.
 *
 * This file is part of OpenSIPS, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * OpenSIPS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * OpenSIPS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef WEB3_AUTH_API_H
#define WEB3_AUTH_API_H

#include "../../parser/digest/digest.h"
#include "../../parser/msg_parser.h"
#include "../../parser/hf.h"
#include "../../str.h"

/**
 * @brief Web3 Authentication API structure
 * 
 * This structure provides function pointers for Web3-based authentication
 * operations. Other OpenSIPS modules can bind to this API to use Web3
 * authentication functionality.
 */
typedef struct web3_auth_api {
	/**
	 * Digest authentication function
	 * 
	 * @param msg SIP message
	 * @param realm Authentication realm
	 * @param hftype Header field type (Authorization or Proxy-Authorization)
	 * @param rmethod SIP method
	 * @return 1 on success, -1 on failure
	 */
	int (*digest_authenticate)(struct sip_msg *msg, str *realm,
	                           hdr_types_t hftype, str *rmethod);
	
	/**
	 * Check authentication response
	 * 
	 * @param cred Digest credentials
	 * @param method SIP method
	 * @return 1 on success, -1 on failure
	 */
	int (*check_response)(dig_cred_t *cred, str *method);
	
} web3_auth_api_t;

/**
 * @brief Bind Web3 authentication API
 * 
 * This function binds the Web3 authentication API to the provided structure.
 * Other modules should call this function to access Web3 authentication
 * functionality.
 * 
 * @param api Pointer to API structure to fill
 * @return 0 on success, -1 on error
 */
typedef int (*bind_web3_auth_t)(web3_auth_api_t* api);
int bind_web3_auth(web3_auth_api_t* api);

#endif /* WEB3_AUTH_API_H */

