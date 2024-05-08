/*
 * AKA Authentication - Diameter Support
 *
 * Copyright (C) 2024 Razvan Crainea
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#ifndef AKA_AV_DIAMETER_MAR_H
#define AKA_AV_DIAMETER_MAR_H

#define AKA_AV_DM_APP_ID    16777216
#define AKA_AV_DM_VENDOR_ID 10415
#define AKA_AV_DM_MAR_CODE  303
#define AKA_AV_DM_MAA_CODE  303

#define AKA_AV_DM_SESSION "Session-Id"
#define AKA_AV_DM_ORIGIN_HOST "Origin-Host"
#define AKA_AV_DM_ORIGIN_REALM "Origin-Realm"
#define AKA_AV_DM_DST_REALM "Destination-Realm"
#define AKA_AV_DM_VENDOR_ID_S "Vendor-Id"
#define AKA_AV_DM_AUTH_APP_ID "Auth-Application-Id"
#define AKA_AV_DM_VENDOR_APP_ID "Vendor-Specific-Application-Id"
#define AKA_AV_DM_AUTH_SESS "Auth-Session-State"
#define AKA_AV_DM_USER_NAME "User-Name"
#define AKA_AV_DM_PUBLIC_ID "Public-Identity"
#define AKA_AV_DM_SERVER_NAME "Server-Name"
#define AKA_AV_DM_AUTH_ITEMS "3GPP-SIP-Number-Auth-Items"
#define AKA_AV_DM_AUTH_SCHEME "3GPP-SIP-Authentication-Scheme"
#define AKA_AV_DM_AUTH_ITEM "3GPP-SIP-Auth-Data-Item"
#define AKA_AV_DM_AUTH_ITEM_NO "3GPP-SIP-Item-Number"
#define AKA_AV_DM_AUTH_ITEM_AUTHENTICATE "3GPP-SIP-Authenticate"
#define AKA_AV_DM_AUTH_ITEM_AUTHORIZE "3GPP-SIP-Authorization"
#define AKA_AV_DM_AUTH_ITEM_CK "Confidentiality-Key"
#define AKA_AV_DM_AUTH_ITEM_IK "Integrity-Key"

#endif /* AKA_AV_DIAMETER_MAR_H */
