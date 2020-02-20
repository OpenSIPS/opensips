/*
 * Copyright (C) 2019 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
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
 *
 */

#ifndef _PRES_DFKS_H_
#define _PRES_DFKS_H_

#include "../../msg_translator.h"

#define DFKS_EVENT_NAME_S "as-feature-event"
#define DFKS_EVENT_NAME_LEN (sizeof(DFKS_EVENT_NAME_S)-1)

#define DEFAULT_GET_ROUTE_NAME "dfks_get"
#define DEFAULT_SET_ROUTE_NAME "dfks_set"

#define FEATURE_DND_NAME "DoNotDisturb"
#define FEATURE_CFA_NAME "CallForwardingAlways"
#define FEATURE_CFB_NAME "CallForwardingBusy"
#define FEATURE_CFNA_NAME "CallForwardingNoAnswer"

#define BASE_FEATURES_NO 4
#define MAX_FEATURES_NO 16
#define MAX_VALUES_NO 8

#define PV_SUBNAME_ASSIGN "assigned"
#define PV_SUBNAME_STATUS "status"
#define PV_SUBNAME_VALUE "value/"
#define PV_SUBNAME_VALUE_LEN (sizeof(PV_SUBNAME_VALUE)-1)
#define PV_SUBNAME_FEATURE "feature"
#define PV_SUBNAME_PRESENTITY "presentity"
#define PV_SUBNAME_NOTIFY "notify"
#define PV_SUBNAME_PARAM "param"

#define PV_TYPE_ASSIGN 0
#define PV_TYPE_STATUS 1
#define PV_TYPE_VALUE 2
#define PV_TYPE_FEATURE 3
#define PV_TYPE_PRESENTITY 4
#define PV_TYPE_NOTIFY 5
#define PV_TYPE_PARAM 6

#define CT_TYPE_MULTIPART "multipart/mixed;boundary=" OSS_BOUNDARY
#define CT_TYPE_MULTIPART_LEN (sizeof(CT_TYPE_MULTIPART)-1)
#define CT_TYPE_DFKS "application/x-as-feature-event+xml"
#define CT_TYPE_DFKS_LEN (sizeof(CT_TYPE_DFKS)-1)
#define CT_TYPE_DFKS_HDR "Content-Type: " CT_TYPE_DFKS
#define CT_TYPE_DFKS_HDR_LEN (sizeof(CT_TYPE_DFKS_HDR)-1)
#define MULTIPART_BOUNDARY "--" OSS_BOUNDARY
#define MULTIPART_BOUNDARY_LEN (sizeof(MULTIPART_BOUNDARY)-1)
#define MULTIPART_BOUNDARY_END "--" OSS_BOUNDARY "--"
#define MULTIPART_BOUNDARY_END_LEN (sizeof(MULTIPART_BOUNDARY_END)-1)

#define XML_VERSION_STR "1.0"
#define DFKS_NS_STR "http://www.ecmainternational.org/standards/ecma-323/csta/ed3"
#define XML_ENC "ISO-8859-1"

#define DEVICE_NODE_NAME "device"
#define DEVICE_NODE_MAGIC_VAL "9995060044"
#define RESP_ROOT_NODE_DND "DoNotDisturbEvent"
#define REQ_ROOT_NODE_DND "SetDoNotDisturb"
#define RESP_ROOT_NODE_FWD "ForwardingEvent"
#define REQ_ROOT_NODE_FWD "SetForwarding"
#define STATUS_NODE_DND "doNotDisturbOn"
#define RESP_STATUS_NODE_FWD "forwardStatus"
#define REQ_STATUS_NODE_FWD "activateForward"
#define RESP_VALUE_NODE_FWD "forwardTo"
#define REQ_VALUE_NODE_FWD "forwardDN"
#define VALUE_NODE_RING "ringCount"
#define TYPE_NODE_FWD "forwardingType"
#define TYPE_VAL_FWD_CFA "forwardImmediate"
#define TYPE_VAL_FWD_CFB "forwardBusy"
#define TYPE_VAL_FWD_CFNA "forwardNoAns"
#define STATUS_VAL_TRUE "true"
#define STATUS_VAL_FALSE "false"


struct dfks_ctx {
	int assigned;
	int notify;
	int status;
	int idx;
	str pres_uri;
	str values[MAX_VALUES_NO];
	str param;
};

struct dfks_ipc_params {
	str pres_uri;
	str values[MAX_VALUES_NO];
	int feature_idx;
	int status;
	str param;
};

struct dfks_pv_name {
	int type;
	str value_node;
};

#endif
