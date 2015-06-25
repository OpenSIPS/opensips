/*
 * opensips osp module.
 *
 * This module enables opensips to communicate with an Open Settlement
 * Protocol (OSP) server.  The Open Settlement Protocol is an ETSI
 * defined standard for Inter-Domain VoIP pricing, authorization
 * and usage exchange.  The technical specifications for OSP
 * (ETSI TS 101 321 V4.1.1) are available at www.etsi.org.
 *
 * Uli Abend was the original contributor to this module.
 *
 * Copyright (C) 2001-2005 Fhg Fokus
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _OSP_MOD_ORIG_TRANSACTION_H_
#define _OSP_MOD_ORIG_TRANSACTION_H_

#include "../../parser/msg_parser.h"
#include "osp_mod.h"

typedef struct _osp_inbound {
    char source[OSP_STRBUF_SIZE];
    char srcdev[OSP_STRBUF_SIZE];
    char snid[OSP_STRBUF_SIZE];
    char display[OSP_STRBUF_SIZE];
    char rpid[OSP_STRBUF_SIZE];
    char pai[OSP_STRBUF_SIZE];
    char divuser[OSP_STRBUF_SIZE];
    char divhost[OSP_STRBUF_SIZE];
    char pci[OSP_STRBUF_SIZE];
} osp_inbound;

int ospRequestRouting(struct sip_msg*, char*, char*);
int ospCheckRoute(struct sip_msg*, char*, char*);
int ospPrepareRoute(struct sip_msg*, char*, char*);
int ospPrepareRedirectRoutes(struct sip_msg*, char*, char*);
int ospPrepareAllRoutes(struct sip_msg*, char*, char*);
int ospCheckCalling(struct sip_msg*, char*, char*);

#endif /* _OSP_MOD_ORIG_TRANSACTION_H_ */

