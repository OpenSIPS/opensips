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

#ifndef _OSP_MOD_DESTINATION_H_
#define _OSP_MOD_DESTINATION_H_

#include <time.h>
#include <osp/osp.h>
#include "osp_mod.h"

typedef struct _osp_dest {
    int type;
    unsigned int destcount;
    int supported;
    int used;
    int reported;
    unsigned long long transid;
    char validafter[OSP_STRBUF_SIZE];
    char validuntil[OSP_STRBUF_SIZE];
    char callid[OSP_STRBUF_SIZE];
    unsigned int callidsize;
    char calling[OSP_STRBUF_SIZE];
    char called[OSP_STRBUF_SIZE];
    char origcalled[OSP_STRBUF_SIZE];
    char srcdev[OSP_STRBUF_SIZE];
    char source[OSP_STRBUF_SIZE];
    char host[OSP_STRBUF_SIZE];
    char destdev[OSP_STRBUF_SIZE];
    char snid[OSP_STRBUF_SIZE];
    char dnid[OSP_STRBUF_SIZE];
    char nprn[OSP_STRBUF_SIZE];
    char npcic[OSP_STRBUF_SIZE];
    int npdi;
    char opname[OSPC_OPNAME_NUMBER][OSP_STRBUF_SIZE];
    char display[OSP_STRBUF_SIZE];
    char rpid[OSP_STRBUF_SIZE];
    char pai[OSP_STRBUF_SIZE];
    char divuser[OSP_STRBUF_SIZE];
    char divhost[OSP_STRBUF_SIZE];
    char pci[OSP_STRBUF_SIZE];
    unsigned char token[OSP_TOKENBUF_SIZE];
    unsigned int tokensize;
    unsigned int timelimit;
    OSPE_PROTOCOL_NAME protocol;
    int lastcode;
    time_t authtime;
    time_t time100;
    time_t time180;
    time_t time200;
} osp_dest;

int ospParseAvps(void);
osp_dest* ospInitDestination(osp_dest* dest);
int ospSaveOrigDestination(osp_dest* dest);
int ospSaveTermDestination(osp_dest* dest);
int ospCheckOrigDestination(void);
osp_dest* ospGetNextOrigDestination(void);
osp_dest* ospGetLastOrigDestination(void);
osp_dest* ospGetTermDestination(void);
void ospRecordEvent(int clientcode, int servercode);
void ospDumpDestination(osp_dest* dest);
void ospDumpAllDestination(void);
void ospConvertToOutAddress(const char* src, char* dest, int bufsize);
void ospConvertToInAddress(const char* src, char* dest, int bufsize);

#endif /* _OSP_MOD_DESTINATION_H_ */

