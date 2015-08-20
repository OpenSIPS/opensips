/*
 * Copyright (C) 2006-2007 VozTelecom Sistemas S.L
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
 */


int encode_via_body(char *hdr,int hdrlen,struct via_body *via_parsed,unsigned char *where);

int encode_via(char *hdrstart,int hdrlen,struct via_body *body,unsigned char *where);

int print_encoded_via_body(FILE *fp,char *hdr,int hdrlen,unsigned char *payload,int paylen,char *prefix);

int print_encoded_via(FILE *fp,char *hdr,int hdrlen,unsigned char* payload,int paylen,char *prefix);

int dump_via_body_test(char *hdr,int hdrlen,unsigned char *payload,int paylen,int fd,char segregationLevel);
