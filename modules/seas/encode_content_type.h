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


int encode_content_type(char *hdrstart,int hdrlen,unsigned int bodi,char *where);

int encode_accept(char *hdrstart,int hdrlen,unsigned int *bodi,char *where);

int encode_mime_type(char *hdrstart,int hdrlen,unsigned int bodi,char *where);

int print_encoded_mime_type(FILE *fp,char *hdr,int hdrlen,unsigned int* payload,int paylen,char *prefix);

int print_encoded_content_type(FILE *fp,char *hdr,int hdrlen,unsigned char* payload,int paylen,char *prefix);

int print_encoded_accept(FILE *fp,char *hdr,int hdrlen,unsigned char* payload,int paylen,char *prefix);
