/*
 * $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#ifndef CALC_H
#define CALC_H


#define HASHLEN 16
typedef char HASH[HASHLEN];


#define HASHHEXLEN 32
typedef char HASHHEX[HASHHEXLEN+1];


void CvtHex(HASH Bin, HASHHEX Hex);

/* 
 * calculate H(A1) as per HTTP Digest spec 
 */
void DigestCalcHA1(const char * pszAlg, const char * pszUserName, const char * pszRealm,
		   const char * pszPassword, const char * pszNonce, const char * pszCNonce,
		   HASHHEX SessionKey);

/* calculate request-digest/response-digest as per HTTP Digest spec */
void DigestCalcResponse(HASHHEX HA1,           /* H(A1) */
			const char * pszNonce,       /* nonce from server */
			const char * pszNonceCount,  /* 8 hex digits */
			const char * pszCNonce,      /* client nonce */
			const char * pszQop,         /* qop-value: "", "auth", "auth-int" */
			const char * pszMethod,      /* method from the request */
			const char * pszDigestUri,   /* requested URL */
			HASHHEX HEntity,       /* H(entity body) if qop="auth-int" */
			HASHHEX Response      /* request-digest or response-digest */);


#endif
