/*
 * Copyright (C) 2001-2003 FhG Fokus
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
 *
 * History:
 * --------
 * 2003-04-05  DEFAULT_*_URL introduced (jiri)
 * 2003-07-04  fixed SRV lookup prefix for TLS/sips (andrei)
 * 2007-02-16  Added an OPENSER_OID define to localize OpenSER's IANA assigned
 *             OID under the enterprise branch (jmagder)
 * 2013-09-17  TLS_DH_PARAMS_FILE added (mehmet)
 */

/*!
 * \file
 * \brief Main Configuration settings
 */


#ifndef config_h
#define config_h

#define SIP_PORT  5060		/*!< default sip port if none specified */
#define SIPS_PORT 5061		/*! default sip port for tls if none specified */

#define CFG_FILE CFG_DIR "opensips.cfg"
#define MEM_WARMING_DEFAULT_PATTERN_FILE CFG_DIR "mem_warming_pattern"
#define MEM_WARMING_DEFAULT_PERCENTAGE 75
#define RESTART_PERSISTENCY_MEM_FILE ".restart_persistency.cache"

#define TLS_PKEY_FILE CFG_DIR "tls/ckey.pem"
#define TLS_CERT_FILE CFG_DIR "tls/cert.pem"
#define TLS_CA_FILE 0 		/*!< no CA list file by default */
#define TLS_CA_DIRECTORY      "/etc/pki/CA/"
#define TLS_DH_PARAMS_FILE 0   /*!< no DH params file by default */

#define MAX_LISTEN 16		/*!< maximum number of addresses on which we will listen */

#define UDP_WORKERS_NO    8		/*!< default number of UDP workers started */

/*! \brief maximum allowed execution time of a high-priority, graceful
 *    shutdown job broadcast before the attendant process SIGKILLs any
 *    remaining workers
 */
#define GRACEFUL_SHUTDOWN_TIMEOUT    5 /* sec */

/*! \brief overall maximum shutdown time (graceful shutdown + all cleanups) */
#define SHUTDOWN_TIMEOUT    60 /* sec */

#define RT_NO 100 		/*!< routing tables number */
#define FAILURE_RT_NO RT_NO	/*!< on_failure routing tables number */
#define ONREPLY_RT_NO RT_NO	/*!< on_reply routing tables number */
#define BRANCH_RT_NO  RT_NO 	/*!< T-branch routing tables number */
#define TIMER_RT_NO   RT_NO 	/*!< Timer routing tables number */
#define EVENT_RT_NO   RT_NO 	/*!< Event routing tables number */
#define DEFAULT_RT 0 		/*!< default routing table */

#define MAX_REC_LEV 100		/*!< maximum number of recursive calls */
#define ROUTE_MAX_REC_LEV 100 /*!< maximum number of recursive calls for route()*/

#define MAX_URI_SIZE 1024	/*!< used when rewriting URIs */

#define MAX_PATH_SIZE 255	/*!< maximum length of Path header */

#define MY_VIA "Via: SIP/2.0/UDP "
#define MY_VIA_LEN (sizeof(MY_VIA) - 1)

#define CONTENT_LENGTH "Content-Length: "
#define CONTENT_LENGTH_LEN (sizeof(CONTENT_LENGTH)-1)

#define USER_AGENT "User-Agent: OpenSIPS (" VERSION " (" ARCH "/" OS"))"		/*!< Default User-Agent header */
#define USER_AGENT_LEN (sizeof(USER_AGENT)-1)

#define SERVER_HDR "Server: OpenSIPS (" VERSION " (" ARCH "/" OS"))"		/*!< Default Server: header */
#define SERVER_HDR_LEN (sizeof(SERVER_HDR)-1)

#define MAX_WARNING_LEN  256

#define MY_BRANCH ";branch="
#define MY_BRANCH_LEN (sizeof(MY_BRANCH) - 1)

#define MAX_PORT_LEN 7 /*!< ':' + max 5 letters + \\0 */
#define CRLF "\r\n"
#define CRLF_LEN (sizeof(CRLF) - 1)

#define RECEIVED        ";received="
#define RECEIVED_LEN (sizeof(RECEIVED) - 1)

#define TRANSPORT_PARAM ";transport="
#define TRANSPORT_PARAM_LEN (sizeof(TRANSPORT_PARAM) - 1)

#define TOTAG_TOKEN ";tag="
#define TOTAG_TOKEN_LEN (sizeof(TOTAG_TOKEN)-1)

#define RPORT ";rport="
#define RPORT_LEN (sizeof(RPORT) - 1)

#define ID_PARAM ";i="
#define ID_PARAM_LEN (sizeof(ID_PARAM) - 1)

#define SRV_UDP_PREFIX "_sip._udp."
#define SRV_UDP_PREFIX_LEN (sizeof(SRV_UDP_PREFIX) - 1)

#define SRV_TCP_PREFIX "_sip._tcp."
#define SRV_TCP_PREFIX_LEN (sizeof(SRV_TCP_PREFIX) - 1)

#define SRV_SCTP_PREFIX "_sip._sctp."
#define SRV_SCTP_PREFIX_LEN (sizeof(SRV_SCTP_PREFIX) - 1)

#define SRV_TLS_PREFIX "_sips._tcp."
#define SRV_TLS_PREFIX_LEN (sizeof(SRV_TLS_PREFIX) - 1)

#define SRV_WS_PREFIX "_ws._tcp."
#define SRV_WS_PREFIX_LEN (sizeof(SRV_WS_PREFIX) - 1)

#define SRV_WSS_PREFIX "_wss._tcp."
#define SRV_WSS_PREFIX_LEN (sizeof(SRV_WSS_PREFIX) - 1)

#define SRV_MAX_PREFIX_LEN SRV_TLS_PREFIX_LEN

#ifdef HP_MALLOC
#define PKG_MEM_SIZE 16				/*!< Used only if PKG_MALLOC is defined*/
#else
#define PKG_MEM_SIZE 2				/*!< Used only if PKG_MALLOC is defined*/
#endif
#define SHM_MEM_SIZE 32				/*!< Used if SH_MEM is defined*/
#define SHM_MAX_SECONDARY_HASH_SIZE 32
#define DEFAULT_SHM_HASH_SPLIT_PERCENTAGE 1	/*!< Used if SH_MEM is defined*/
#define DEFAULT_SHM_SECONDARY_HASH_SIZE 8

#define TIMER_TICK   1  			/*!< one second */
#define UTIMER_TICK  100*1000			/*!< 100 milliseconds*/

/*!< dimensioning buckets in q_malloc
	 size of the size2bucket table; everything beyond that asks for
   	a variable-size kilo-bucket
 */
#define MAX_FIXED_BLOCK   3072

#define BLOCK_STEP        512			/*!< distance of kilo-buckets */
#define MAX_BUCKET        15			/*!< maximum number of possible buckets */

/*! \brief receive buffer size
	\note preferably set low to avoid terror of excessively huge messages; they are
   		useless anyway
*/
#define BUF_SIZE 65535

/*!< forwarding  -- Via buffer dimensioning */
#define MAX_VIA_LINE_SIZE	240
#define MAX_RECEIVED_SIZE	57
#define MAX_RPORT_SIZE		13

#define MAX_BRANCHES    12			/*!< maximum number of branches per transaction */

#define MCOOKIE "z9hG4bK"			/*!< magic cookie for transaction matching as defined in RFC3261 */
#define MCOOKIE_LEN (sizeof(MCOOKIE)-1)

/*! \brief Maximum length of values appended to Via-branch parameter */
#define MAX_BRANCH_PARAM_LEN  (MCOOKIE_LEN+8 /*!<int2hex*/ + 1 /*sep*/ + \
								MD5_LEN + 1 /*!<sep*/ + 8 /*int2hex*/ + \
								1 /*extra space, needed by t_calc_branch*/)

#define PATH_MAX_GUESS	1024			/*!< maximum path length */

#define VERSION_TABLE     "version" 		/*!< Table holding versions of other opensips tables */
#define VERSION_COLUMN    "table_version"	/*!< Column name for the version value in version table */
#define TABLENAME_COLUMN  "table_name"		/*!< Column name of the table name column in the version table */

#define MIN_UDP_PACKET        20		/*!< minimum packet size; smaller packets will be dropped silently */

#define OPENSER_OID   1,3,6,1,4,1,27483

#endif
