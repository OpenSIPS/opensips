/*
 * Usrloc contact structure
 *
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
 * ---------
 * 2003-03-12 added replication mark and three zombie states (nils)
 * 2005-07-11 added FL_NAT_SIPPING for nat pinging with SIP method
 *             instead of UDP package (bogdan)
 */

/*! \file
 *  \brief USRLOC - Usrloc contact structure
 *  \ingroup usrloc
 */


#ifndef UCONTACT_H
#define UCONTACT_H


#include <stdio.h>
#include <time.h>
#include "../../map.h"
#include "../../qvalue.h"
#include "../../str.h"
#include "../../proxy.h"
#include "../../db/db_insertq.h"



/*! \brief States for in-memory contacts in regards to contact storage handler (db, in-memory, ldap etc) */
typedef enum cstate {
	CS_NEW,        /*!< New contact - not flushed yet */
	CS_SYNC,       /*!< Synchronized contact with the database */
	CS_DIRTY       /*!< Update contact - not flushed yet */
} cstate_t;


/*! \brief
 * Flags that can be associated with a Contact
 */
typedef enum flags {
	FL_NONE        = 0,          /*!< No flags set */
	FL_MEM         = 1 << 0,     /*!< Update memory only */
	FL_ALL         = (int)0xFFFFFFFF  /*!< All flags set */
} flags_t;


/*! \brief
 * Main structure for handling of registered Contact: data
 */
typedef struct ucontact {
	uint64_t contact_id;	/*!< 64 bit Contact identifier
							  0-------0-------------0---------------0
							  |0 - 13 |   14 - 45   |    46 - 61    |
							  |aorhash| record label| contact label |
							  0-------0-------------0---------------0
							*/
	str* domain;            /*!< Pointer to domain name (NULL terminated) */
	str* aor;               /*!< Pointer to the AOR string in record structure*/
	str c;                  /*!< Contact address */
	str received;           /*!< IP+port+protocol we received the REGISTER from */
	str path;               /*!< Path header */
	time_t expires;         /*!< UNIX timestamp for the expiry */
	time_t expires_in;      /*!< Expires value from the initial request */
	time_t expires_out;     /*!< Expires value from the 200 OK reply */
	qvalue_t q;             /*!< q parameter */
	str instance;			/*!< instance parameter */
	str callid;             /*!< Call-ID header field of registration */
	int cseq;               /*!< CSeq value */
	cstate_t state;         /*!< State of the contact (\ref cstate) */
	unsigned int flags;     /*!< Various flags (NAT, ping type, etc) */
	unsigned int cflags;    /*!< Custom contact flags (from script) */
	str user_agent;         /*!< User-Agent header field */
	struct socket_info *sock; /*!< received socket */
	time_t last_modified;   /*!< When the record was last modified */
	unsigned int methods;   /*!< Supported methods */
	str attr;               /*!< Additional registration info  */
	struct proxy_l next_hop;/*!< SIP-wise determined next hop */
	unsigned int label;     /*!< label to find the contact in contact list>*/

	map_t kv_storage;       /*!< data attached by API subscribers >*/

	void **attached_data;   /*!< TODO del; data attached by API subscribers >*/

	struct ucontact* next;  /*!< Next contact in the linked list */
	struct ucontact* prev;  /*!< Previous contact in the linked list */
} ucontact_t;

typedef struct ucontact_info {
	uint64_t contact_id;	/*!< 64 bit Contact identifier
							  0-------0-------------0---------------0
							  |0 - 15 |   16 - 47   |    48 - 63    |
							  |aorhash| record label| contact label |
							  0-------0-------------0---------------0
							*/
	str received;
	str* path;
	time_t expires;
	time_t expires_in;
	time_t expires_out;
	qvalue_t q;
	str instance;
	str* callid;
	int cseq;
	unsigned int flags;
	unsigned int cflags;
	str *user_agent;
	struct socket_info *sock;
	unsigned int methods;
	time_t last_modified;
	str *attr;
} ucontact_info_t;

/*! \brief
 * ancient time used for marking the contacts forced to expired
 */
#define UL_EXPIRED_TIME 10

/*
 * Valid contact is a contact that either didn't expire yet or is permanent
 */
#define VALID_CONTACT(c, t)   ((c->expires>t) || (c->expires==0))


/*! \brief
 * Create a new contact structure
 */
ucontact_t*
new_ucontact(str* _dom, str* _aor, str* _contact,  ucontact_info_t* _ci);


/*! \brief
 * Free all memory associated with given contact structure
 */
void free_ucontact(ucontact_t* _c);


/*! \brief
 * Print contact, for debugging purposes only
 */
void print_ucontact(FILE* _f, ucontact_t* _c);


/*! \brief
 * Update existing contact in memory with new values
 */
int mem_update_ucontact(ucontact_t* _c, ucontact_info_t *_ci);


/* ===== State transition functions - for write back cache scheme ======== */


/*! \brief
 * Update state of the contact if we
 * are using write-back scheme
 */
void st_update_ucontact(ucontact_t* _c);


/*! \brief
 * Update state of the contact if we
 * are using write-back scheme
 * Returns 1 if the contact should be
 * deleted from memory immediately,
 * 0 otherwise
 */
int st_delete_ucontact(ucontact_t* _c);


/*! \brief
 * Called when the timer is about to delete
 * an expired contact, this routine returns
 * 1 if the contact should be removed from
 * the database and 0 otherwise
 */
int st_expired_ucontact(ucontact_t* _c);


/*! \brief
 * Called when the timer is about flushing the contact,
 * updates contact state and returns 1 if the contact
 * should be inserted, 2 if updated and 0 otherwise
 */
int st_flush_ucontact(ucontact_t* _c);


/* ==== Database related functions ====== */


/*! \brief
 * Insert contact into the database
 */
int db_insert_ucontact(ucontact_t* _c,query_list_t **ins_list, int update);


/*! \brief
 * Update contact in the database
 */
int db_update_ucontact(ucontact_t* _c);


/*! \brief
 * Delete contact from the database
 */
int db_delete_ucontact(ucontact_t* _c);

/*! \brief
 * Delete multiple contacts from the database
 * having the cids
 * WARNING: FL_MEM flag for a contact MUST be checked before
 * append a contact id to cids list
 */
int db_multiple_ucontact_delete(str *domain, db_key_t *keys,
										db_val_t *vals, int clen);


/* ====== Module interface ====== */

struct urecord;

/*! \brief
 * Update ucontact with new values
 */
typedef int (*update_ucontact_t)(struct urecord* _r, ucontact_t* _c,
		ucontact_info_t* _ci, char is_replicated);

int update_ucontact(struct urecord* _r, ucontact_t* _c, ucontact_info_t* _ci,
                    char is_replicated);

/*! \brief
 * Fetch a key from the contact-level storage
 * NOTE: assumes the corresponding udomain lock is properly acquired
 *
 * Returns: NULL on error/key not found, value pointer otherwise
 */
typedef int_str_t *(*get_ucontact_key_t)(ucontact_t* _ct,
                                         const str* _key);

int_str_t *get_ucontact_key(ucontact_t* _ct, const str* _key);

/*! \brief
 * Create or re-assign a key-value pair within contact-level storage.
 *   ("_key" and "_val" are fully duplicated in shared memory)
 *
 * NOTE: assumes the corresponding udomain lock is properly acquired
 *
 * Returns: NULL on error, new value pointer otherwise
 */
typedef int_str_t *(*put_ucontact_key_t)(ucontact_t* _ct,
                                    const str* _key, const int_str_t* _val);

int_str_t *put_ucontact_key(ucontact_t* _ct, const str* _key,
                            const int_str_t* _val);

#endif /* UCONTACT_H */
