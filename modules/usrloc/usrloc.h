/*
 * Convenience usrloc header file
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
 */

/*! \file
 *  \brief USRLOC - Convenience usrloc header file
 *  \ingroup usrloc
 */

#ifndef USRLOC_H
#define USRLOC_H


#include "dlist.h"
#include "udomain.h"
#include "urecord.h"
#include "ucontact.h"
#include "ul_callback.h"
#include "ul_dbg.h"

typedef enum ul_cluster_mode {
	CM_NONE,
	CM_FEDERATION,
	CM_FEDERATION_CACHEDB,
	CM_FULL_SHARING,
	CM_FULL_SHARING_CACHEDB,
	CM_SQL_ONLY,
} ul_cluster_mode_t;

/* XXX: deprecated! */
enum usrloc_modes {
	NOT_SET       = -1,

	NO_DB         = 0,
	WRITE_THROUGH = 1,
	WRITE_BACK    = 2,
	DB_ONLY       = 3,
};

typedef struct usrloc_api {
	int use_domain;

	enum ul_cluster_mode cluster_mode;

	/* whether the user location caches contacts in OpenSIPS memory */
	int (*have_mem_storage) (void);

	/* whether the user location makes use of contact ownership tags */
	int (*tags_in_use) (void);

	/* the NAT branch flag, as bitmask */
	unsigned int nat_flag;

	/**
	 * Register a new usrloc domain.  If the domain already exists, a pointer
	 * to an existing structure will be returned.
	 *   NOTE: may only be called before forking! (e.g., during mod_init())
	 *
	 * @name: name of the new domain (if using a DB, it is also the table name)
	 * @d: output variable holding the domain
	 *
	 * Return: 0 (success), negative otherwise
	 */
	int (*register_udomain) (const char *name, udomain_t **d);

	/**
	 * Lock/Unlock the hash table entry of the given Address-of-Record.
	 *   NOTE: you MUST always lock an AoR before using any AoR or contact
	 *         manipulation functions of this API.
	 *
	 * @d: the usrloc domain to use
	 * @aor: the AoR to grab/release the entry for
	 */
	void (*lock_udomain) (udomain_t *d, str *aor);
	void (*unlock_udomain) (udomain_t *d, str *aor);

	/**
	 * Fetch a given AoR from an usrloc domain.
	 *   NOTE: remember to @release_urecord() when you are done with it!
	 *
	 * @d: the domain to search within
	 * @aor: the AoR to fetch
	 * @r: will hold the returned object if found, NULL otherwise
	 *
	 * Return: 0 (found), 1 (not found) otherwise
	 */
	int (*get_urecord) (udomain_t *d, str *aor, struct urecord **r);

	/**
	 * Fetch a given AoR from an usrloc domain, across multiple locations.
	 * Thus, this function is only relevant when using
	 * cluster_mode == CM_FEDERATION_CACHEDB.  The function will return success
	 * if the AoR exists in at least one location.
	 *
	 * @d: the domain to search within
	 * @aor: the AoR to fetch
	 * @r: will hold the returned object if found, NULL otherwise
	 *
	 * Return: 0 (found), 1 (not found) otherwise
	 */
	int (*get_global_urecord) (udomain_t *d, str *aor, struct urecord **r);

	/**
	 * Release an (urecord_t) object previously obtained through either
	 * @get_urecord or @get_global_urecord.
	 *
	 * @r: the usrloc record to release
	 * @skip_replication: set to true in order to avoid replicating an AoR
	 *                    deletion event, if any, to neighboring cluster nodes
	 */
	void (*release_urecord) (urecord_t *r, char skip_replication);

	/**
	 * Create and insert a new Address-of-Record into the given domain.
	 *   NOTE: will leak shared memory if the record already exists!  Use
	 *         @get_urecord accordingly beforehand to prevent this.
	 *
	 * @d: the domain to insert the record into
	 * @aor: the AoR to insert
	 * @r: will hold the newly created object
	 * @skip_replication: set to true in order to avoid replicating an AoR
	 *                    insertion event to neighboring cluster nodes
	 *
	 * Return: 0 (success), negative otherwise
	 */
	int (*insert_urecord) (udomain_t *d, str *aor, struct urecord **r,
	                       char skip_replication);

	/**
	 * Fetch a key from record-level storage.
	 *   NOTE: remember to lock the urecord beforehand.
	 *
	 * @r: the record to search into
	 * @key: the key to locate
	 *
	 * Return: NULL on error/key not found, value pointer otherwise
	 */
	int_str_t *(*get_urecord_key) (urecord_t *r, const str *key);

	/**
	 * Create or re-assign a key-value pair within record-level storage.
	 *   NOTES:
	 *      - remember to lock the urecord beforehand
	 *      - both @key and @val will be duplicated in shared memory
	 *
	 * @r: the record to search into
	 * @key: the key to locate
	 * @val: the value to set
	 *
	 * Return: NULL on error, new value pointer otherwise
	 */
	int_str_t *(*put_urecord_key) (urecord_t *r, const str *key,
	                               const int_str_t *val);

	/**
	 * Delete a given AoR from an usrloc domain, along with all of its
	 * contacts.
	 *
	 * @d: the domain to search within
	 * @aor: the AoR to delete
	 * @r: optional, if available -- the exact object to delete
	 * @skip_replication: set to true in order to avoid replicating deletion
	 *                    events to neighboring cluster nodes for both contact
	 *                    and AoR deletions
	 *
	 * Return: 0 (success), negative otherwise
	 */
	int (*delete_urecord) (udomain_t *d, str *aor, struct urecord *r,
	                       char skip_replication);

	/**
	 * Match a contact against a list of contacts stored in an usrloc record.
	 *
	 * @r: the usrloc record to search for the contact
	 * @ct_uri: the contact URI to search
	 * @callid: the SIP Call-ID of the pending REGISTER message
	 * @cseq: the SIP CSeq of the pending REGISTER message
	 * @match: how to match the contact against existing bindings
	 * @c: will hold the returned contact if found or NULL
	 *
	 * Return:
	 *   0 - contact found and returned in @c
	 *   1 - contact not found
	 *  -1 - contact found, however the given @cseq is too old and you
	 *       should ignore this REGISTER
	 *  -2 - contact found, however the given @cseq is equal to the existing
	 *       one, so you should ignore this REGISTER (is it a retransmission?)
	 */
	int (*get_ucontact) (urecord_t *r, str *ct_uri, str *callid, int cseq,
	                     const struct ct_match *match, ucontact_t **c);

	/**
	 * Fetch a ucontact from an usrloc domain using a contact ID.
	 *   NOTE: on success, the urecord *lock will be grabbed*!
	 *         Remember to @release_urecord, followed by @unlock_udomain!
	 *
	 * @d: the domain to search within
	 * @id: the contact ID, a 64-bit unsigned integer
	 * @r: will hold the contact's usrloc record, if found
	 *
	 * Return:
	 *   NULL, if contact not found
	 *   pointer to the contact, if found
	 */
	ucontact_t *(*get_ucontact_from_id) (udomain_t *d,
	                                     ucontact_id id, urecord_t **r);

	/**
	 * Create and add a new contact to the list of contacts in @r.  If
	 * @desc_time_order is on, the contact will be simply appended at the head
	 * of the list (most recent), otherwise in descending q-value order.
	 *
	 * @r: the usrloc record of the contact
	 * @ct_uri: the SIP URI of the contact
	 * @ci: various info pertaining to the contact, extract from the REGISTER
	 *      message (and not only!)
	 * @match: Required if @skip_replication is false, in order to instruct
	 *      the replicas on how to match this contact
	 * @skip_replication: set to true in order to avoid replicating an "insert"
	 *                    event to neighboring cluster nodes
	 * @c: will hold the output contact, once created
	 *
	 * Return: 0 (success), negative otherwise
	 */
	int (*insert_ucontact) (urecord_t *r, str *ct_uri, ucontact_info_t *ci,
	                      const struct ct_match *match, char skip_replication,
	                      ucontact_t **c);

	/**
	 * Update the info of an existing usrloc contact, possibly on a re-REGISTER
	 *
	 * @r: the usrloc record of the contact
	 * @c: the usrloc contact to update
	 * @ci: various info pertaining to the contact to update
	 * @match: Required if @skip_replication is false, in order to instruct
	 *      the replicas on how to match this contact
	 * @skip_replication: set to true in order to avoid replicating an "update"
	 *                    event to neighboring cluster nodes
	 *
	 * Return: 0 (success), negative otherwise
	 */
	int (*update_ucontact) (urecord_t *r, ucontact_t *c, ucontact_info_t *ci,
	                      const struct ct_match *match, char skip_replication);

	/**
	 * Fetch a key from contact-level storage.
	 *   NOTE: remember to lock the urecord beforehand.
	 *
	 * @c: the usrloc contact to search into
	 * @key: the key to locate
	 *
	 * Return: NULL on error/key not found, value pointer otherwise
	 */
	int_str_t *(*get_ucontact_key) (ucontact_t *c, const str *key);

	/**
	 * Create or re-assign a key-value pair within contact-level storage.
	 *   NOTES:
	 *      - remember to lock the urecord beforehand
	 *      - both @key and @val will be duplicated in shared memory
	 *
	 * @c: the usrloc contact to search into
	 * @key: the key to locate
	 * @val: the value to set
	 *
	 * Return: NULL on error, new value pointer otherwise
	 */
	int_str_t *(*put_ucontact_key) (ucontact_t *c, const str *key,
	                                const int_str_t *val);

	/**
	 * Delete a contact from a given usrloc record.
	 *
	 * @r: the usrloc record
	 * @c: the usrloc contact to delete
	 * @skip_replication: set to true in order to avoid replicating a "delete"
	 *                    event to neighboring cluster nodes
	 *
	 * Return: 0 (success), negative otherwise
	 */
	int (*delete_ucontact) (urecord_t *r, ucontact_t *c,
	                      const struct ct_match *match, char skip_replication);

	/**
	 * Delete a contact from a given usrloc domain, using its hash table or
	 * SIP coordinates.
	 *
	 * @d: the usrloc domain to search within
	 * @coords: the contact ID or SIP coordinates of the contact
	 *          (see @ucontact_coords for more info)
	 * @skip_replication: set to true in order to avoid replicating a "delete"
	 *                    event to neighboring cluster nodes
	 *
	 * Return: 0 (success), negative otherwise
	 */
	int (*delete_ucontact_from_coords) (udomain_t *d, ucontact_coords coords,
	                                    char skip_replication);

	/**
	 * Compare @ucontact_coords structs @a and @b.
	 *
	 * Return: 0 if equal, -1 otherwise
	 */
	int (*ucontact_coords_cmp) (ucontact_coords a, ucontact_coords b);

	/**
	 * Free an @ucontact_coords object.
	 */
	void (*free_ucontact_coords) (ucontact_coords coords);

	/**
	 * Check if an ucontact is logically owned by the current OpenSIPS node.
	 * Always returns true in single node setups or if a contact does not have
	 * an ownership tag attached.
	 *
	 * Return: 1 (true), 0 (false)
	 */
	int (*is_my_ucontact) (ucontact_t *c);

	/**
	 * Generate the next contact ID of a given record.  Returns a different
	 * contact ID on each new call, rotating across CLABEL_MASK values.
	 *
	 * @r: the usrloc record
	 *
	 * Return: the next contact ID
	 */
	uint64_t (*next_contact_id) (urecord_t *r);

	/**
	 * Update the SIP pinging latency of a contact, i.e. the round-trip delay
	 * of pinging a contact using a SIP OPTIONS message.
	 *
	 * @d: the usrloc domain to update
	 * @coords: the SIP coordinates of the contact
	 * @sipping_latency: new latency value, in microseconds
	 *
	 * Return: 0 (success), negative otherwise
	 */
	int (*update_sipping_latency) (udomain_t *d, ucontact_coords coords,
	                               int sipping_latency);

	/**
	 * Raise an async registration refresh event for an usrloc contact
	 *
	 * @ct: the usrloc contact
	 * @reason: short text denoting the reason for the refresh
	 * @req_callid: Call-ID of the pending SIP request or NULL if not available
	 */
	void (*raise_ev_ct_refresh) (const ucontact_t *ct, const str *reason,
	                             const str *req_callid);

	/**
	 * Easily iterate through all currently registered domains.
	 * @d: the last fetched domain.  Use a NULL value to fetch the 1st domain.
	 *
	 * Return: the next domain or NULL if the end of list end has been reached.
	 */
	udomain_t *(*get_next_udomain) (udomain_t *d);

	/**
	 * Low-level functions to lock/unlock a hash table bucket on a given domain
	 * @d: the domain to use
	 * @slot: the index of the bucket, must be less than @d->size
	 */
	void (*lock_ulslot) (udomain_t *d, int slot);
	void (*unlock_ulslot) (udomain_t *d, int slot);

	/**
	 * Return all contacts for all currently registered users in the given
	 * domain.  The function expects a buffer of sufficient length to fit all
	 * contacts.  If the buffer is exhausted, the function returns the
	 * estimated amount of additional space needed.  In this case, the caller
	 * is expected to repeat the call using this value as the hint.
	 *
	 * @d: the usrloc domain to search within
	 * @buf: the input buffer
	 * @buf_len: the length of the buffer
	 * @flags: flag bitmask to be used as a filter (use 0 to skip)
	 * @part_idx / @part_max: partition the contact space.  E.g.:
	 *     * to only grab the top 25% of contacts, use: "0 / 4"
	 *     * to grab all contacts, use: "0 / 1"
	 * @pack_coords: Set to 1 to include the contact coords in the buffer,
	 *     otherwise 0.  See @ucontact_coords for more info.
	 *
	 * The contact information is packed into the buffer as follows:
	 *
	 * +=======+======+=========+=======+=============+======+========+=======+
	 * |int    |char[]|int      |char[] |socket_info *|uint  |proxy_l |uint64 |
	 * +=======+======+=========+=======+=============+======+========+=======+
	 * |ct1.len|ct1.s |path1.len|path1.s|sock1        |flags1|nx_hop1 |coords1|
	 * +-------+------+---------+-------+-------------+------+--------+-------+
	 * |ct2.len|ct2.s |path2.len|path2.s|sock2        |flags2|nx_hop2 |coords2|
	 * +-------+------+---------+-------+-------------+------+--------+-------+
	 * |  ...  | ...  |   ...   |  ...  |     ...     |  ... |  ...   |  ...  |
	 * +-------+------+---------+-------+-------------+------+--------+-------+
	 * |ctN.len|ctN.s |pathN.len|pathN.s|sockN        |flagsN|nx_hopN |coordsN|
	 * +-------+------+---------+-------+-------------+------+--------+-------+
	 * |0000000|
	 * +-------+
	 */
	int (*get_domain_ucontacts) (udomain_t *d, void *buf, int buf_len,
	                             unsigned int flags, unsigned int part_idx,
	                             unsigned int part_max, int pack_coords);

	/**
	 * Similar to @get_domain_ucontacts, except it works for all current usrloc
	 * domains, with the contacts of each domain being merged together, without
	 * the ability to discern the domain of a given contact anymore.
	 */
	int (*get_all_ucontacts) (void *buf, int buf_len, unsigned int flags,
	                          unsigned int part_idx, unsigned int part_max,
	                          int pack_coords);

	/**
	 * Subscribe to various user location create/update/delete/expire events
	 * concerning records (AoRs) and contacts.
	 *
	 * @types: bitmask of callback types to register the @cb callback for
	 * @cb: The registered callback function.  Explanation of its arguments:
	 *	  - @binding: depending on the callback type, you should cast it to
	 *	              either (ucontact_t *) or (urecord_t *)
	 *	  - @type: type of the invoked callback (e.g. UL_CONTACT_EXPIRE)
	 *
	 * Return: 0 (success), negative otherwise
	 */
	int (*register_ulcb) (ul_cb_type types,
	                      void (*cb) (void *binding, ul_cb_type type));
} usrloc_api_t;


typedef int (*bind_usrloc_t)(usrloc_api_t* api);

static inline int load_ul_api(usrloc_api_t *ul)
{
	bind_usrloc_t bind_usrloc;

	bind_usrloc = (bind_usrloc_t)find_export("ul_bind_usrloc", 0);
	if (!bind_usrloc) {
		LM_ERR("can't bind usrloc\n");
		return -1;
	}

	if (bind_usrloc(ul) < 0)
		return -1;

	return 0;
}

#endif /* USRLOC_H */
