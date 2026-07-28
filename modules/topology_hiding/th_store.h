/*
 * Copyright (C) 2026 OpenSIPS Solutions
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
 */

#ifndef TH_STORE_H
#define TH_STORE_H

#include "../../str.h"

/*
 * Server-side storage for the topology hiding state of dialog-less calls.
 *
 * In the default (stateless) mode, the whole encoded state travels in the
 * Contact URI parameter, which makes that URI long. Some user agents cannot
 * cope with it and truncate the parameter, so the state can no longer be
 * decoded when they send a sequential request.
 *
 * In this mode, the state is kept on the server side under a short key, and
 * only that key travels in the Contact URI. Off the wire the obfuscation and
 * URI-safe encoding serve no purpose, so the stored copy carries neither: its
 * fields are simply length-prefixed in a printable "<length>:<bytes>" form,
 * which keeps it inspectable in the store (only the state that still travels
 * inline in a Contact is obfuscated and encoded). The state must be readable
 * by whichever node receives the sequential request, so the storage is
 * expected to be shared between all the nodes handling the same traffic.
 */

/* length of the key travelling on the wire (hex chars => 64 bits) */
#define TH_KEY_LEN 16

/*
 * A key travels in the Contact URI parameter prefixed by this marker, so
 * that it can never be taken for an encoded state travelling in that same
 * parameter instead - both are in use at once, as it is decided per dialog
 * which of the two it gets (see th_state_storable()).
 *
 * The marker has to satisfy two things, and '_' is picked because it
 * provably does:
 *
 * 1) No encoded state may ever start with it, or a state would be looked
 *    up in the storage as if it were a key. The state is emitted by
 *    word64encode() or word32encode(), whose alphabets are word64digits
 *    "A-Za-z0-9+." and base32digits "A-Z2-7" (see ut.c), and both pad
 *    with '-'. So an encoded state is always within [A-Za-z0-9+.-], which
 *    '_' is not part of. Note this holds whatever its length: telling the
 *    two apart by length instead would rest on nothing more than the
 *    minimum size of what gets packed, which no rule keeps true.
 *
 *    Mind that word64 is not the usual base64: it ends in "+." where
 *    base64 ends in "+/", so '.' - the tempting choice - is one of the
 *    characters a state can be made of, and would not do here.
 *
 * 2) It must be legal, unescaped, in the parameter of a SIP URI. Per the
 *    grammar of RFC 3261 25.1:
 *
 *      pvalue     =  1*paramchar
 *      paramchar  =  param-unreserved / unreserved / escaped
 *      unreserved =  alphanum / mark
 *      mark       =  "-" / "_" / "." / "!" / "~" / "*" / "'" / "(" / ")"
 *
 *    which puts '_' in mark, hence in unreserved, hence in paramchar.
 *
 * The marker only ever has to be unambiguous inside the value of our own
 * parameter: whatever else the URI carries is matched by parameter name
 * (see topology_hiding_match()), so no other parameter can shadow it.
 */
#define TH_KEY_MARKER '_'

/* what a key takes up in the Contact, marker included */
#define TH_KEY_WIRE_LEN (1 + TH_KEY_LEN)

/* storage backends */
enum th_store_type {
	TH_STORE_NONE = 0,   /* stateless - state travels in the Contact */
	TH_STORE_CACHEDB,    /* shared key-value store */
};

extern str th_state_url;
extern int th_state_ttl;
extern int th_state_ttl_short;

/* added on top of a subscription's Expires, to cover the refresh */
#define TH_STATE_TTL_MARGIN 30

/* is a server-side storage configured? */
int th_store_enabled(void);

/* bind the storage backend - to be called from mod_init */
int th_store_init(void);
/* connect to the storage backend - to be called from child_init */
int th_store_child_init(void);
void th_store_destroy(void);

/*
 * Derive the wire key of a state from @seeds into @out, which must hold
 * TH_KEY_LEN bytes. The key is deterministic, so that every refresh of the
 * same dialog leg lands on it again - see the definition for the rationale.
 */
void th_store_make_key(str seeds[], int n, char *out);

/*
 * Store @blob for @ttl seconds under @key. The caller provides the key,
 * already filled in (TH_KEY_LEN bytes, e.g. via th_store_make_key), so
 * that refreshing a leg overwrites its state in place rather than piling
 * up a new one.
 */
int th_store_put(str *blob, str *key, int ttl);

/*
 * Fetch the blob stored under @key. On success, @blob->s is allocated in
 * pkg memory and must be freed by the caller.
 */
int th_store_get(str *key, str *blob);

/* Drop the blob stored under @key, once it is known to be of no use. */
void th_store_del(str *key);

/*
 * Keep the blob already stored under @key around for another @ttl
 * seconds. @blob must be the value it currently holds.
 */
void th_store_refresh(str *key, str *blob, int ttl);

#endif /* TH_STORE_H */
