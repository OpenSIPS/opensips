#ifndef _RTPENGINE_HASH_H
#define _RTPENGINE_HASH_H

#include "../../str.h"
#include "../../locking.h"
#include "rtpengine.h"

/*
 * table entry
 *
 * Each entry is a linked list which can accommodate many calls and branches.
 */
struct rtpengine_hash_entry
{
	str callid;				// call callid
	str viabranch;			// call viabranch
	struct rtpe_node *node; // call selected node

	unsigned int tout;				   // call timeout
	struct rtpengine_hash_entry *next; // call next
};

/*
 * table
 *
 * Note that the table size constrains only the number of buckets, if too small the computed hash over each
 * callid will lead to many collisions however these will be accommodated in the entry list which is a
 * linked list of allocations. Setting the size is based on the number of buckets we wish to provide and then
 * a trade-off between this and the number of entries we need to inspect when performing checks and changes.
 *
 * In an unconstrained memory environment we should be content with a low load factor (i.e. 0.5) meaning that
 * if we want to store 5000 calls we would set the size to 10000 (~820KB).
 */
struct rtpengine_hash_table
{
	struct rtpengine_hash_entry *
			*row_entry_list;  // vector of size pointers to entry (each row can have many entries)
	gen_lock_t **row_locks;	  // vector of size pointers to locks
	unsigned int *row_totals; // vector of size numbers of entries in the hashtable rows (count of via branches)
	unsigned int size; // hash table size
};

int rtpengine_hash_table_init(int size);
int rtpengine_hash_table_destroy(void);
int rtpengine_hash_table_insert(str callid, struct rtpengine_hash_entry *value);
int rtpengine_hash_table_remove(str callid, str viabranch, enum rtpe_operation);
struct rtpe_node *rtpengine_hash_table_lookup(str callid, str viabranch, enum rtpe_operation);

void rtpengine_hash_table_print(void);
unsigned int rtpengine_hash_table_total(void);

void rtpengine_hash_table_free_entry(struct rtpengine_hash_entry *entry);

#endif