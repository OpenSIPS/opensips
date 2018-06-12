#ifndef __C_SLOT_H__
#define __C_SLOT_H__

#include "c_elem.h"
#include "cache.h"

struct cache;
struct c_elem;

typedef struct c_slot {
	struct {                  /* Linked list of elements in this collision slot */
		int count;        /* Number of elements in the collision slot */
		struct c_elem* first;  /* First element in the list */
		struct c_elem* last;   /* Last element in the list */
	} ll;

	struct cache* cache;           /* Cache we belong to */

	int mutex;                /* Mutex ID if we have enought mutexes */
	int ref;                  /* Reference counter */
} c_slot_t;


/* First element the collision slot */
#define SLOT_FIRST_ELEM(slot) (slot->ll.first)

/* Number of elements in the collision slot */
#define SLOT_ELEM_COUNT(slot) (slot->ll.count)

/* Next element in the collision slot */
#define SLOT_ELEM_NEXT(elem) (elem->ll.next)

/* Last element in the collision slot */
#define SLOT_ELEM_LAST(slot) (slot->ll.last)


int            init_slot    (struct cache* _c, c_slot_t* _ent);
void           deinit_slot  (c_slot_t* _ent);
struct c_elem* find_elem    (c_slot_t* _sl, const char* _str);


#endif
