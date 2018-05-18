#ifndef _RATE_CACHER_MAIN_H_
#define _RATE_CACHER_MAIN_H_

/* ratesheet description */

#define PTREE_CHILDREN 10
#define IS_DECIMAL_DIGIT(d) \
	(((d)>='0') && ((d)<= '9'))
			

#define INIT_PTREE_NODE(p, n) \
do {\
        (n) = (ptree_t*)shm_malloc(sizeof(ptree_t));\
        if(NULL == (n)) {\
		LM_ERR("Failed to allocate trie node \n"); \
		return -1;\
	} \
        memset((n), 0, sizeof(ptree_t));\
        (n)->bp=(p);\
}while(0)

typedef struct ptree_node_ {
	struct ratesheet_cell_entry *re;
	struct ptree_ *next;
} ptree_node_t;

typedef struct ptree_ {
	/* backpointer */
	struct ptree_ *bp;
	ptree_node_t ptnode[PTREE_CHILDREN];
} ptree_t;

struct ratesheet_cell_entry {
	str destination;
	double price;
	int minimum;
	int increment;
};

/* carriers hash */
struct carrier_table{
	unsigned int       size;
	struct carrier_entry   *entries;
};

struct carrier_entry {
	struct carrier_cell *first;
	struct carrier_cell *last;
	rw_lock_t *lock;
};

struct carrier_cell {
	str carrierid;
	unsigned int rateid;
	str rate_table;
	str rate_currency;
	ptree_t *trie;
	int reload_pending;
	struct carrier_cell *next;
	struct carrier_cell *prev;
};

/* accounts hash */
struct accounts_table{
	unsigned int       size;
	struct account_entry   *entries;
};

struct account_entry {
	struct account_cell *first;
	struct account_cell *last;
	rw_lock_t *lock;
};

struct account_cell {
	str accountid;
	unsigned int ws_rateid;
	unsigned int rt_rateid;
	str ws_rate_table;
	str rt_rate_table;
	str ws_rate_currency;
	str rt_rate_currency;
	ptree_t *ws_trie;
	ptree_t *rt_trie;
	int ws_reload_pending;
	int rt_reload_pending;
	struct account_cell *next;
	struct account_cell *prev;
};

/* FIXME - might not want to have this static :( */
#define MAX_CARR_IN_SIZE 32

#endif
