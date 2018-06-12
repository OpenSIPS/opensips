/* $Id$
 *
 * simple & fast malloc library
 */

#ifndef q_malloc_h
#define q_malloc_h


struct qm_frag{
	unsigned int size;
	union{
		struct qm_frag* nxt_free;
		int is_free;
	}u;
#ifdef DBG_QM_MALLOC
	char* file;
	char* func;
	unsigned int line;
#endif
};

struct qm_frag_end{
	unsigned int size;
	struct qm_frag* prev_free;
};


struct qm_block{
	unsigned int size; /* total size */
	unsigned int used; /* alloc'ed size*/
	unsigned int real_used; /* used+malloc overhead*/
	unsigned int max_real_used;
	
	struct qm_frag* first_frag;
	struct qm_frag_end* last_frag_end;
	
	struct qm_frag free_lst;
	struct qm_frag_end free_lst_end;
};



struct qm_block* qm_malloc_init(char* address, unsigned int size);

#ifdef DBG_QM_MALLOC
void* qm_malloc(struct qm_block*, unsigned int size, char* file, char* func, 
					unsigned int line);
#else
void* qm_malloc(struct qm_block*, unsigned int size);
#endif

#ifdef DBG_QM_MALLOC
void  qm_free(struct qm_block*, void* p, char* file, char* func, 
				unsigned int line);
#else
void  qm_free(struct qm_block*, void* p);
#endif

void  qm_status(struct qm_block*);


#endif
