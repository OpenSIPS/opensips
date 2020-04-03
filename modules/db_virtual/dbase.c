/*
 * Copyright (C) 2009 Voice Sistem SRL
 * Copyright (C) 2009 Razvan
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
 *  2009-07-29 initial version (razvan)
 */


#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../db/db_query.h"
#include "../../db/db_ut.h"
#include "db_virtual.h"
#include "dbase.h"
#include "../../timer.h"

#define MAXBUF (1<<14)
/*  Conceptual allowed operations
 *                          parallel    round
    dbb->use_table
    dbb->init
    dbb->close
 *
    dbb->query              0           1
    dbb->fetch_result       0           0.5
    dbb->raw_query          0           1
    dbb->free_result        0           0.5
    dbb->insert             1           1
    dbb->delete             1           0
    dbb->update             1           0
    dbb->replace            1           0
    dbb->last_inserted_id   0           0
    dbb->insert_update      1           1
 *
 * Explanation:
 * it makes sense to insert in multiple dbs
 * but not to query and fetch from multiple dbs.
 *
 */

extern int db_access_mode;

extern info_global_t* global;
//extern handle_set_t * private_handles;
extern handle_private_t* private;

extern int db_reconnect_with_timer;
extern int db_max_consec_retrys;

str use_table={0,0};

void get_update_flags(handle_set_t * private_handles){

    int i;
    for(i=0; i< global->set_list[private_handles->set_index].size; i++){
        if(global->set_list[
	    private_handles->set_index].db_list[i].flags & MAY_USE){
            private_handles->con_list[i].flags |= MAY_USE;
        }else{
            private_handles->con_list[i].flags &= NOT_MAY_USE;
        }
    }
}

void set_update_flags(int db_index, handle_set_t * private_handles){
    if(0<=db_index && db_index <
	    global->set_list[private_handles->set_index].size){
        if(private_handles->con_list[db_index].flags & CAN_USE){
            if(!db_reconnect_with_timer)
                global->set_list[
		private_handles->set_index].db_list[db_index].flags |= CAN_USE;
        }else{
            global->set_list[
	    private_handles->set_index].db_list[db_index].flags &= NOT_CAN_USE;
        }
    }
}

void try_reconnect(handle_set_t * p){

    LM_DBG("try reconnect\n");

    int i;
    //handle_set_t * p = (handle_set_t*)_h->tail;//private_handles;

    for(i=0; i< global->set_list[p->set_index].size; i++){
        if(!(p->con_list[i].flags & CAN_USE) &&
                global->set_list[p->set_index].db_list[i].flags & CAN_USE){

            if( global->set_list[p->set_index].db_list[i].flags & RERECONNECT){
                p->con_list[i].no_retries = db_max_consec_retrys;
            }
            if(p->con_list[i].no_retries-- > 0){
                p->con_list[i].con =
                    global->set_list[p->set_index].db_list[i].dbf.init(
                    &global->set_list[p->set_index].db_list[i].db_url);
                if(!p->con_list[i].con){
                    LM_DBG("cant reconnect to db %.*s\n",
                        global->set_list[p->set_index].db_list[i].db_url.len,
                        global->set_list[p->set_index].db_list[i].db_url.s);
                    continue;
                }

                global->set_list[p->set_index].db_list[i].dbf.use_table(
                        p->con_list[i].con, &use_table);

                p->con_list[i].flags |= CAN_USE;
                set_update_flags(i, p);

                p->con_list[i].no_retries = db_max_consec_retrys;
            }
        }
    }
}


#define  db_generic_operation2(FUNCTION_WITH_PARAMS, is_parallel, is_roundable, use_rc)\
do{                                                                             \
    LM_DBG("f call \n");                                                        \
    int i;                                                                      \
    int rc=0, rc2=1;                                                            \
    int max_loop;                                                               \
	int old_flags;                                                              \
    handle_con_t * handle;                                                      \
    db_func_t * f;                                                              \
    handle_set_t * p = (handle_set_t*)_h->tail;                                 \
										\
    LM_DBG("f call handle size = %i\n", p->size);				\
                                                                                \
    max_loop = p->size;                                                         \
                                                                                \
    get_update_flags(p);                                                        \
    try_reconnect(p);                                                           \
                                                                                \
    switch(global->set_list[p->set_index].set_mode){				\
                                                                                \
        case ROUND: /* ROBIN HOOD = ROB_IN_WOOD,  ROBE_N' HOOD*/                \
            if(is_roundable)                                                    \
                p->curent_con = (p->curent_con+1) % p->size;                    \
                                                                                \
        case FAILOVER:                                                          \
            do{                                                                 \
                /* get next valid handle*/                                      \
                handle = &p->con_list[p->curent_con];                           \
                f = &global->set_list[p->set_index].db_list[p->curent_con].dbf; \
                                                                                \
                if((handle->flags & CAN_USE) && (handle->flags & MAY_USE)){     \
                    LM_DBG("flags1 = %i\n", p->con_list[p->curent_con].flags);  \
                                                                                \
                                                                                \
                    old_flags = handle->con->flags;                             \
                    handle->con->flags |= _h->flags;                            \
                    /* call f*/                                                 \
                    rc = f->FUNCTION_WITH_PARAMS;                               \
                    handle->con->flags = old_flags;                             \
                    /* in db core OR op is being reset after every db op so we  \
                     * also have to reset it here */                            \
                    CON_OR_RESET( _h );                                         \
                                                                                \
                    if((rc && use_rc)){                                         \
                        LM_DBG("failover call failed\n");                       \
                        /* set local can not use flag*/                         \
                        handle->flags &= NOT_CAN_USE;                           \
                                                                                \
                        /* close connection*/                                   \
                        f->close(handle->con);                                  \
                                                                                \
                        /* move to the next conn */                             \
                        p->curent_con = (p->curent_con+1)%p->size;              \
                    }                                                           \
                    set_update_flags(p->curent_con, p);                         \
                }else{                                                          \
                    LM_DBG("flags2 = %i\n", p->con_list[p->curent_con].flags);  \
                                                                                \
                    /* try next*/                                               \
                    rc = -1;                                                    \
                    p->curent_con = (p->curent_con+1)%p->size;                  \
                }                                                               \
                LM_DBG("curent_con = %i\n", p->curent_con);                     \
            }while((rc && use_rc) && --max_loop);                               \
                                                                                \
            rc2=rc;                                                             \
         break;                                                                 \
                                                                                \
        case PARALLEL:                                                          \
            if(is_parallel){                                                    \
                for(i=0; i< max_loop; i++){                                     \
                    handle = &p->con_list[i];                                   \
                    f = &global->set_list[p->set_index].db_list[i].dbf;         \
                    if((handle->flags & CAN_USE) && (handle->flags & MAY_USE)){ \
                                                                                \
                        rc = f->FUNCTION_WITH_PARAMS;                           \
                        if((rc && use_rc)){                                     \
                            LM_DBG("parallel call failed\n");                   \
                            handle->flags &= NOT_CAN_USE;                       \
                                                                                \
                            f->close(handle->con);                              \
                        }                                                       \
                        set_update_flags(i, p);                                 \
                    }                                                           \
                    else{                                                       \
                        rc = 1;                                                 \
                    }                                                           \
                                                                                \
                    if(use_rc)                                                  \
                        rc2 &= rc;                                              \
                    else                                                        \
                        rc2 = rc;                                               \
                                                                                \
                }                                                               \
            }else{                                                              \
            do{                                                                 \
                /* get next valid handle*/                                      \
                handle = &p->con_list[p->curent_con];                           \
                f = &global->set_list[p->set_index].db_list[p->curent_con].dbf; \
                                                                                \
                if((handle->flags & CAN_USE) && (handle->flags & MAY_USE)){     \
                    LM_DBG("flags1 = %i\n", p->con_list[p->curent_con].flags);  \
                                                                                \
                    /* call f*/                                                 \
                    rc = f->FUNCTION_WITH_PARAMS;                               \
                    if(rc){                                                     \
                        /* set local can not use flag*/                         \
                        handle->flags &= NOT_CAN_USE;                           \
                                                                                \
                        /* set global can not use flag*/                        \
                        set_update_flags(p->curent_con, p);                     \
                                                                                \
                        /* close connection*/                                   \
                        f->close(handle->con);                                  \
                                                                                \
                        /* move to the next conn */                             \
                        p->curent_con = (p->curent_con+1)%p->size;              \
                    }                                                           \
                }else{                                                          \
                    LM_DBG("flags2 = %i\n", p->con_list[p->curent_con].flags);  \
                                                                                \
                    /* try next*/                                               \
                    rc = -1;                                                    \
                    p->curent_con = (p->curent_con+1)%p->size;                  \
                }                                                               \
                LM_DBG("curent_con = %i\n", p->curent_con);                     \
            }while((rc && use_rc) && --max_loop);                               \
                                                                                \
                rc2=rc ;                                                        \
            }                                                                   \
            break;                                                              \
                                                                                \
        default:                                                                \
            rc2 = 1;                                                            \
            break;                                                              \
    }                                                                           \
                                                                                \
    return rc2;                                                                 \
}while(0)                                                                       \


/*
    find set_url in global state
    get index
    allocate
    populate with db_init
*/
db_con_t* db_virtual_init(const str* _set_url)
{
    int i;
    int index = -1;
    db_con_t * res=NULL;
    char buffer[256];
    char * token;
    handle_set_t* p;

    if(!_set_url || !_set_url->s){
        LM_ERR("url or url.s NULL\n");
        return NULL;
    }

    LM_DBG("INIT set_name, %.*s\n", _set_url->len, _set_url->s);

    /* so that loadmodule order does not matter */
    if(!global){
        if(virtual_mod_init())
            return NULL;
    }

    //if(!private_handles){
    if(!private || !private->hset_list){
        LM_ERR("private handles NULL %p \n", private);
        return NULL;
    }



    /* find set_name in global */
    memset(buffer, 0, 256);
    memcpy(buffer, _set_url->s, _set_url->len);
    token = strtok(buffer, "/");
    token = strtok(NULL, "/");

    LM_DBG("token = %s\n", token);

    //for(i=0; i< global->size; i++){
    for(i=0; i< private->size; i++){
        if(strncmp(token, global->set_list[i].set_name.s,
		global->set_list[i].set_name.len) == 0){
            LM_DBG("found set_name: %s\n", token);
            index = i;
            break;
        }
    }

    if(index < 0){
	LM_ERR("set_name: %.*s not found\n", _set_url->len, _set_url->s);
	return NULL;
    }


    p = &private->hset_list[index];

    /* alocat res */
    res = (db_con_t*)pkg_malloc(sizeof(db_con_t));
    if (!res) {
        MEM_ERR(MEM_PKG);
    }
    memset(res, 0, sizeof(db_con_t));

    /* if refcount > 1 just return*/
    p->refcount++;
    if(p->refcount > 1){
	res->tail = (unsigned long)&(private->hset_list[index]);
    }

    //p = &private->hset_list[index];
    /* else allocate */
    p->set_index = index;
    p->curent_con = 0;
    p->size = global->set_list[index].size;
    p->con_list = (handle_con_t*) pkg_malloc(p->size * sizeof(handle_con_t));
    if(!p->con_list)
	MEM_ERR(MEM_PKG);

    memset(p->con_list, 0, p->size * sizeof(handle_con_t));

    /* populate */
    for(i=0; i< p->size; i++){
        p->con_list[i].flags = global->set_list[p->set_index].db_list[i].flags;

        if((p->con_list[i].flags & CAN_USE) && (p->con_list[i].flags & MAY_USE))
        p->con_list[i].con =
                global->set_list[p->set_index].db_list[i].dbf.init(
                &global->set_list[p->set_index].db_list[i].db_url);
        if(!p->con_list[i].con){
            LM_ERR("cant init db %.*s\n",
                    global->set_list[p->set_index].db_list[i].db_url.len,
                    global->set_list[p->set_index].db_list[i].db_url.s);
            p->con_list[i].flags &=NOT_CAN_USE;
            set_update_flags(i, p);

        }
        p->con_list[i].no_retries = db_max_consec_retrys;
    }


    /* link the private handles */
    res->tail = (unsigned long)p;

    return res;

error:
    if(p->con_list)
        pkg_free(p->con_list);

    if(res)
        pkg_free(res);


    return NULL;
}

void db_virtual_close(db_con_t* _h)
{

    LM_DBG("CLOSE\n");

    int i;
    //handle_set_t * p = private_handles;
    handle_set_t * p = (handle_set_t*)_h->tail;

    p->refcount--;

    /* if recount is zero close all and free structure */
    /* else return */
    if(p->refcount == 0){
	for(i=0; i < p->size; i++){
	    if(p->con_list[i].flags & CAN_USE){
		global->set_list[p->set_index].db_list[i].dbf.close(
		p->con_list[i].con);
	    }
	}
	pkg_free(p->con_list);
    }
    return;
}

int db_virtual_use_table(db_con_t* _h, const str* _t)
{

    LM_DBG("USE TABLE\n");

    int i;
    int rc=0;
    int rc2=0;

    handle_set_t * p = (handle_set_t*)_h->tail;//private_handles;

    for(i=0; i < p->size; i++){
        if(p->con_list[i].flags & CAN_USE){
            rc = global->set_list[p->set_index].db_list[i].dbf.use_table(
		    p->con_list[i].con, _t);
            if(rc)
                LM_ERR("USE TABLE failed: %.*s\n", _t->len, _t->s);
            rc2 |=rc;
        }
    }


    /* store the string for later use */
    if(use_table.s)
        pkg_free(use_table.s);
    use_table.s = (char*) pkg_malloc(_t->len * sizeof(char));
    use_table.len = _t->len;

    memcpy(use_table.s, _t->s, _t->len);


    return rc2;
}

int db_virtual_free_result(db_con_t* _h, db_res_t* _r)
{
    db_generic_operation2(free_result(handle->con, _r), 0, 0, 1);
}

int db_virtual_query(const db_con_t* _h, const db_key_t* _k, const db_op_t* _op,
	 const db_val_t* _v, const db_key_t* _c, const int _n, const int _nc,
	 const db_key_t _o, db_res_t** _r)
{
    db_generic_operation2(query(handle->con, _k, _op, _v, _c, _n, _nc, _o, _r),
	    0, 1, 1);
}


int db_virtual_fetch_result(const db_con_t* _h, db_res_t** _r, const int nrows)
{
    db_generic_operation2(fetch_result(handle->con, _r, nrows), 0, 0, 1);
}


int db_virtual_raw_query(const db_con_t* _h, const str* _s, db_res_t** _r)
{
    db_generic_operation2(raw_query(handle->con, _s, _r),0, 1, 1);
}


int db_virtual_insert(const db_con_t* _h, const db_key_t* _k,
	const db_val_t* _v, const int _n)
{
    db_generic_operation2(insert(handle->con, _k, _v, _n),1, 1, 1);
}


int db_virtual_delete(const db_con_t* _h, const db_key_t* _k, const db_op_t* _o,
	const db_val_t* _v, const int _n)
{
    db_generic_operation2(delete(handle->con, _k, _o, _v, _n), 1, 0, 1);
}

int db_virtual_update(const db_con_t* _h, const db_key_t* _k, const db_op_t* _o,
	const db_val_t* _v, const db_key_t* _uk, const db_val_t* _uv,
	const int _n, const int _un)
{
    db_generic_operation2(update(handle->con, _k, _o, _v, _uk, _uv, _n, _un),1,
	    0, 1);
}

int db_virtual_replace(const db_con_t* _h, const db_key_t* _k,
	const db_val_t* _v, const int _n)
{
    db_generic_operation2(replace(handle->con, _k, _v, _n),1, 0, 1);
}


int db_virtual_last_inserted_id(const db_con_t* _h)
{
    db_generic_operation2(last_inserted_id(handle->con),0, 0, 0);
}

int db_virtual_insert_update(const db_con_t* _h, const db_key_t* _k,
	const db_val_t* _v,const int _n)
{
    db_generic_operation2(insert_update(handle->con, _k, _v, _n),1, 1, 1);
}

#define CURRCON(_ah) (_ah->current_con)

#define db_generic_async_operation(_h,_ah, _resume_f, FUNC, ...)         \
do {                                                                            \
	int mode;                                                                   \
    int rc=0;                                                                   \
	int old_flags;                                                              \
    handle_con_t * handle;                                                      \
    db_func_t * f;                                                              \
    handle_set_t * p = (handle_set_t*)_h->tail;                                \
                                                                                \
    LM_DBG("f call handle size = %i\n", p->size);                               \
                                                                                \
    get_update_flags(p);                                                        \
    try_reconnect(p);                                                           \
                                                                                \
	mode = global->set_list[p->set_index].set_mode;                             \
                                                                                \
	if (mode == PARALLEL) {                                                     \
		LM_WARN("PARALLEL not supported in async! using FAILOVER!\n");          \
	} else if (mode != FAILOVER && mode != ROUND) {                             \
		LM_ERR("mode %d not supported!\n", mode);                               \
		return -1;                                                              \
	}                                                                           \
                                                                                \
	do {                                                                        \
		handle = &p->con_list[CURRCON(_ah)];                                   \
		f = &global->set_list[p->set_index].db_list[CURRCON(_ah)].dbf;         \
                                                                                \
		if((handle->flags & CAN_USE) && (handle->flags & MAY_USE)){             \
			LM_DBG("flags1 = %i\n", p->con_list[CURRCON(_ah)].flags);          \
                                                                                \
			if (f == NULL || f->FUNC == NULL) {                                 \
				LM_ERR("async not supported for this backend!\n");              \
				return -1;                                                      \
			}                                                                   \
                                                                                \
			old_flags = handle->con->flags;                                     \
			handle->con->flags |= _h->flags;                                    \
			rc=f->FUNC(__VA_ARGS__);                                            \
                                                                                \
			handle->con->flags = old_flags;                                     \
			/* in db core OR op is being reset after every db op so we          \
			 * also have to reset it here */                                    \
			CON_OR_RESET( _h );                                                 \
                                                                                \
			if (rc<0) {                                                         \
				/* FIXME quite a complicated case                               \
				 * if the db disconected by any means then                      \
				 * anything shall be ok if continue with other DB               \
				 * if cannot open new connections to mysql                      \
				 * then things are gonna be messed up if continuing */          \
				LM_ERR("failover call failed rc:%d\n", rc);                     \
				/* set local can not use flag*/                                 \
				handle->flags &= NOT_CAN_USE;                                   \
                                                                                \
				/* close connection*/                                           \
				set_update_flags(CURRCON(_ah), p);                             \
                                                                                \
				f->close(handle->con);                                          \
				/* if failed before placing the fd in reactor                   \
				 * we keep on */                                                \
				if ((--_ah->cons_rem) == 0) {                                  \
					LM_ERR("All databases failed!! No hope for you!\n");        \
					return -1;                                                  \
				}                                                               \
                                                                                \
				/* try next*/                                                   \
				rc = -1;                                                        \
				CURRCON(_ah)  = (CURRCON(_ah)+1)%p->size;                     \
			} else {                                                            \
				if (_resume_f)                                                  \
					async_status = ASYNC_CHANGE_FD;                             \
				set_update_flags(CURRCON(_ah), p);                             \
				return rc;                                                      \
			}                                                                   \
		} else {                                                                \
			LM_DBG("flags2 = %i\n", p->con_list[CURRCON(_ah)].flags);          \
			if ((--_ah->cons_rem) == 0) {                                      \
				LM_ERR("All databases failed!! No hope for you!\n");            \
				return -1;                                                      \
			}                                                                   \
                                                                                \
			/* try next*/                                                       \
			rc = -1;                                                            \
			CURRCON(_ah)  = (CURRCON(_ah)+1)%p->size;                         \
		}                                                                       \
		LM_DBG("curent_con = %i\n", CURRCON(_ah));                             \
	} while ((_ah)->cons_rem); /* should never exit here */                    \
                                                                                \
	return rc;                                                                  \
}while (0);


int db_virtual_async_raw_query(db_con_t *_h, const str *_s, void **_priv)
{
	handle_async_t* _ah;
    handle_con_t * _handle;
    handle_set_t * _p = (handle_set_t*)_h->tail;

	if (_s->len > MAXBUF) {
		LM_ERR("query exceeds buffer size(%d)!\n", MAXBUF);
		return -1;
	}

	if ((_ah=pkg_malloc(sizeof(handle_async_t)+_s->len)) == NULL) {
		LM_ERR("no more pkg\n");
		return -1;
	} else {
		/* automatically jump to next DB destination only for ROUND ROBIN
		 * else, for failover, will jump only if something goes wrong */
		if (global->set_list[_p->set_index].set_mode == ROUND)
			_p->curent_con = (_p->curent_con+1)%_p->size;

		_ah->current_con = _p->curent_con;
		_ah->cons_rem    = _p->size;

		/* store the query for further calls */
		_ah->query.len   = _s->len;
		_ah->query.s	 = (char*)(_ah+1);
		memcpy(_ah->query.s, _s->s, _s->len);

		*_priv			 = _ah;
	}

    _handle = &_p->con_list[CURRCON(_ah)];

	db_generic_async_operation(_h, _ah,0, async_raw_query, _handle->con, _s,
	                           &_ah->_priv );

	return 0;
}


int db_virtual_async_resume(db_con_t *_h, int fd, db_res_t **_r, void *_priv)
{

	handle_async_t *_ah;
    db_func_t * _f;
    handle_con_t * _handle;
    handle_set_t * _p = (handle_set_t*)_h->tail;

	if (!_priv) {
		LM_ERR("Expecting async handle! Nothing received!\n");
		return -1;
	}

	_ah = (handle_async_t *)_priv;
    _handle = &_p->con_list[CURRCON(_ah)];
    _f = &global->set_list[_p->set_index].db_list[CURRCON(_ah)].dbf;

	/* call the resume function */
	if (_f->async_resume(_handle->con, fd, _r, _ah->_priv) < 0) {
		_handle->flags &= NOT_CAN_USE;
		/* close connection*/
		_f->close(_handle->con);

		/* we did all we could, but no con worked
		 * do something to those DBs */
		if ((--_ah->cons_rem) == 0) {
			LM_ERR("All databases failed!! No hope for you!\n");
			return -1;
		}

		/* try next DB; no matter RR or FAILOVER */
		CURRCON(_ah) = (CURRCON(_ah) +1)%_p->size;
		_handle = &_p->con_list[CURRCON(_ah)];

		/* try the next database connection */
		db_generic_async_operation(_h, _ah,1,
				async_raw_query, _handle->con, &_ah->query, _ah->_priv );
	}

	/* if here means it worked; we set this connection as current connection
	 * for other messages to come */
	_p->curent_con = CURRCON(_ah);

	async_status = ASYNC_DONE;

	return 0;
}

int db_virtual_async_free_result(db_con_t *_h, db_res_t *_r, void *_priv)
{
	handle_async_t *_ah = (handle_async_t *)_priv;
	db_func_t *_f;
	handle_con_t *_handle;
	handle_set_t *_p = (handle_set_t *)_h->tail;

	if (!_ah) {
		LM_ERR("Expecting async handle! Nothing received!\n");
		return -1;
	}

	_handle = &_p->con_list[CURRCON(_ah)];
	_f = &global->set_list[_p->set_index].db_list[CURRCON(_ah)].dbf;

	if (_f->async_free_result(_handle->con, _r, _ah->_priv) < 0) {
		LM_ERR("error while freeing async query result\n");
		return -1;
	}

	pkg_free(_ah);
	return 0;
}

#undef CURRCON
