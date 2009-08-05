/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
 * it makes sence to insert in multiple dbs
 * but not to query and fetch from multiple dbs.
 *
 */

extern int db_access_mode;
extern db_set_array_t * global_state;
extern db_handle_array_t * private_handles;
extern int db_reconnect_with_timer;
extern int db_max_consec_retrys;

str use_table={0,0};

void get_update_flags(void){

    int i;
    for(i=0; i< global_state->set_a[private_handles->db_set_index].size; i++){
        if(global_state->set_a[private_handles->db_set_index].db_state_a[i].flags & MAY_USE){
            private_handles->hlist[i].flags |= MAY_USE;
        }else{
            private_handles->hlist[i].flags &= NOT_MAY_USE;
        }
    }
}

void set_update_flags(int db_index){
    if(0<=db_index && db_index < global_state->set_a[private_handles->db_set_index].size){
        if(private_handles->hlist[db_index].flags & CAN_USE){
            if(!db_reconnect_with_timer)
                global_state->set_a[private_handles->db_set_index].db_state_a[db_index].flags |= CAN_USE;
        }else{
            global_state->set_a[private_handles->db_set_index].db_state_a[db_index].flags &= NOT_CAN_USE;
        }
    }
}

void try_reconnect(void){

    LM_DBG("try reconnect\n");

    int i;
    db_handle_array_t * p = private_handles;
    
    for(i=0; i< global_state->set_a[p->db_set_index].size; i++){
        if(!(p->hlist[i].flags & CAN_USE) &&
                global_state->set_a[p->db_set_index].db_state_a[i].flags & CAN_USE){

            if( global_state->set_a[p->db_set_index].db_state_a[i].flags & RERECONNECT){
                p->hlist[i].no_retrys = db_max_consec_retrys;
            }
            if(p->hlist[i].no_retrys-- > 0){
                p->hlist[i].con =
                    global_state->set_a[p->db_set_index].db_state_a[i].dbf.init(
                    &global_state->set_a[p->db_set_index].db_state_a[i].db_url);
                if(!p->hlist[i].con){
                    LM_DBG("cant reconnect to db %.*s\n",
                        global_state->set_a[p->db_set_index].db_state_a[i].db_url.len,
                        global_state->set_a[p->db_set_index].db_state_a[i].db_url.s);
                    continue;
                }

                global_state->set_a[p->db_set_index].db_state_a[i].dbf.use_table(
                        p->hlist[i].con, &use_table);

                p->hlist[i].flags |= CAN_USE;
                set_update_flags(i);

                p->hlist[i].no_retrys = db_max_consec_retrys;
            }
        }
    }
}

#define  db_generic_operation2(FUNCTION_WITH_PARAMS, is_parallel, is_roundable, use_rc) \
do{                                                                             \
    LM_DBG("f call \n");                                                        \
    int i;                                                                      \
    int rc=0, rc2=1;                                                            \
    int max_loop;                                                               \
    db_handle_t * handle;                                                       \
    db_func_t * f;                                                              \
    db_handle_array_t * p = private_handles;                                    \
                                                                                \
    max_loop = p->size;                                                         \
                                                                                \
    get_update_flags();                                                         \
    try_reconnect();                                                            \
                                                                                \
    switch(global_state->set_a[p->db_set_index].set_mode){                      \
                                                                                \
        case ROUND: /* ROBIN HOOD = ROB_IN_WOOD,  ROBE_N' HOOD*/                \
            if(is_roundable)                                                    \
                p->curent = (p->curent+1) % p->size;                            \
                                                                                \
        case FAILOVER:                                                          \
            do{                                                                 \
                /* get next valid handle*/                                      \
                handle = &p->hlist[p->curent];                                  \
                f = &global_state->set_a[p->db_set_index].db_state_a[p->curent].dbf;\
                                                                                \
                if((handle->flags & CAN_USE) && (handle->flags & MAY_USE)){     \
                    LM_DBG("flags1 = %i\n", p->hlist[p->curent].flags);         \
                                                                                \
                                                                                \
                                                                                \
                    /* call f*/                                                 \
                    rc = f->FUNCTION_WITH_PARAMS;                               \
                    if((rc && use_rc)){                                         \
                        LM_DBG("failover call failed\n");                       \
                        /* set local can not use flag*/                         \
                        handle->flags &= NOT_CAN_USE;                           \
                                                                                \
                                                                                \
                        /* close connection*/                                   \
                        f->close(handle->con);                                  \
                    }                                                           \
                    set_update_flags(p->curent);                                \
                }else{                                                          \
                    LM_DBG("flags2 = %i\n", p->hlist[p->curent].flags);         \
                                                                                \
                    /* try next*/                                               \
                    rc = 1;                                                     \
                    p->curent = (p->curent+1)%p->size;                          \
                }                                                               \
                LM_DBG("curent = %i\n", p->curent);                             \
            }while((rc && use_rc) && max_loop--);                               \
                                                                                \
            rc2=rc;                                                             \
         break;                                                                 \
                                                                                \
        case PARALLEL:                                                          \
            if(is_parallel){                                                    \
                for(i=0; i< max_loop; i++){                                     \
                    handle = &p->hlist[i];                                      \
                    f = &global_state->set_a[p->db_set_index].db_state_a[i].dbf;\
                    if((handle->flags & CAN_USE) && (handle->flags & MAY_USE)){ \
                                                                                \
                                                                                \
                        rc = f->FUNCTION_WITH_PARAMS;                           \
                        if((rc && use_rc)){                                     \
                            LM_DBG("parallel call failed\n");                   \
                            handle->flags &= NOT_CAN_USE;                       \
                                                                                \
                                                                                \
                                                                                \
                            f->close(handle->con);                              \
                        }                                                       \
                        set_update_flags(i);                                    \
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
                                                                                \
                                                                                \
                }                                                               \
            }else{                                                              \
                do{                                                             \
                /* get next valid handle*/                                      \
                handle = &p->hlist[p->curent];                                  \
                f = &global_state->set_a[p->db_set_index].db_state_a[p->curent].dbf;\
                                                                                \
                if((handle->flags & CAN_USE) && (handle->flags & MAY_USE)){     \
                    LM_DBG("flags1 = %i\n", p->hlist[p->curent].flags);         \
                                                                                \
                                                                                \
                                                                                \
                    /* call f*/                                                 \
                    rc = f->FUNCTION_WITH_PARAMS;                               \
                    if(rc){                                                     \
                        /* set local can not use flag*/                         \
                        handle->flags &= NOT_CAN_USE;                           \
                                                                                \
                        /* set global can not use flag*/                        \
                        set_update_flags(p->curent);                            \
                                                                                \
                        /* close connection*/                                   \
                        f->close(handle->con);                                  \
                    }                                                           \
                }else{                                                          \
                    LM_DBG("flags2 = %i\n", p->hlist[p->curent].flags);         \
                                                                                \
                    /* try next*/                                               \
                    rc = 1;                                                     \
                    p->curent = (p->curent+1)%p->size;                          \
                }                                                               \
                LM_DBG("curent = %i\n", p->curent);                             \
            }while((rc && use_rc) && max_loop--);                               \
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


db_con_t* db_virtual_init(const str* _set_url)
{
/*
    find set_url in globla state
    get index
    alocate
    populate with db_init
*/
    LM_DBG("INIT set_name, %.*s\n", _set_url->len, _set_url->s);

    int i;
    int index = -3;
    db_con_t * res=NULL;
    char buffer[256];
    char * token;
    
    if(!_set_url || !_set_url->s){
        LM_ERR("url or url.s NULL\n");
        return NULL;
    }

    /* so that loadmodule order does not matter */
    if(!global_state){
        if(virtual_mod_init())
            return NULL;
    }

    if(!private_handles){
        LM_ERR("private handles NULL\n");
        return NULL;
    }

    /* find set_name in global_state */
    memset(buffer, 0, 256);
    memcpy(buffer, _set_url->s, _set_url->len);
    token = strtok(buffer, "/");
    token = strtok(NULL, "/");

    LM_DBG("token = %s\n", token);

    for(i=0; i< global_state->size; i++){
        if(strncmp(token, global_state->set_a[i].set_name.s, global_state->set_a[i].set_name.len) == 0){
            LM_DBG("found set_name: %s\n", token);
            index = i;
            break;
        }
    }

    

    /* get index */
    private_handles->db_set_index = index;
    private_handles->size = global_state->set_a[index].size;
    private_handles->curent = 0;

    /* alocate */
    private_handles->hlist = (db_handle_t *) pkg_malloc(private_handles->size * sizeof(db_handle_t));
    if(!private_handles->hlist)
        MEM_ERR(MEM_PKG);

    memset(private_handles->hlist, 0, private_handles->size * sizeof(db_handle_t));



    /* populate */
    for(i=0; i< private_handles->size; i++){
        private_handles->hlist[i].flags = global_state->set_a[private_handles->db_set_index].db_state_a[i].flags;

        if((private_handles->hlist[i].flags & CAN_USE) && (private_handles->hlist[i].flags & MAY_USE))
        private_handles->hlist[i].con =
                global_state->set_a[private_handles->db_set_index].db_state_a[i].dbf.init(
                &global_state->set_a[private_handles->db_set_index].db_state_a[i].db_url);
        if(!private_handles->hlist[i].con){
            LM_ERR("cant init db %.*s\n",
                    global_state->set_a[private_handles->db_set_index].db_state_a[i].db_url.len,
                    global_state->set_a[private_handles->db_set_index].db_state_a[i].db_url.s);
            private_handles->hlist[i].flags &=NOT_CAN_USE;
            set_update_flags(i);

        }
        private_handles->hlist[i].no_retrys = db_max_consec_retrys;
    }


    /* store all handles */
    res = (db_con_t*)pkg_malloc(sizeof(db_con_t));
    if (!res) {
        MEM_ERR(MEM_PKG);
    }
    memset(res, 0, sizeof(db_con_t));


    res->tail = (unsigned long)private_handles;

    return res;

error:
    if(private_handles->hlist)
        pkg_free(private_handles->hlist);

    if(res)
        pkg_free(res);


    return NULL;
}

void db_virtual_close(db_con_t* _h)
{

    LM_DBG("CLOSE\n");

    int i;
    db_handle_array_t * p = private_handles;
  
    if(p){
        if(p->hlist){
            for(i=0; i< p->size; i++){
                if((p->hlist[i].flags & CAN_USE) && !(p->hlist[i].flags & CLOSED)){
                    p->hlist[i].flags |= CLOSED;
                    global_state->set_a[p->db_set_index].db_state_a[i].dbf.close(p->hlist[i].con);
                }
            }
        }
    }
}

int db_virtual_use_table(db_con_t* _h, const str* _t)
{

    LM_DBG("USE TABLE\n");

    int i;
    int rc=0;
    int rc2=0;

    db_handle_array_t * p = private_handles;

    for(i=0; i < p->size; i++){
        if(p->hlist[i].flags & CAN_USE){
            rc = global_state->set_a[p->db_set_index].db_state_a[i].dbf.use_table(p->hlist[i].con, _t);
            if(rc)
                LM_ERR("USE TABLE failed: %.*s\n", _t->len, _t->s);
            rc2 |=rc;
        }
    }

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
    db_generic_operation2(query(handle->con, _k, _op, _v, _c, _n, _nc, _o, _r), 0, 1, 1);
}


int db_virtual_fetch_result(const db_con_t* _h, db_res_t** _r, const int nrows)
{
    db_generic_operation2(fetch_result(handle->con, _r, nrows), 0, 0, 1);
}


int db_virtual_raw_query(const db_con_t* _h, const str* _s, db_res_t** _r)
{
    db_generic_operation2(raw_query(handle->con, _s, _r),0, 1, 1);
}


int db_virtual_insert(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v, const int _n)
{
    db_generic_operation2(insert(handle->con, _k, _v, _n),1, 1, 1);
}


int db_virtual_delete(const db_con_t* _h, const db_key_t* _k, const db_op_t* _o,
	const db_val_t* _v, const int _n)
{
    db_generic_operation2(delete(handle->con, _k, _o, _v, _n), 1, 0, 1);
}

int db_virtual_update(const db_con_t* _h, const db_key_t* _k, const db_op_t* _o,
	const db_val_t* _v, const db_key_t* _uk, const db_val_t* _uv, const int _n, 
	const int _un)
{
    db_generic_operation2(update(handle->con, _k, _o, _v, _uk, _uv, _n, _un),1, 0, 1);
}

int db_virtual_replace(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v, const int _n)
{
    db_generic_operation2(replace(handle->con, _k, _v, _n),1, 0, 1);
}


int db_virtual_last_inserted_id(const db_con_t* _h)
{
    db_generic_operation2(last_inserted_id(handle->con),0, 0, 0);
}

int db_virtual_insert_update(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v,
	const int _n)
{
    db_generic_operation2(insert_update(handle->con, _k, _v, _n),1, 1, 1);
}
