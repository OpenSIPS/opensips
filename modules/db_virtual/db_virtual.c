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



#include "../../sr_module.h"
#include "../../db/db.h"
#include "dbase.h"
#include "db_virtual.h"
#include "../../mi/mi.h"
#include "../../pt.h"
#include <string.h>
#include "../../mem/shm_mem.h"

#include <stdio.h>
#include "../../timer.h"

#define MAX_BUF 1028

/* probing time interval */
int db_probe_time = 10;

/* max consecutive retries before give up */
int db_max_consec_retrys = 10;          

/* for debug.. try_reconect with or without a timer process(probe) */
int db_reconnect_with_timer = 1;        

/* exactly once condition keeper */
/*char is_initialized = 0;*/

/* dbs state in shared memory seen global */
db_set_array_t * global_state = NULL;

/* dbs handles in private memory local to each process */
db_handle_array_t * private_handles = NULL;

/* db_urls pointer older until initialization */
char*   db_urls_list[100];
int     db_urls_count=0;

MODULE_VERSION


int init_global_state(void);
static void destroy(void);
int db_virtual_bind_api(const str* mod, db_func_t *dbb);


struct mi_root *db_get_info(struct mi_root *cmd, void *param);
struct mi_root* db_set_info(struct mi_root* cmd, void* param);
//struct mi_root* db_add_url(struct mi_root* cmd, void* param);

static int store_urls( modparam_t type, void* val);


/*
 * Virtual database module interface
 */
static cmd_export_t cmds[] = {
	{"db_bind_api",         (cmd_function)db_virtual_bind_api,      0, 0, 0, 0},
	{0, 0, 0, 0, 0, 0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
        //{"db_file",                 STR_PARAM, &db_file.s},
        {"db_probe_time",           INT_PARAM, &db_probe_time},
        {"db_max_consec_retrys",    INT_PARAM, &db_max_consec_retrys},
        {"db_urls",     STR_PARAM|USE_FUNC_PARAM,(void*)store_urls},
	{0, 0, 0}
};
/*
 * MI
 */
static mi_export_t mi_cmds[] = {
        {"db_get",      db_get_info,       MI_NO_INPUT_FLAG,  0,  0 },
        {"db_set",      db_set_info,       0,  0,  0 },
        //{"db_add",      db_add_url,        0,  0,  0 },
	{ 0, 0, 0, 0, 0}
};

struct module_exports exports = {	
	"db_virtual",
	DEFAULT_DLFLAGS,            /* dlopen flags */
	cmds,
	params,                     /*  module parameters */
	0,                          /* exported statistics */
	mi_cmds,                    /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,                          /* extra processes */
	virtual_mod_init,           /* module initialization function */
	0,                          /* response function*/
	(destroy_function) destroy, /* destroy function */
	0                           /* per-child init function */
};


int add_url(int index, char * name){

    LM_DBG("add url (%i . %s)\n", index, name);

    int i;
    if(global_state->set_a[index].size){
        LM_DBG("add another url %p\n", global_state->set_a[index].db_state_a);

        /* realoc */
        i = global_state->set_a[index].size;

        /* db_state_a realloc */
        global_state->set_a[index].db_state_a =
            (db_state_t *) shm_realloc(global_state->set_a[index].db_state_a,
            (i+1)* sizeof(db_state_t));
        global_state->set_a[index].size +=1;

        /* db_url */
        global_state->set_a[index].db_state_a[i].db_url.s =
                (char *) shm_malloc(strlen(name) * sizeof(char));
        global_state->set_a[index].db_state_a[i].db_url.len = strlen(name);
        memcpy(global_state->set_a[index].db_state_a[i].db_url.s,
                name, strlen(name));

    
    }else{

        LM_DBG("add first set url\n");

        i=0;
        /* alloc set_a index */
        global_state->set_a[index].db_state_a =
                (db_state_t *) shm_malloc(1 * sizeof(db_state_t));
        if(!global_state->set_a[index].db_state_a)
            MEM_ERR(MEM_SHM);

        memset(global_state->set_a[index].db_state_a, 0, sizeof(db_state_t));

        global_state->set_a[index].size = 1;

        /* alloc url name */
        global_state->set_a[index].db_state_a[0].db_url.s =
                (char *) shm_malloc(strlen(name)*sizeof(char));
        global_state->set_a[index].db_state_a[0].db_url.len = strlen(name);

        memcpy(global_state->set_a[index].db_state_a[0].db_url.s,
                name, strlen(name));    
    }

    global_state->set_a[index].db_state_a[i].flags = CAN_USE | MAY_USE;
    return 0;

    error:
    return 1;
}

int add_set(char * name, char * mode){
    

    int nmode = 0;
    char *c;
    if(strncmp(mode, "FAILOVER", strlen("FAILOVER")) == 0)
        nmode = FAILOVER;
    else if(strncmp(mode, "PARALLEL", strlen("PARALLEL")) == 0)
        nmode = PARALLEL;
    else if(strncmp(mode, "ROUND", strlen("ROUND")) == 0)
        nmode = ROUND;

    LM_DBG("add set=%s mode=%i\n", name, nmode);

    if(global_state){
        LM_DBG("realloc\n");
        /* realoc set_a */
        int i = global_state->size;
        global_state->set_a = (db_set_t *)shm_realloc(global_state->set_a,
                                (i+1)*sizeof(db_set_t));
        if(!global_state->set_a)
            MEM_ERR(MEM_SHM);

        global_state->size +=1;
        
        global_state->set_a[i].set_name.s =
                (char *) shm_malloc(strlen(name)*sizeof(char));
        global_state->set_a[i].set_name.len = strlen(name);
        memcpy(global_state->set_a[i].set_name.s, name, strlen(name));

        /* set mode */
        global_state->set_a[i].set_mode = nmode;

        global_state->set_a[i].size = 0 ;



    }else{
        LM_DBG("alloc %p %i\n", global_state, sizeof(db_set_array_t));
        /* alloc global_state */
        c = (char *)shm_malloc(8);
        LM_DBG("alloc %p\n", c);
        pkg_free(c);
        LM_DBG("alloc %p\n", global_state);
        global_state = (db_set_array_t *) shm_malloc (1 * sizeof(db_set_array_t));
        LM_DBG("alloc %p\n", global_state);
        
        if(!global_state)
            MEM_ERR(MEM_SHM);

        memset(global_state, 0, 1 * sizeof(db_set_array_t));
        LM_DBG("alloc done\n");

        /* alloc set array */
        global_state->set_a = (db_set_t *) shm_malloc (1 * sizeof(db_set_t));
        if(!global_state->set_a)
            MEM_ERR(MEM_SHM);

        memset(global_state->set_a, 0, 1 * sizeof(db_set_t));

        /* set array size */
        global_state->size = 1;


        /* alloc set name */
        global_state->set_a[0].set_name.s =
                (char *) shm_malloc(strlen(name)*sizeof(char));
        global_state->set_a[0].set_name.len = strlen(name);

        memcpy(global_state->set_a[0].set_name.s, name, strlen(name));

        /* set mode */
        global_state->set_a[0].set_mode = nmode;

        /* set size */
        global_state->set_a[0].size=0;
    }

    return 0;

    error:
    return 1;
}

static int store_urls( modparam_t type, void* val){
    
    db_urls_list[db_urls_count] = val;
    db_urls_count++;

    return 0;
}


int init_global_state(void){//str *db_set_mapping){


    
    int i, j;
    char *s, *p;
    int count = -1;

    for(i=0; i< db_urls_count; i++){

        s = db_urls_list[i];
        LM_DBG("line = %s\n", s);

        if(s && strlen(s) && s[0]!='#'){

            if(strncmp("define", s, strlen("define")) == 0){
                s += strlen("define")+1;
                p = strchr(s, ' ');
                /* set1=FAILOVER */
                *p = 0;
                p++;
                LM_DBG("set_mode = {%s}, mode = {%s}\n", s, p);
                add_set(s, p);
                /*LM_ERR("done\n"); */
                count++;
            }
            else{
                /* mysql:........ */
                LM_DBG("db = %s\n", s);
                add_url(count, s);
            }
        }
 
    }
    for(i = 0; i< global_state->size; i++)
        for(j=0; j<global_state->set_a[i].size; j++){

            global_state->set_a[i].db_state_a[j].dbf.cap = 0;

            if(db_bind_mod(&global_state->set_a[i].db_state_a[j].db_url,
                    &global_state->set_a[i].db_state_a[j].dbf)){
                LM_ERR("cant bind db : %.*s", global_state->set_a[i].db_state_a[j].db_url.len,
                        global_state->set_a[i].db_state_a[j].db_url.s);
                goto error;
            }
        }

    LM_DBG("global_state done\n");
    /*is_initialized = 1; */
    return 0;

    error:

    destroy();
    return -1;
}

int init_private_handles(void){

    private_handles = (db_handle_array_t *) pkg_malloc(1 * sizeof(db_handle_array_t));
    if(!private_handles)
        MEM_ERR(MEM_PKG);

    memset(private_handles, 0, sizeof(db_handle_array_t));
    return 0;

    error:
    return -1;
}

static void reconnect_timer(unsigned int ticks, void *data)
{
    LM_DBG("reconnect with timer\n");
    int i,j;

    db_con_t * con;
    
    for(i=0; i < global_state-> size; i++){
        for(j=0; j < global_state->set_a[i].size; j++){
            /* if CAN DOWN */
            if(!(global_state->set_a[i].db_state_a[j].flags & CAN_USE)){
                con =
                    global_state->set_a[i].db_state_a[j].dbf.init(
                    &global_state->set_a[i].db_state_a[j].db_url);
                if(!con){
                     LM_DBG("Cant reconnect on timer to db %.*s, %i\n",
                        global_state->set_a[i].db_state_a[j].db_url.len,
                        global_state->set_a[i].db_state_a[j].db_url.s,
                             global_state->set_a[i].db_state_a[j].flags);

                }else{
                    LM_DBG("Can reconnect on timer to db %.*s\n",
                            global_state->set_a[i].db_state_a[j].db_url.len,
                        global_state->set_a[i].db_state_a[j].db_url.s);
                    global_state->set_a[i].db_state_a[j].dbf.close(con);
                    global_state->set_a[i].db_state_a[j].flags |= CAN_USE;
                }
            }
        }
    }
}


int virtual_mod_init(void){
	LM_DBG("VIRTUAL client version is %s\n","1.33");



        if(!global_state){
            int i,j;
            int rc;
            rc = init_global_state();
            rc |= init_private_handles();

            //print structure
            for(i = 0; i< global_state->size; i++){
                LM_DBG("set {%.*s}\n", global_state->set_a[i].set_name.len,
                global_state->set_a[i].set_name.s);
                for(j=0; j< global_state->set_a[i].size; j++){
                    LM_DBG("url \t{%.*s}%p\n",
                    global_state->set_a[i].db_state_a[j].db_url.len,
                    global_state->set_a[i].db_state_a[j].db_url.s,
                    &global_state->set_a[i].db_state_a[j].dbf);
                }
            }

            if(db_reconnect_with_timer){
                if (register_timer_process(reconnect_timer, NULL, db_probe_time,
                        TIMER_PROC_INIT_FLAG) < 0) {
                    LM_ERR("failed to register keepalive timer process\n");
                }
            }

            return rc;
        }

        return 0;
}


static void destroy(void){
	LM_NOTICE("destroy module ...\n");

        int i, j;
        
        if(global_state){
            if(global_state->set_a){
                for(i=0; i< global_state->size; i++){
                    if(global_state->set_a[i].db_state_a){
                        for(j=0; j< global_state->set_a[i].size; j++){
                            if(global_state->set_a[i].db_state_a[j].db_url.s){
                                shm_free(global_state->set_a[i].db_state_a[j].db_url.s);
                            }
                        }
                        shm_free(global_state->set_a[i].db_state_a);
                    }
                }
                shm_free(global_state->set_a);
            }
            shm_free(global_state);
        }
}

int db_virtual_bind_api(const str* mod, db_func_t *dbb)
{
    LM_DBG("BINDING API for virtual url: %.*s\n", mod->len, mod->s);

    int i, j;
    str s;
    //int len;

    if(!global_state)
        if(virtual_mod_init())
            return 1;
    
    if(dbb==NULL)
            return -1;

    memset(dbb, 0, sizeof(db_func_t));


    /*  virtual://set5
     *          p
     */
    s.s = strchr(mod->s, '/');
    s.s +=2;

    
    for(i=0; i< global_state->size; i++){
        if(strncmp(s.s, global_state->set_a[i].set_name.s,
                global_state->set_a[i].set_name.len) == 0)
            break;
    }

    LM_DBG("REDUCING capabilities for %.*s\n",
        global_state->set_a[i].set_name.len, global_state->set_a[i].set_name.s);

    dbb->cap = DB_CAP_FAILOVER;
    for(j=0; j< global_state->set_a[i].size; j++){
        dbb->cap &= global_state->set_a[i].db_state_a[j].dbf.cap;
    }

    if(global_state->set_a[i].set_mode == FAILOVER){
        dbb->cap &= DB_CAP_FAILOVER;
    }else if(global_state->set_a[i].set_mode == PARALLEL){
        dbb->cap &= DB_CAP_PARALLEL;
    }else if(global_state->set_a[i].set_mode == ROUND){
        dbb->cap &= DB_CAP_ROUND;
    }
    
    
    dbb->use_table        = db_virtual_use_table;
    dbb->init             = db_virtual_init;
    dbb->close            = db_virtual_close;
    dbb->query            = db_virtual_query;
    dbb->fetch_result     = db_virtual_fetch_result;
    dbb->raw_query        = db_virtual_raw_query;
    dbb->free_result      = db_virtual_free_result;
    dbb->insert           = db_virtual_insert;
    dbb->delete           = db_virtual_delete;
    dbb->update           = db_virtual_update;
    dbb->replace          = db_virtual_replace;
    dbb->last_inserted_id = db_virtual_last_inserted_id;
    dbb->insert_update    = db_virtual_insert_update;

    return 0;
}

struct mi_root *db_get_info(struct mi_root *cmd, void *param){
    int i,j;
    struct mi_root *rpl_tree;
    struct mi_node *rpl;
    struct mi_node *node;
    struct mi_node *node2;
    struct mi_attr *attr;
    char *p;
    int len;

    int can_use;
    int may_use;
    int recon;
    char buf[MAX_BUF];

    rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
    
    if (rpl_tree==0)
            return 0;
    rpl = &rpl_tree->node;


    for(i=0; i < global_state->size; i++ ){
        node = add_mi_node_child(rpl, 0, MI_SSTR("SET"), 0, 0 );
        if (node==0)
            goto error;

        p = int2str((unsigned long)i, &len);
        attr = add_mi_attr(node, MI_DUP_VALUE, MI_SSTR("i"), p, len);
        if (attr==0)
            goto error;

        attr = add_mi_attr(node, 0, MI_SSTR("name"), global_state->set_a[i].set_name.s,global_state->set_a[i].set_name.len);
        if (attr==0)
            goto error;

        switch(global_state->set_a[i].set_mode){
            case FAILOVER:
                sprintf(buf, "%s", "FAILOVER");
                break;
            case PARALLEL:
                sprintf(buf, "%s", "PARALLEL");
                break;
            case ROUND:
                sprintf(buf, "%s", "ROUND");
                break;
        }

        attr = add_mi_attr(node, MI_DUP_VALUE, MI_SSTR("mode"), buf,strlen(buf));
        if (attr==0)
            goto error;
        
        for(j=0; j< global_state->set_a[i].size; j++){

            node2 = add_mi_node_child(node, 0, MI_SSTR("DB"), 0, 0);
            if(node2 == 0)
                goto error;

            p = int2str((unsigned long)j, &len);
            attr = add_mi_attr(node2, MI_DUP_VALUE, MI_SSTR("j"), p, len);
            if (attr==0)
            goto error;

            attr = add_mi_attr(node2, 0, MI_SSTR("name"), global_state->set_a[i].db_state_a[j].db_url.s,global_state->set_a[i].db_state_a[j].db_url.len);
            if (attr==0)
                goto error;

            can_use = (global_state->set_a[i].db_state_a[j].flags & CAN_USE) ? 1 : 0;
            may_use = (global_state->set_a[i].db_state_a[j].flags & MAY_USE) ? 1 : 0;
            recon = (global_state->set_a[i].db_state_a[j].flags & RERECONNECT) ? 1 : 0;

            p = int2str((unsigned long)can_use, &len);
            LM_DBG("can flag %.*s\n", len, p);
            attr = add_mi_attr(node2, MI_DUP_VALUE, MI_SSTR("can"), p, len);
            if (attr==0)
                goto error;

            p = int2str((unsigned long)may_use, &len);
            LM_DBG("may flag%.*s\n", len, p);
            attr = add_mi_attr(node2, MI_DUP_VALUE, MI_SSTR("may"), p, len);
            if (attr==0)
                goto error;

            p = int2str((unsigned long)recon, &len);
            LM_DBG("reset_recon flag %.*s\n", len, p);
            attr = add_mi_attr(node2, MI_DUP_VALUE, MI_SSTR("r_rec"), p, len);
            if (attr==0)
                goto error;
        }
    }

    return rpl_tree;
    
error:
    LM_ERR("failed to add node\n");
    free_mi_tree(rpl_tree);
    return 0;
};


struct mi_root* db_set_info(struct mi_root* cmd, void* param){
    
    struct mi_node* node= NULL;


    str index1 = {0,0};
    str index2 = {0,0};
    str state = {0,0};
    str recon = {0,0};

    unsigned int nindex1;
    unsigned int nindex2;
    unsigned int nstate;
    unsigned int nrecon = 0;
    int flags;

    

    // get index
    node = cmd->node.kids;
    if(node == NULL){
        LM_ERR("no index1\n");
        return 0;
    }
    index1 = node->value;
    if(index1.s == NULL){
        LM_ERR("empty index1\n");
        return 0;
    }
    if(str2int(&index1, &nindex1)){
        LM_ERR("invalid index1(not int)\n");
        return 0;
    }
    if(nindex1 >= global_state->size || nindex1<0){
        LM_ERR("invalid index1 value\n");
        // fa un return la rezultat
        return 0;
    }


    // get set
    node = node->next;
    if(node == NULL){
        LM_ERR("no index\n");
        return 0;
    }
    index2 = node->value;
    if(index2.s == NULL){
        LM_ERR("empty index\n");
        return 0;
    }
    if(str2int(&index2, &nindex2)){
        LM_ERR("invalid index(not int)\n");
        return 0;
    }
    if(nindex2 >= global_state->set_a[nindex1].size || nindex2<0){
        LM_ERR("invalid index value\n");
        /* fa un return la rezultat */
        return 0;
    }


    /* get may state 1=UP 0=DOWN */
    node = node->next;
    if(node == NULL){
        LM_ERR("no state\n");
        return 0;
    }
    state= node->value;
    if(state.s == NULL){
            LM_ERR("empty state\n");
            return 0;
    }
    if(str2int(&state, &nstate)){
        LM_ERR("invalid state(not int)\n");
        return 0;
    }
    if(!(nstate==1 || nstate==0)){
        LM_ERR("invalid state value\n");
        return 0;
    }

    flags = global_state->set_a[nindex1].db_state_a[nindex2].flags;

    /* get possible rerecon state 1=UP 0= DOWN */
    node = node->next;
    if(node != NULL){
        recon= node->value;
        if(recon.s == NULL){
                LM_ERR("empty recon\n");
                return 0;
        }
        if(str2int(&recon, &nrecon)){
            LM_ERR("invalid recon(not int)\n");
            return 0;
        }
        if(!(nrecon==1 || nrecon==0)){
            LM_ERR("invalid recon value\n");
            return 0;
        }

        if(nrecon)
            flags |= RERECONNECT;
        else
            flags &= NOT_RERECONNECT;
    }

    if(nstate)
        flags |= MAY_USE;
    else
        flags &=NOT_MAY_USE;

    
    
    global_state->set_a[nindex1].db_state_a[nindex2].flags = flags;  
    /* dont worry about race conditions */
    
    return init_mi_tree( 200, MI_SSTR(MI_OK));
}