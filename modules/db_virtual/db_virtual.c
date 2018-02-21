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
info_global_t * global = NULL;

/* dbs handles in private memory local to each process */
//handle_set_t * private_handles = NULL;
handle_private_t * private = NULL;

/* db_urls pointer older until initialization */
char*   db_urls_list[100];
int     db_urls_count=0;




int init_global(void);
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
	{"db_bind_api",         (cmd_function)db_virtual_bind_api, 0, 0, 0, 0},
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
        {"db_get",      0, db_get_info,       MI_NO_INPUT_FLAG,  0,  0 },
        {"db_set",      0, db_set_info,       0,  0,  0 },
        //{"db_add",      db_add_url,        0,  0,  0 },
	{ 0, 0, 0, 0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_SQLDB, NULL, DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"db_virtual",
	MOD_TYPE_SQLDB,   /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,  /* dlopen flags */
	&deps,            /* OpenSIPS module dependencies */
	cmds,
	0,
	params,           /*  module parameters */
	0,                /* exported statistics */
	mi_cmds,          /* exported MI functions */
	0,                /* exported pseudo-variables */
	0,                /* extra processes */
	virtual_mod_init, /* module initialization function */
	0,                /* response function*/
	destroy,          /* destroy function */
	0                 /* per-child init function */
};


int add_url(int index, char * name){

    LM_DBG("add url (%i . %s)\n", index, name);

    int i;

    LM_DBG("add another url %p\n", global->set_list[index].db_list);

    /* realoc */
    i = global->set_list[index].size;

    /* db_list realloc */
    global->set_list[index].db_list =
        (info_db_t *) shm_realloc(global->set_list[index].db_list,
        (i+1)* sizeof(info_db_t));

    if(!global->set_list[index].db_list)
        MEM_ERR(MEM_SHM);

    global->set_list[index].size++;

    /* db_url */
    global->set_list[index].db_list[i].db_url.s =
            (char *) shm_malloc(strlen(name) * sizeof(char));
    global->set_list[index].db_list[i].db_url.len = strlen(name);
    memcpy(global->set_list[index].db_list[i].db_url.s,
            name, strlen(name));

    global->set_list[index].db_list[i].flags = CAN_USE | MAY_USE;
    return 0;

error:
    return 1;
}

int add_set(char * name, char * mode){

    int nmode = 0;

    if(strncmp(mode, "FAILOVER", strlen("FAILOVER")) == 0)
        nmode = FAILOVER;
    else if(strncmp(mode, "PARALLEL", strlen("PARALLEL")) == 0)
        nmode = PARALLEL;
    else if(strncmp(mode, "ROUND", strlen("ROUND")) == 0)
        nmode = ROUND;

    LM_DBG("add set=%s mode=%i\n", name, nmode);

	if (!global) {
        global = shm_malloc(sizeof *global);

		if (!global)
			MEM_ERR(MEM_SHM);

	    memset(global, 0, sizeof *global);
	}

    /* realloc set_list */
    int i = global->size;
    global->set_list = (info_set_t *)shm_realloc(global->set_list,
                            (i+1)*sizeof(info_set_t));
    if(!global->set_list)
        MEM_ERR(MEM_SHM);

    memset(&global->set_list[i], 0, sizeof *global->set_list);

    global->size++;

    global->set_list[i].set_name.s =
            (char *) shm_malloc(strlen(name)*sizeof(char));
    global->set_list[i].set_name.len = strlen(name);
    memcpy(global->set_list[i].set_name.s, name, strlen(name));

    /* set mode */
    global->set_list[i].set_mode = nmode;

    global->set_list[i].size = 0;

    return 0;

error:
    return 1;
}

static int store_urls( modparam_t type, void* val){

    db_urls_list[db_urls_count] = val;
    db_urls_count++;

    return 0;
}


int init_global(void){//str *info_set_mapping){



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
				if (count == -1) {
					LM_ERR("db_virtual module cannot start with no DB sets defined!\n");
					return -1;
				}

                /* mysql:........ */
                LM_DBG("db = %s\n", s);
                add_url(count, s);
            }
        }
    }

	if (!global) {
		LM_ERR("db_virtual module cannot start with no DB URLs defined!\n");
		return -1;
	}

    for(i = 0; i< global->size; i++)
        for(j=0; j<global->set_list[i].size; j++){

            global->set_list[i].db_list[j].dbf.cap = 0;

            if(db_bind_mod(&global->set_list[i].db_list[j].db_url,
                    &global->set_list[i].db_list[j].dbf)){
                LM_ERR("cant bind db : %.*s",
			global->set_list[i].db_list[j].db_url.len,
                        global->set_list[i].db_list[j].db_url.s);
                goto error;
            }
        }

    LM_DBG("global done\n");
    /*is_initialized = 1; */
    return 0;

    error:

    destroy();
    return -1;
}

int init_private_handles(void){

    LM_DBG("Init private handles\n");


    private = (handle_private_t* ) pkg_malloc(sizeof(handle_private_t));
    if(!private)
	MEM_ERR(MEM_PKG);

    memset(private, 0, sizeof(handle_private_t));


    private->size = global->size;
    private->hset_list = (handle_set_t*)pkg_malloc(private->size * sizeof(handle_set_t));
    if(!private->hset_list)
	MEM_ERR(MEM_PKG);

    memset(private->hset_list, 0, private->size * sizeof(handle_set_t));

    return 0;

    error:
    return -1;
}

static void reconnect_timer(unsigned int ticks, void *data)
{
    LM_DBG("reconnect with timer\n");
    int i,j;

    db_con_t * con;

    for(i=0; i < global-> size; i++){
        for(j=0; j < global->set_list[i].size; j++){
            /* if CAN DOWN */
            if(!(global->set_list[i].db_list[j].flags & CAN_USE)){
                con =
                    global->set_list[i].db_list[j].dbf.init(
                    &global->set_list[i].db_list[j].db_url);
                if(!con){
                     LM_DBG("Cant reconnect on timer to db %.*s, %i\n",
                        global->set_list[i].db_list[j].db_url.len,
                        global->set_list[i].db_list[j].db_url.s,
                             global->set_list[i].db_list[j].flags);

                }else{
                    LM_DBG("Can reconnect on timer to db %.*s\n",
                            global->set_list[i].db_list[j].db_url.len,
                        global->set_list[i].db_list[j].db_url.s);
                    global->set_list[i].db_list[j].dbf.close(con);
                    global->set_list[i].db_list[j].flags |= CAN_USE;
                }
            }
        }
    }
}


int virtual_mod_init(void){
	LM_DBG("VIRTUAL client version is %s\n","1.33");



        if(!global){
            int i,j;
            if (init_global() || init_private_handles())
				return -1;

            //print structure
            for(i = 0; i< global->size; i++){
                LM_DBG("set {%.*s}\n", global->set_list[i].set_name.len,
                global->set_list[i].set_name.s);
                for(j=0; j< global->set_list[i].size; j++){
                    LM_DBG("url \t{%.*s}%p\n",
                    global->set_list[i].db_list[j].db_url.len,
                    global->set_list[i].db_list[j].db_url.s,
                    &global->set_list[i].db_list[j].dbf);
                }
            }

            if(db_reconnect_with_timer){
                if (register_timer("db_virtual-reconnect",
                        reconnect_timer, NULL, db_probe_time,
                        TIMER_FLAG_DELAY_ON_DELAY)<0) {
                    LM_ERR("failed to register keepalive timer\n");
                }
            }
        }

        return 0;
}


static void destroy(void){
	LM_NOTICE("destroying module...\n");

        int i, j;

        if(global){
            if(global->set_list){
                for(i=0; i< global->size; i++){
                    if(global->set_list[i].db_list){
                        for(j=0; j< global->set_list[i].size; j++){
                            if(global->set_list[i].db_list[j].db_url.s){
                                shm_free(global->set_list[i].db_list[j].db_url.s);
                            }
                        }
                        shm_free(global->set_list[i].db_list);
                    }
                }
                shm_free(global->set_list);
            }
            shm_free(global);
        }
}

int db_virtual_bind_api(const str* mod, db_func_t *dbb)
{
    LM_DBG("BINDING API for virtual url: %.*s\n", mod->len, mod->s);

    int i, j;
    str s;
    //int len;

    if(!global)
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


    for(i=0; i< global->size; i++){
        if(strncmp(s.s, global->set_list[i].set_name.s,
                global->set_list[i].set_name.len) == 0)
            break;
    }

    dbb->cap = global->set_list[i].db_list[0].dbf.cap;
    for(j=1; j< global->set_list[i].size; j++){
        dbb->cap &= global->set_list[i].db_list[j].dbf.cap;
    }

    LM_DBG("Computed capabilities for %.*s are %x\n",
        global->set_list[i].set_name.len, global->set_list[i].set_name.s,
        dbb->cap);

    dbb->use_table         = db_virtual_use_table;
    dbb->init              = db_virtual_init;
    dbb->close             = db_virtual_close;
    dbb->query             = db_virtual_query;
    dbb->fetch_result      = db_virtual_fetch_result;
    dbb->raw_query         = db_virtual_raw_query;
    dbb->free_result       = db_virtual_free_result;
    dbb->insert            = db_virtual_insert;
    dbb->delete            = db_virtual_delete;
    dbb->update            = db_virtual_update;
    dbb->replace           = db_virtual_replace;
    dbb->last_inserted_id  = db_virtual_last_inserted_id;
    dbb->insert_update     = db_virtual_insert_update;
    dbb->async_raw_query   = db_virtual_async_raw_query;
    dbb->async_resume      = db_virtual_async_resume;
    dbb->async_free_result = db_virtual_async_free_result;

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
    rpl->flags |= MI_IS_ARRAY;


    for(i=0; i < global->size; i++ ){
        node = add_mi_node_child(rpl, MI_IS_ARRAY, MI_SSTR("SET"), 0, 0 );
        if (node==0)
            goto error;

        p = int2str((unsigned long)i, &len);
        attr = add_mi_attr(node, MI_DUP_VALUE, MI_SSTR("i"), p, len);
        if (attr==0)
            goto error;

        attr = add_mi_attr(node, 0, MI_SSTR("name"),
	    global->set_list[i].set_name.s,global->set_list[i].set_name.len);
        if (attr==0)
            goto error;

        switch(global->set_list[i].set_mode){
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

        attr = add_mi_attr(node, MI_DUP_VALUE, MI_SSTR("mode"),
		buf,strlen(buf));
        if (attr==0)
            goto error;

        for(j=0; j< global->set_list[i].size; j++){

            node2 = add_mi_node_child(node, 0, MI_SSTR("DB"), 0, 0);
            if(node2 == 0)
                goto error;

            p = int2str((unsigned long)j, &len);
            attr = add_mi_attr(node2, MI_DUP_VALUE, MI_SSTR("j"), p, len);
            if (attr==0)
            goto error;

            attr = add_mi_attr(node2, 0, MI_SSTR("name"),
		global->set_list[i].db_list[j].db_url.s,
		global->set_list[i].db_list[j].db_url.len);
            if (attr==0)
                goto error;

            can_use = (global->set_list[i].db_list[j].flags & CAN_USE) ? 1 : 0;
            may_use = (global->set_list[i].db_list[j].flags & MAY_USE) ? 1 : 0;
            recon = (global->set_list[i].db_list[j].flags & RERECONNECT) ? 1 :0;

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
}


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
    if(nindex1 >= global->size){
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
    if(nindex2 >= global->set_list[nindex1].size){
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

    flags = global->set_list[nindex1].db_list[nindex2].flags;

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



    global->set_list[nindex1].db_list[nindex2].flags = flags;
    /* don't worry about race conditions */

    return init_mi_tree( 200, MI_SSTR(MI_OK));
}

