/*
 * Copyright (C) 2007-2008 1&1 Internet AG
 *
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
 */

/**
 * @file load_data.c
 * @brief API to bind a data loading function.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../../globals.h"
#include "load_data.h"
#include "route_db.h"
#include "route_config.h"
#include "carrierroute.h"

/**
 * Binds the loader function pointer api to the matching loader
 * function depending on source
 *
 * @param source the configuration data source, at the moment
 * it can be db or file
 * @param api pointer to the api where the loader function is
 * bound to
 *
 * @return 0 means everything is ok, -1 means an error
 */
int bind_data_loader(const char * source, route_data_load_func_t * api){
	struct stat fs;
	if(strcmp(source, "db") == 0){
		LM_INFO("use database as configuration source");
		*api = load_route_data;
		mode = SP_ROUTE_MODE_DB;
		if(db_init() < 0){
			return -1;
		}
		return 0;
	}
	if(strcmp(source, "file") == 0){
		LM_INFO("use file as configuration source");
		*api = load_config;
		mode = SP_ROUTE_MODE_FILE;
		if(stat(config_file, &fs) != 0){
			LM_ERR("can't stat config file\n");
			return -1;
		}
		if(fs.st_mode & S_IWOTH){
			LM_WARN("insecure file permissions, routing data is world writable");
		}
		if( !( fs.st_mode & S_IWOTH) &&
			!((fs.st_mode & S_IWGRP) && (fs.st_gid == getegid())) &&
			!((fs.st_mode & S_IWUSR) && (fs.st_uid == geteuid())) ) {
				LM_ERR("config file not writable\n");
				return -1;
			}
		return 0;
	}
	LM_ERR("could not bind configuration source <%s>", source);
	return -1;
}

int data_main_finalize(void){
	if(mode == SP_ROUTE_MODE_DB){
		main_db_close();
	}
	return 0;
}

int data_child_init(void){
	if(mode == SP_ROUTE_MODE_DB){
		return db_child_init();
	}
	return 0;
}

void data_destroy(void){
	if(mode == SP_ROUTE_MODE_DB){
		db_destroy();
	}
	return;
}
