/*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2006 Voice-Sistem SRL
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
 *
 * History:
 * -------
 * 2003-08-21: cpl_remove() added (bogdan)
 * 2003-06-24: file created (bogdan)
 */


#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include "../../str.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../parser/parse_uri.h"
#include "../../mi/mi.h"
#include "cpl_db.h"
#include "cpl_env.h"
#include "cpl_parser.h"
#include "cpl_loader.h"


extern db_con_t* db_hdl;

#if 0
/* debug function -> write into a file the content of a str struct. */
int write_to_file(char *filename, str *buf)
{
	int fd;
	int ret;

	fd = open(filename,O_WRONLY|O_CREAT|O_TRUNC,0644);
	if (!fd) {
		LM_ERR("cannot open file : %s\n",
			strerror(errno));
		goto error;
	}

	while ( (ret=write( fd, buf->s, buf->len))!=buf->len) {
		if ((ret==-1 && errno!=EINTR)|| ret!=-1) {
			LM_ERR("cannot write to file:"
				"%s write_ret=%d\n",strerror(errno), ret );
			goto error;
		}
	}
	close(fd);

	return 0;
error:
	return -1;
}
#endif



/* Loads a file into a buffer; first the file length will be determined for
 * allocated an exact buffer len for storing the file content into.
 * Returns:  1 - success
 *          -1 - error
 */
int load_file( char *filename, str *xml)
{
	int n;
	int offset;
	int fd;

	xml->s = 0;
	xml->len = 0;

	/* open the file for reading */
	fd = open(filename,O_RDONLY);
	if (fd==-1) {
		LM_ERR("cannot open file for reading:"
			" %s\n",strerror(errno));
		goto error;
	}

	/* get the file length */
	if ( (xml->len=lseek(fd,0,SEEK_END))==-1) {
		LM_ERR("cannot get file length (lseek):"
			" %s\n", strerror(errno));
		goto error;
	}
	LM_DBG("file size = %d\n",xml->len);
	if ( lseek(fd,0,SEEK_SET)==-1 ) {
		LM_ERR("cannot go to beginning (lseek):"
			" %s\n",strerror(errno));
		goto error;
	}

	/* get some memory */
	xml->s = (char*)pkg_malloc( xml->len+1/*null terminated*/ );
	if (!xml->s) {
		LM_ERR("no more free pkg memory\n");
		goto error;
	}

	/*start reading */
	offset = 0;
	while ( offset<xml->len ) {
		n=read( fd, xml->s+offset, xml->len-offset);
		if (n==-1) {
			if (errno!=EINTR) {
				LM_ERR("read failed:"
					" %s\n", strerror(errno));
				goto error;
			}
		} else {
			if (n==0) break;
			offset += n;
		}
	}
	if (xml->len!=offset) {
		LM_ERR("couldn't read all file!\n");
		goto error;
	}
	xml->s[xml->len] = 0;

	close(fd);
	return 1;
error:
	if (fd!=-1) close(fd);
	if (xml->s)
		/* coverity[tainted_data] */
		pkg_free( xml->s);
	return -1;
}



/* Writes an array of texts into the given response file.
 * Accepts also empty texts, case in which it will be created an empty
 * response file.
 */
void write_to_file( char *file, str *txt, int n )
{
	int fd;

	/* open file for write */
	fd = open( file, O_WRONLY|O_CREAT|O_TRUNC/*|O_NOFOLLOW*/, 0600 );
	if (fd==-1) {
		LM_ERR("cannot open response file "
			"<%s>: %s\n", file, strerror(errno));
		return;
	}

	/* write the txt, if any */
	if (n>0) {
again:
		if ( writev( fd, (struct iovec*)txt, n)==-1) {
			if (errno==EINTR) {
				goto again;
			} else {
				LM_ERR("write_logs_to_file: writev failed: "
					"%s\n", strerror(errno) );
			}
		}
	}

	/* close the file*/
	close( fd );
	return;
}


/**************************** MI ****************************/
#define FILE_LOAD_ERR_S   "Cannot read CPL file"
#define DB_SAVE_ERR_S     "Cannot save CPL to database"
#define CPLFILE_ERR_S     "Bad CPL file"
#define USRHOST_ERR_S     "Bad user@host"
#define DB_RMV_ERR_S      "Database remove failed"
#define DB_RMV_ERR_LEN    (sizeof(DB_RMV_ERR_S)-1)
#define DB_GET_ERR_S      "Database query failed"

mi_response_t *mi_cpl_load(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct sip_uri uri;
	str xml = {0,0};
	str bin = {0,0};
	str enc_log = {0,0};
	char *file;
	str username, cpl_file;
	mi_response_t *resp;

	LM_DBG("\"LOAD_CPL\" MI command received!\n");

	if (get_mi_string_param(params, "username", &username.s, &username.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "cpl_filename", &cpl_file.s, &cpl_file.len) < 0)
		return init_mi_param_error();

	if (parse_uri( username.s, username.len, &uri)!=0){
		LM_ERR("invalid sip URI [%.*s]\n",
			username.len, username.s);
		return init_mi_error(400, MI_SSTR(USRHOST_ERR_S));
	}
	LM_DBG("user@host=%.*s@%.*s\n",
		uri.user.len,uri.user.s,uri.host.len,uri.host.s);

	/* second argument is the cpl file */
	file = pkg_malloc(cpl_file.len+1);
	if (file==NULL) {
		LM_ERR("no more pkg mem\n");
		return 0;
	}
	memcpy( file, cpl_file.s, cpl_file.len);
	file[cpl_file.len]= '\0';

	/* load the xml file - this function will allocated a buff for the loading
	 * the cpl file and attach it to xml.s -> don't forget to free it! */
	if (load_file( file, &xml)!=1) {
		pkg_free(file);
		return init_mi_error(500, MI_SSTR(FILE_LOAD_ERR_S));
	}
	LM_DBG("cpl file=%s loaded\n",file);
	pkg_free(file);

	/* get the binary coding for the XML file */
	if (encodeCPL( &xml, &bin, &enc_log)!=1) {
		resp = init_mi_error_extra(500, MI_SSTR(CPLFILE_ERR_S),
						enc_log.s, enc_log.len);
		goto error;
	}

	/* write both the XML and binary formats into database */
	if (write_to_db( &uri.user,cpl_env.use_domain?&uri.host:0, &xml, &bin)!=1){
		resp = init_mi_error(500, MI_SSTR(DB_SAVE_ERR_S));
		goto error;
	}

	/* everything was OK */
	return init_mi_result_ok();

error:
	if (enc_log.s)
		pkg_free ( enc_log.s );
	if (xml.s)
		pkg_free ( xml.s );
	return resp;
}


mi_response_t *mi_cpl_remove(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct sip_uri uri;
	str user;

	LM_DBG("\"REMOVE_CPL\" MI command received!\n");

	if (get_mi_string_param(params, "username", &user.s, &user.len) < 0)
		return init_mi_param_error();

	/* check user+host */
	if (parse_uri( user.s, user.len, &uri)!=0){
		LM_ERR("invalid SIP uri [%.*s]\n",
			user.len,user.s);
		return init_mi_error(400, MI_SSTR(USRHOST_ERR_S));
	}
	LM_DBG("user@host=%.*s@%.*s\n",
		uri.user.len,uri.user.s,uri.host.len,uri.host.s);

	if (rmv_from_db( &uri.user, cpl_env.use_domain?&uri.host:0)!=1)
		return init_mi_error(500, MI_SSTR(DB_RMV_ERR_S));

	return init_mi_result_ok();
}


mi_response_t *mi_cpl_get(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	struct sip_uri uri;
	str script = {0,0};
	str user;

	if (get_mi_string_param(params, "username", &user.s, &user.len) < 0)
		return init_mi_param_error();

	/* check user+host */
	if (parse_uri( user.s, user.len, &uri)!=0) {
		LM_ERR("invalid user@host [%.*s]\n",
			user.len,user.s);
		return init_mi_error(400, MI_SSTR(USRHOST_ERR_S));
	}
	LM_DBG("user@host=%.*s@%.*s\n",
		uri.user.len,uri.user.s,uri.host.len,uri.host.s);

	/* get the script for this user */
	str query_str = str_init("cpl_xml");
	if (get_user_script( &uri.user, cpl_env.use_domain?&uri.host:0,
	&script, &query_str)==-1)
		return init_mi_error(500, MI_SSTR(DB_GET_ERR_S));

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	/* write the response into response file - even if script is null */
	if (add_mi_string(resp_obj, MI_SSTR("script"), script.s, script.len) < 0) {
		free_mi_response(resp);
		return 0;
	}

	if (script.s)
		shm_free( script.s );

	return resp;
}
