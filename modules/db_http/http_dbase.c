/*
 * $Id$
 *
 * Copyright (C) 2009 Voice Sistem SRL
 * Copyright (C) 2009 Andrei Dragus
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * History:
 * ---------
 *  2009-08-12  first version (andreidragus)
 */


#include "http_dbase.h"
#include "../../db/db_id.h"
#include "../../db/db_ut.h"
#include "../../db/db_row.h"
#include <curl/curl.h>

typedef struct _http_conn
{

	CURL * handle;
	str  start;
	int last_id;
} http_conn_t;

typedef struct var_str_t
{
	char * s;
	int len;
	int allocated;

} var_str;



enum
{
	QUERY,
	INSERT,
	DELETE,
	UPDATE,
	REPLACE,
	INSERT_UPDATE,
	CUSTOM
};

enum
{
	IN = 0,
	OUT = 1,
	ESC = 2
};

int next_state[3][256];

char line_delim = '\n';
char col_delim = ';';
char quote_delim = '|';

extern int use_ssl;

char error_buffer[CURL_ERROR_SIZE];


#define CHECK( val,expected,err_tag)		\
{						\
	if( (val) != (expected) )		\
		goto err_tag;			\
}	




int set_col_delim( unsigned int type, void *val)
{
	char * v = (char*) val;

	if( strlen(val) != 1)
	{
		LM_ERR("Only one field delimiter may be set\n");
		return -1;
	}
	col_delim = v[0];

	return 0;
}

int set_line_delim( unsigned int type, void *val)
{
	char * v = (char*) val;

	if( strlen(val) != 1)
	{
		LM_ERR("Only one field delimiter may be set\n");
		return -1;
	}
	line_delim = v[0];

	return 0;
}

int set_quote_delim( unsigned int type, void *val)
{
	char * v = (char*) val;

	if( strlen(val) != 1)
	{
		LM_ERR("Only one field delimiter may be set\n");
		return -1;
	}
	quote_delim = v[0];

	return 0;
}




str value_to_string(const db_val_t * v);
str url_encode(str s);



static int append_str( var_str * to, str from)
{
	if(to->len + from.len > to->allocated)
	{
		to->s = (char*) pkg_realloc(to->s, to->len + from.len + 1);
		to->allocated = to->len + from.len;

		if( to->s == NULL)
		{
			LM_ERR("Out of memory\n");
			return -1;
		}
	}

	memcpy( to->s+to->len, from.s, from.len );
	to->len += from.len;

	to->s[to->len] = 0;

	return 0;

}

static int append_const(var_str* to, char * from)
{
	static str temp;

	temp.s = from;
	temp.len = strlen(from);

	return append_str(to,temp);
}


static int append_keys (var_str * q,const char * name, const db_key_t* k,
		int n, int * started )
{
	int i;

	if( k != NULL)
	{
		if( *started )
			CHECK(append_const(q,"&"),0,error);

		CHECK(append_const(q,(char*)name),0,error);
		CHECK(append_const(q,"="),0,error);
		
		for(i=0;i<n;i++)
		{

			CHECK(append_str(q,url_encode(*k[i])),0,error);
			if( i < n-1)
				CHECK(append_const(q,","),0,error);
		}
		*started = 1;
	}

	return 0;

error:
	return -1;

}

static int append_values (var_str * q,const char * name, const db_val_t* v,
		int n, int * started )
{	
	int i;

	if( v != NULL)
	{
		if( *started )
			CHECK(append_const(q,"&"),0,error);

		CHECK(append_const(q,(char*)name),0,error);
		CHECK(append_const(q,"="),0,error);

		for(i=0;i<n;i++)
		{
			CHECK(append_str(q,url_encode(value_to_string(&v[i]))),0,error);
			if( i < n-1)
				CHECK(append_const(q,","),0,error);
		}

		*started = 1;

	}
	return 0;

error:
	return -1;

}

static int append_ops(var_str * q,const char * name, const db_op_t* op,
		int n, int * started )
{
	int i;
	
	if( op != NULL)
	{
		if( *started )
			CHECK(append_const(q,"&"),0,error);

		CHECK(append_const(q,(char*)name),0,error);
		CHECK(append_const(q,"="),0,error);

		for(i=0;i<n;i++)
		{

			str tmp;

			tmp.s = (char*)op[i];
			tmp.len = strlen(tmp.s);

			CHECK(append_str(q,url_encode(tmp)),0,error);



			if( i < n-1)
				CHECK(append_const(q,","),0,error);
		}
		*started = 1;
	}
	return 0;

error:
	return -1;
}


size_t receive(void *buffer, size_t size, size_t nmemb, void *userp)
{
	var_str * buff;
	str temp;

	buff = (var_str*) userp;

	temp.s = (char*)buffer;
	temp.len = size * nmemb;

	append_str(buff,temp);


	return temp.len;


}






db_res_t * new_full_db_res(int rows, int cols)
{
	db_res_t * res;
	int i;

	res = db_new_result();

	if( res == NULL)
	{
		LM_ERR("Error allocating db result\n");
		return NULL;
	}

	if( db_allocate_columns(res,cols) < 0)
	{
		LM_ERR("Error allocating db result columns\n");
		pkg_free(res);
		return NULL;
	}
	res->col.n = cols;

	if( db_allocate_rows(res,rows) < 0 )
	{
		LM_ERR("Error allocating db result rows\n");
		db_free_columns( res );
		pkg_free(res);
		return NULL;
	}

	res->n = rows;
	res->res_rows = rows;
	res->last_row = rows;

	
	for( i=0;i<rows;i++)
		res->rows[i].n = cols;

	return res;
}



int put_type_in_result( char * start, int len , db_res_t * res , int cur_col )
{
	int ok = 0;

	LM_DBG("Found type: %.*s %d\n",len,start,len);

	if( len == 3 && !strncmp (start,"int",len))
	{
		res->col.types[cur_col] = DB_INT;
		ok = 1;
	}
	if( len == 6 && !strncmp (start,"double",len))
	{
		res->col.types[cur_col] = DB_DOUBLE;
		ok = 1;
	}
	if( len == 6 && !strncmp (start,"string",len))
	{
		res->col.types[cur_col] = DB_STRING;
		ok = 1;
	}
	
	if( len == 3 && !strncmp (start,"str",len))
	{
		res->col.types[cur_col] = DB_STR;
		ok = 1;
	}
	if( len == 4 && !strncmp (start,"blob",len))
	{
		res->col.types[cur_col] = DB_BLOB;
		ok = 1;
	}
	if( len == 4 && !strncmp (start,"date",len))
	{
		res->col.types[cur_col] = DB_DATETIME;
		ok = 1;
	}


	if( !ok )
		LM_ERR("Unknown datatype\n");
	
	return 1 - ok;
	
}

int put_value_in_result(  char * start, int len , db_res_t * res ,
		int cur_col, int cur_line )
{


	db_val_t * row;

	LM_DBG("Found value: %.*s\n",len,start);

	row = res->rows[cur_line].values;
	row[cur_col].type = res->col.types[cur_col];

	
	if( len == 0 && (res->col.types[cur_col] != DB_BLOB )
		&& (res->col.types[cur_col] != DB_STRING )
		&& (res->col.types[cur_col] != DB_STR )
	  )
	{
		row[cur_col].nul = 1;
		return 0;
	}
	
	switch(res->col.types[cur_col])
	{
		case( DB_INT):
			CHECK( sscanf(start,"%d",&row[cur_col].val.int_val), 1, error);
			break;

		case( DB_DOUBLE):
			CHECK( sscanf(start,"%lf",&row[cur_col].val.double_val), 1, error);
			break;

		case( DB_STRING):
			row[cur_col].val.string_val = start;
			break;

		case( DB_STR):
		case( DB_BLOB):
			row[cur_col].val.blob_val.s = start;
			row[cur_col].val.blob_val.len = len;
			break;

		case( DB_DATETIME):
			CHECK( db_str2time(start,&row[cur_col].val.time_val), 0, error);
			break;
		default:
			break;

	}

	return 0;


error:
	LM_ERR("Unable to parse value: %.*s\n",len,start);
	return -1;
}

int form_result(var_str buff, db_res_t** r)
{
	db_res_t * res;
	char * cur, * dest, * start, * end;
	int col_count, cur_col, line_count, cur_line, delim_count, len;
	int state, next, first_line, consume;

	
	LM_DBG("Called with : %.*s\n",buff.len,buff.s);




	end = buff.s + buff.len;
	res = NULL;

	if( buff.len == 0 )
	{
		*r = new_full_db_res(0,0);
		return 0;
	}


	state = OUT;
	cur = buff.s;

	col_count = 0;
	cur_col = 0;
	cur_line = -1;
	delim_count = 0;


	while( cur < end )
	{

		next = next_state[ state ][ (int)((unsigned char)*cur) ];
		consume = 1;

		if( state == OUT )
		{
			if( *cur == col_delim )
			{
				cur_col++;
				delim_count++;
			}

			if( *cur == line_delim )
			{
				cur_col++;
				if( cur_line == -1 )
					col_count = cur_col;
				else
					if(cur_col != col_count)
						goto error_before;

				delim_count++;
				cur_line++;
				cur_col = 0;
			}

		}

		if( state == ESC )
		{
			/* do not consume other characters than 'quote_delim' */
			if( *cur != quote_delim )
				consume = 0;
		}

		if( consume)
			cur++;

		state = next;

	}

	line_count = cur_line;

	
	if( col_count == 0 || line_count == 0 )
		goto error_before;



	/* validate input */

	if( delim_count != (line_count+1)*col_count)
		goto error_before;


	


	/* allocate all necessary info */

	res = new_full_db_res(line_count,col_count);

	if( res == NULL )
		return -1;
	


	state = OUT;
	cur = buff.s;
	dest = buff.s;

	cur_col = 0;
	cur_line = -1;
	first_line = 1;
	start = dest;

	while( cur < end )
	{
		

		next = next_state[ state ][ (int)((unsigned char)*cur) ];
		consume =  1;
		if( state == OUT )
		{

			if( *cur == col_delim )
			{
				len = dest - start;
				start[len] = 0;

				if( cur_line == -1 )
					CHECK( put_type_in_result(start,len,
						res,cur_col), 0, error)
				
				else
					CHECK( put_value_in_result(start,len,
						res,cur_col,cur_line),0,error)

				dest = start + len + 1;
				start = dest;
				cur_col++;

				
			}
			else
			if( *cur == line_delim )
			{
				len = dest - start;
				start[len] = 0;

				if( cur_line == -1 )
					put_type_in_result(start,len,res,cur_col);

				else
					put_value_in_result(start,len,res,cur_col,cur_line);

				dest = start + len + 1;
				start = dest;

				cur_line++;
				cur_col = 0;
			
			}
			else
			if( *cur != quote_delim )
			{
				*dest++ = *cur;
			}


		}


		if( state == ESC )
		{
			if( *cur != quote_delim )
				consume = 0;
			else
				*dest++ = *cur;
			
		}

		if( state == IN )
		{
			if( *cur != quote_delim )
				*dest++ = *cur;

		}

		if( consume )
			cur++;

		state = next;

	}



	

	LM_DBG("Finished query\n");


	*r = res;
	return 0;

error:
	db_http_free_result(NULL,res);

error_before:

	LM_ERR("Error parsing HTTP reply\n");
	return -1;

	
}

int do_http_op (  const db_con_t* h, const db_key_t* k, const db_op_t* op,
	     const db_val_t* v, const int n, const db_key_t* c, const int nc,
	     const db_key_t* uk, const db_val_t* uv, const int nu,
	     const db_key_t o, const str* custom, db_res_t** r,   int db_op )

{


	LM_DBG("Called with db_op=%d\n",db_op);

	static var_str q = {0,0,0};
	static var_str buff = {0,0,0};
	http_conn_t * conn ;
	int started = 0;
	int middle_poz;
	CURLcode ret;

	ret = 0;
	q.len = 0;
	buff.len = 0;
	middle_poz = 0;

	conn = (http_conn_t*) h->tail;

	/* put the http adress */
	CHECK( append_str(&q,conn->start), 0, error);



	if( h->table->s == NULL)
	{
		LM_ERR("No table selected for op");
		goto error;
	}

	/* put the table name */
	CHECK( append_str(&q,*h->table), 0, error);

	/* for operations other than querie use POST */
	if( db_op == QUERY || db_op == CUSTOM )
	{
		/* put the queries */
		CHECK( append_const(&q,"/?"), 0, error);

	}
	else
	{
		str tmp;
		tmp.s="\0";
		tmp.len = 1;
		CHECK( append_str(&q,tmp), 0, error);
		middle_poz = q.len;
	}

	CHECK( append_keys(&q,"k",k,n,&started), 0, error);
	CHECK( append_ops(&q,"op",op,n,&started), 0, error);
	CHECK( append_values(&q,"v",v,n,&started), 0, error);
	CHECK( append_keys(&q,"c",c,nc,&started), 0, error);
	CHECK( append_keys(&q,"uk",uk,nu,&started), 0, error);
	CHECK( append_values(&q,"uv",uv,nu,&started), 0, error);

	if( o != NULL)
	{
		if( started)
			CHECK( append_const(&q,"&"), 0, error);

		CHECK( append_const(&q,"o="), 0, error);
		CHECK( append_str(&q,url_encode(*o)) ,0, error);

		started = 1;
	}

	if( custom != NULL)
	{
		if( started)
			CHECK( append_const(&q,"&"), 0, error);

		CHECK( append_const(&q,"q="), 0, error);
		CHECK( append_str(&q,url_encode(*custom)) ,0, error);

		started = 1;
	}


	if( started && db_op != QUERY)
	{
		CHECK( append_const(&q,"&"), 0, error);
	}

	switch(db_op)
	{

		case(QUERY):
			break;
		case(INSERT):
			CHECK( append_const(&q,"query_type=insert"), 0, error);
			break;
		case(DELETE):
			CHECK( append_const(&q,"query_type=delete"), 0, error);
			break;
		case(UPDATE):
			CHECK( append_const(&q,"query_type=update"), 0, error);
			break;
		case(REPLACE):
			CHECK( append_const(&q,"query_type=replace"), 0, error);
			break;
		case(INSERT_UPDATE):
			CHECK( append_const(&q,"query_type=insert_update"), 0, error);
			break;
		case(CUSTOM):
			CHECK( append_const(&q,"query_type=custom"), 0, error);
			break;
		default:
			LM_ERR("Unknown db operation\n");
			return -1;

	}

	
	q.s[q.len] = 0 ;

	

	LM_DBG("Sent:%s \n",q.s);

	curl_easy_setopt(conn->handle, CURLOPT_HTTPGET, 1);
	curl_easy_setopt(conn->handle, CURLOPT_URL, q.s);

	
	curl_easy_setopt(conn->handle, CURLOPT_WRITEFUNCTION, receive);
	curl_easy_setopt(conn->handle, CURLOPT_WRITEDATA, &buff);

	if( db_op != QUERY && db_op != CUSTOM)
	{
		LM_DBG("Posted:%s \n",&q.s[middle_poz]);
		curl_easy_setopt(conn->handle, CURLOPT_POSTFIELDS, &q.s[middle_poz]);

	}


	curl_easy_setopt(conn->handle, CURLOPT_FAILONERROR,1);
	ret = curl_easy_perform(conn->handle);


	if( ret )
	{
		LM_ERR( "Error in CURL: %s\n", curl_easy_strerror(ret) );
		LM_ERR( "Description  : %s\n",error_buffer);
		return -1;

	}
	if( db_op == QUERY || db_op == CUSTOM )
	{
		if( form_result(buff,r) )
			return -1;
	}

	if( db_op == INSERT )
	{
		if( buff.len > 0)
			sscanf(buff.s,"%d",&conn->last_id);
	}

	

	return 0;

error:
	LM_ERR("Error while appending to buffer\n");
	return -1;
}


str value_to_string(const db_val_t * v)
{

	static char buff[64];
	str rez;
	rez.s = NULL;
	rez.len = 0;


	if( v->nul )
	{
		rez.s = "\0";
		rez.len = 1;
		return rez;
	}
	


	switch ( v->type)
	{
		case (DB_INT):
			sprintf(buff,"%d",v->val.int_val);
			rez.s = buff;
			rez.len = strlen(rez.s);
			break;
		case( DB_DOUBLE):
			sprintf(buff,"%f",v->val.double_val);
			rez.s = buff;
			rez.len = strlen(rez.s);
			break;
		case( DB_STRING):
			rez.s =  (char*) v -> val.string_val;
			rez.len = strlen(rez.s);
			break;
		case(DB_STR):
			rez = v ->val.str_val;
			break;
		case(DB_DATETIME):
			sprintf(buff,"%s",ctime(&v->val.time_val));
			rez.s = buff;
			rez.len = strlen(rez.s);
			break;
		case(DB_BLOB):
			rez = v->val.blob_val;
			break;
		case(DB_BITMAP):
			sprintf(buff,"%d",v -> val.bitmap_val);
			rez.s = buff;
			rez.len = strlen(rez.s);
			break;
	}

	if( rez.s == NULL )
	{
		rez.s = "";
		rez.len = 0;
	}
	

	return rez;
}




/* Converts an integer value to its hex character*/
char to_hex(char code)
{
	static char hex[] = "0123456789abcdef";
	return hex[code & 15];
}

/* Returns a url-encoded version of str */
str url_encode(str s)
{

	
	static char *buf = NULL;
	static int size = 0;

	char *pstr ;
	char *pbuf;
	str rez;
	int i;

	pstr = s.s;
	if( s.len * 3 + 1 > size)
	{
		buf = pkg_realloc(buf, s.len * 3 + 1);
		size = s.len * 3 + 1;
	}
	
	pbuf = buf;
	i = 0;
	
	while ( i < s.len )
	{
		if (isalnum(*pstr) || *pstr == '-' ||
			*pstr == '_' || *pstr == '.' || *pstr == '~')

			*pbuf++ = *pstr;
		else
		{
			*pbuf++ = '%';
			*pbuf++ = to_hex(*pstr >> 4);
			*pbuf++ = to_hex(*pstr & 15);
		}
		
		pstr++;
		i++;
	}

	rez.s =  buf;
	rez.len = pbuf - buf;



	return rez;
}



db_con_t* db_http_init(const str* url)
{

	
	char* path;
	char port [20];
	char user_pass[1024];
	char modified_url[1024];
	str tmp;

	db_con_t * ans;
	http_conn_t * curl;
	int i;
	struct db_id * id;


	memset(modified_url,0,1024);
	memcpy(modified_url,url->s,url->len);

	strcat(modified_url,"/x");
	tmp.s = modified_url;
	tmp.len = strlen(tmp.s);

	user_pass[0] = 0;


	path = (char*)pkg_malloc(1024);

	if( path == NULL )
	{
		LM_ERR("Out of memory\n");
		return NULL;
	}

	memset(path,0,1024);
	
	
	id = new_db_id( &tmp );

	if( id == NULL)
	{
		LM_ERR("Incorrect db_url\n");
		return NULL;
	}
	


	if( id->username && id->password)
	{
		strcat(user_pass,id->username);
		strcat(user_pass,":");
		strcat(user_pass,id->password);
	}

	

	curl = (http_conn_t * ) pkg_malloc(sizeof(http_conn_t));

	if( curl == NULL )
	{
		LM_ERR("Out of memory\n");
		return NULL;
	}

	curl->handle = curl_easy_init();
	curl_easy_setopt(curl->handle,CURLOPT_SSL_VERIFYPEER,0);
	curl_easy_setopt(curl->handle,CURLOPT_SSL_VERIFYHOST,0);

	curl_easy_setopt(curl->handle,CURLOPT_USERPWD,user_pass);
	curl_easy_setopt(curl->handle,CURLOPT_HTTPAUTH,CURLAUTH_ANY);

	curl_easy_setopt(curl->handle,CURLOPT_ERRORBUFFER,error_buffer);


	strcat(path,"http");
	if ( use_ssl )
		strcat(path,"s");
	strcat(path,"://");
	

	strcat(path,id->host);
	if( id->port )
	{
		strcat(path,":");
		sprintf(port,"%d",id->port);
		strcat(path,port);
	}
	strcat(path,"/");

	if( strlen(id->database) > 2 )
	{
		id->database[strlen(id->database)-2] = 0;
		strcat(path,id->database);
		strcat(path,"/");
	}

	curl->start.s = path;
	curl->start.len = strlen(path);


	ans = (db_con_t *)pkg_malloc(sizeof(db_con_t));

	if( ans == NULL )
	{
		LM_ERR("Out of memory\n");
		return NULL;
	}

	ans ->tail = (long)curl;


	for( i=0 ; i< 256;i++)
		next_state[IN][i] = IN;

	for( i=0 ; i< 256;i++)
		next_state[OUT][i] = OUT;

	for( i=0 ; i< 256;i++)
		next_state[ESC][i] = OUT;

	next_state[ OUT ][ (int)quote_delim ] = IN;
	next_state[ IN ][  (int)quote_delim ] = ESC;
	next_state[ ESC ][ (int) quote_delim ] = IN;

	return ans;
	
}


void db_http_close(db_con_t* _h)
{

	http_conn_t* conn = (http_conn_t*) _h->tail;
	curl_easy_cleanup(conn->handle);
	pkg_free(_h);
}


/*
 * Free all memory allocated by get_result
 */
int db_http_free_result(db_con_t* _h, db_res_t* _r)
{


	db_free_columns( _r );

	db_free_rows( _r );

	pkg_free(_r);

	return 0;
}


/*
 * Do a query
 */
int db_http_query(const db_con_t* _h, const db_key_t* _k, const db_op_t* _op,
	     const db_val_t* _v, const db_key_t* _c, const int _n,
	     const int _nc, const db_key_t _o, db_res_t** _r)
{
	return do_http_op (
		_h,
		_k, _op, _v, _n,
		_c, _nc,
		NULL , NULL, 0,
		NULL,
		NULL,
		_r,
		QUERY
		);
	return 0;
}




/*
 * Raw SQL query
 */
int db_http_raw_query(const db_con_t* _h, const str* _s, db_res_t** _r)
{
	return do_http_op (
		_h,
		NULL, NULL, NULL, 0,
		NULL , 0 ,
		NULL , NULL , 0,
		NULL,
		_s,
		_r,
		CUSTOM
		);



}


/*
 * Insert a row into table
 */
int db_http_insert(const db_con_t* _h, const db_key_t* _k,
			const db_val_t* _v, const int _n)
{
	return do_http_op (
		_h,
		_k, NULL, _v, _n,
		NULL , 0 ,
		NULL , NULL , 0,
		NULL,
		NULL,
		NULL,
		INSERT
		);
	
}


/*
 * Delete a row from table
 */
int db_http_delete(const db_con_t* _h, const db_key_t* _k, const
	db_op_t* _o, const db_val_t* _v, const int _n)
{

	return do_http_op (
		_h,
		_k, _o,_v, _n,
		NULL, 0,
		NULL,NULL,0,
		NULL,
		NULL,
		NULL,
		DELETE
		);
	     
}


/*
 * Update a row in table
 */
int db_http_update(const db_con_t* _h, const db_key_t* _k, const db_op_t* _o,
	const db_val_t* _v, const db_key_t* _uk, const db_val_t* _uv,
	const int _n, const int _un)
{
	return do_http_op (
		_h,
		_k, _o, _v, _n,
		NULL, 0,
		_uk, _uv, _un,
		NULL,
		NULL,
		NULL,
		UPDATE
		);
	
}


/*
 * Just like insert, but replace the row if it exists
 */
int db_http_replace(const db_con_t* handle, const db_key_t* keys,
			const db_val_t* vals, const int n)
{
	return do_http_op (
		handle,
		keys,NULL,vals, n,
		NULL, 0,
		NULL,NULL,0,
		NULL,
		NULL,
		NULL,
		REPLACE
		);
}

/*
 * Returns the last inserted ID
 */
int db_last_inserted_id(const db_con_t* _h)
{
	http_conn_t* conn = (http_conn_t*) _h->tail;


	return conn->last_id;
	
}

/*
 * Insert a row into table, update on duplicate key
 */
int db_insert_update(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v,
	const int _n)
{
	return do_http_op (
		_h,
		_k, NULL, _v, _n,
		NULL , 0,
		NULL, NULL, 0,
		NULL,
		NULL,
		NULL,
		INSERT_UPDATE
		);

	
}


/*
 * Store name of table that will be used by
 * subsequent database functions
 */
int db_http_use_table(db_con_t* _h, const str* _t)
{
	_h->table = _t;
	return 0;
}
