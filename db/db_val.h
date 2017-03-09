/*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2007-2008 1&1 Internet AG
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
 */

/**
 * \file db/db_val.h
 * \brief Data structures that represents values in the database.
 *
 * This file defines data structures that represents values in the database.
 * Several datatypes are recognized and converted by the database API.
 * Available types: DB_INT, DB_DOUBLE, DB_STRING, DB_STR, DB_DATETIME, DB_BLOB and DB_BITMAP
 * It also provides some macros for convenient access to this values.
 */


#ifndef DB_VAL_H
#define DB_VAL_H

#include <time.h>
#include <stdint.h>

#include "../dprint.h"
#include "../str.h"


/**
 * Each cell in a database table can be of a different type. To distinguish
 * among these types, the db_type_t enumeration is used. Every value of the
 * enumeration represents one datatype that is recognized by the database
 * API.
 */
typedef enum {
	DB_INT,        /**< represents an 32 bit integer number      */
	DB_BIGINT,     /**< represents an 64 bit integer number      */
	DB_DOUBLE,     /**< represents a floating point number       */
	DB_STRING,     /**< represents a zero terminated const char* */
	DB_STR,        /**< represents a string of 'str' type        */
	DB_DATETIME,   /**< represents date and time                 */
	DB_BLOB,       /**< represents a large binary object         */
	DB_BITMAP      /**< an one-dimensional array of 32 flags     */
} db_type_t;


/**
 * This structure represents a value in the database. Several datatypes are
 * recognized and converted by the database API. These datatypes are automaticaly
 * recognized, converted from internal database representation and stored in the
 * variable of corresponding type.
 *
 * Module that want to use this values needs to copy them to another memory
 * location, because after the call to free_result there are not more available.
 *
 * If the structure holds a pointer to a string value that needs to be freed
 * because the module allocated new memory for it then the free flag must
 * be set to a non-zero value. A free flag of zero means that the string
 * data must be freed internally by the database driver.
 */
typedef struct {
	db_type_t type; /**< Type of the value                              */
	int nul;		/**< Means that the column in database has no value */
	int free;		/**< Means that the value should be freed */
	/** Column value structure that holds the actual data in a union.  */
	union {
		int           int_val;    /**< integer value              */
		long long     bigint_val; /**< big integer value          */
		double        double_val; /**< double value               */
		time_t        time_val;   /**< unix time_t value          */
		const char*   string_val; /**< zero terminated string     */
		str           str_val;    /**< str type string value      */
		str           blob_val;   /**< binary object data         */
		unsigned int  bitmap_val; /**< Bitmap data type           */
	} val;
} db_val_t;

static inline void db_print_val(db_val_t *v)
{
	switch (v->type) {
		case DB_INT:
			LM_GEN1(L_DBG, "\t'%d'\n", v->val.int_val);
			break;
		case DB_BIGINT:
			LM_GEN1(L_DBG, "\t'%lld'\n", v->val.bigint_val);
			break;
		case DB_DOUBLE:
			LM_GEN1(L_DBG, "\t'%.3lf'\n", v->val.double_val);
			break;
		case DB_STRING:
			LM_GEN1(L_DBG, "\t'%s'\n", v->val.string_val);
			break;
		case DB_STR:
			LM_GEN1(L_DBG, "\t'%.*s'\n", v->val.str_val.len, v->val.str_val.s);
			break;
		case DB_DATETIME:
			LM_GEN1(L_DBG, "\t'%ld'\n", v->val.time_val);
			break;
		case DB_BLOB:
			LM_GEN1(L_DBG, "\t'%.*s'\n", v->val.blob_val.len, v->val.blob_val.s);
			break;
		case DB_BITMAP:
			LM_GEN1(L_DBG, "\t'%u'\n", v->val.bitmap_val);
			break;
	}
}


/**
 * Useful macros for accessing attributes of db_val structure.
 * All macros expect a reference to a db_val_t variable as parameter.
 */

/**
 * Use this macro if you need to set/get the type of the value.
 */
#define VAL_TYPE(dv)   ((dv)->type)


/**
 * Use this macro if you need to set/get the null flag. A non-zero flag means that
 * the corresponding cell in the database contains no data (a NULL value in MySQL
 * terminology).
 */
#define VAL_NULL(dv)   ((dv)->nul)


/**
 * Use this macro if you need to set/ get the free flag. A non-zero flag means that
 * the corresponding cell in the database contains data that must be freed from the
 * DB API.
 */
#define VAL_FREE(dv)   ((dv)->free)


/**
 * Use this macro if you need to access the integer value in the db_val_t structure.
 */
#define VAL_INT(dv)    ((dv)->val.int_val)


/**
 * Use this macro if you need to access the big integer value in the db_val_t structure.
 */
#define VAL_BIGINT(dv)    ((dv)->val.bigint_val)


/**
 * Use this macro if you need to access the double value in the db_val_t structure.
 */
#define VAL_DOUBLE(dv) ((dv)->val.double_val)


/**
 * Use this macro if you need to access the time_t value in the db_val_t structure.
 */
#define VAL_TIME(dv)   ((dv)->val.time_val)


/**
 * Use this macro if you need to access the string value in the db_val_t structure.
 */
#define VAL_STRING(dv) ((dv)->val.string_val)


/**
 * Use this macro if you need to access the str structure in the db_val_t structure.
 */
#define VAL_STR(dv)    ((dv)->val.str_val)


/**
 * Use this macro if you need to access the blob value in the db_val_t structure.
 */
#define VAL_BLOB(dv)   ((dv)->val.blob_val)


/**
 * Use this macro if you need to access the bitmap value in the db_val_t structure.
 */
#define VAL_BITMAP(dv) ((dv)->val.bitmap_val)


#define get_str_from_dbval( _col_name, _val, _not_null, _not_empty, _str, _error_label) \
	do{\
		if ((_val)->nul) { \
			if (_not_null) { \
				LM_ERR("value in column %s cannot be null\n", _col_name); \
				goto _error_label;\
			} else { \
				_str.s = NULL; _str.len = 0; \
			} \
		} \
		if ((_val)->type==DB_STRING) { \
			if ( VAL_STRING(_val)==NULL || *(VAL_STRING(_val))==0 ) { \
				if (_not_empty) { \
					LM_ERR("value in column %s cannot be empty\n", _col_name); \
					goto _error_label;\
				} else { \
					_str.s = (char*)VAL_STRING(_val) ; _str.len = 0; \
				} \
			} else { \
				_str.s = (char*)VAL_STRING(_val) ; _str.len = strlen(_str.s); \
			} \
		} else if ((_val)->type==DB_STR) { \
			if ( VAL_STR(_val).s==NULL || VAL_STR(_val).len==0 ) { \
				if (_not_empty) { \
					LM_ERR("value in column %s cannot be empty\n", _col_name); \
					goto _error_label;\
				} else { \
					_str = VAL_STR(_val) ;\
				} \
			} else { \
				_str = VAL_STR(_val); \
			} \
		} else {\
			LM_ERR("column %s does not have a string type (found %d)\n",\
				_col_name,(_val)->type); \
			goto _error_label;\
		} \
	}while(0)




#endif /* DB_VAL_H */
