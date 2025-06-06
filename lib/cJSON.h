/*
  Copyright (c) 2009 Dave Gamble

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#ifndef OS_cJSON__h
#define OS_cJSON__h

#include "../str.h"

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef CJSON_PREFIX
#define CJSON_PREFIX os_
#endif

#ifdef CJSON_PREFIX

/* helpers */
#define cjson_prefix2(X, Y) X ## Y
#define cjson_prefix(X, Y) cjson_prefix2(X, Y)
/* structures */
#define cJSON cjson_prefix(CJSON_PREFIX, cJSON)
#define cJSON_Hooks cjson_prefix(CJSON_PREFIX, cJSON_Hooks)
/* functions */
#define cJSON_Version cjson_prefix(CJSON_PREFIX, cJSON_Version)
#define cJSON_InitHooks cjson_prefix(CJSON_PREFIX, cJSON_InitHooks)
#define cJSON_Parse cjson_prefix(CJSON_PREFIX, cJSON_Parse)
#define cJSON_Print cjson_prefix(CJSON_PREFIX, cJSON_Print)
#define cJSON_PurgeString cjson_prefix(CJSON_PREFIX, cJSON_PurgeString)
#define cJSON_PrintUnformatted cjson_prefix(CJSON_PREFIX, cJSON_PrintUnformatted)
#define cJSON_PrintBuffered cjson_prefix(CJSON_PREFIX, cJSON_PrintBuffered)
#define cJSON_PrintPreallocated cjson_prefix(CJSON_PREFIX, cJSON_PrintPreallocated)
#define cJSON_PrintFlushed cjson_prefix(CJSON_PREFIX, cJSON_PrintFlushed)
#define cJSON_Delete cjson_prefix(CJSON_PREFIX, cJSON_Delete)
#define cJSON_GetArraySize cjson_prefix(CJSON_PREFIX, cJSON_GetArraySize)
#define cJSON_GetArrayItem cjson_prefix(CJSON_PREFIX, cJSON_GetArrayItem)
#define cJSON_GetObjectItem cjson_prefix(CJSON_PREFIX, cJSON_GetObjectItem)
#define cJSON_HasObjectItem cjson_prefix(CJSON_PREFIX, cJSON_HasObjectItem)
#define cJSON_GetErrorPtr cjson_prefix(CJSON_PREFIX, cJSON_GetErrorPtr)
#define cJSON_CreateNull cjson_prefix(CJSON_PREFIX, cJSON_CreateNull)
#define cJSON_CreateTrue cjson_prefix(CJSON_PREFIX, cJSON_CreateTrue)
#define cJSON_CreateFalse cjson_prefix(CJSON_PREFIX, cJSON_CreateFalse)
#define cJSON_CreateBool cjson_prefix(CJSON_PREFIX, cJSON_CreateBool)
#define cJSON_CreateNumber cjson_prefix(CJSON_PREFIX, cJSON_CreateNumber)
#define cJSON_CreateString cjson_prefix(CJSON_PREFIX, cJSON_CreateString)
#define cJSON_CreateStr cjson_prefix(CJSON_PREFIX, cJSON_CreateStr)
#define cJSON_CreateRaw cjson_prefix(CJSON_PREFIX, cJSON_CreateRaw)
#define cJSON_CreateArray cjson_prefix(CJSON_PREFIX, cJSON_CreateArray)
#define cJSON_CreateObject cjson_prefix(CJSON_PREFIX, cJSON_CreateObject)
#define cJSON_CreateIntArray cjson_prefix(CJSON_PREFIX, cJSON_CreateIntArray)
#define cJSON_CreateFloatArray cjson_prefix(CJSON_PREFIX, cJSON_CreateFloatArray)
#define cJSON_CreateDoubleArray cjson_prefix(CJSON_PREFIX, cJSON_CreateDoubleArray)
#define cJSON_CreateStringArray cjson_prefix(CJSON_PREFIX, cJSON_CreateStringArray)
#define cJSON_AddItemToArray cjson_prefix(CJSON_PREFIX, cJSON_AddItemToArray)
#define _cJSON_AddItemToObject cjson_prefix(CJSON_PREFIX, _cJSON_AddItemToObject)
#define cJSON_AddItemToObject cjson_prefix(CJSON_PREFIX, cJSON_AddItemToObject)
#define cJSON_AddItemToObjectCS cjson_prefix(CJSON_PREFIX, cJSON_AddItemToObjectCS)
#define cJSON_AddItemReferenceToArray cjson_prefix(CJSON_PREFIX, cJSON_AddItemReferenceToArray)
#define cJSON_AddItemReferenceToObject cjson_prefix(CJSON_PREFIX, cJSON_AddItemReferenceToObject)
#define cJSON_DetachItemFromArray cjson_prefix(CJSON_PREFIX, cJSON_DetachItemFromArray)
#define cJSON_DeleteItemFromArray cjson_prefix(CJSON_PREFIX, cJSON_DeleteItemFromArray)
#define cJSON_DetachItemFromObject cjson_prefix(CJSON_PREFIX, cJSON_DetachItemFromObject)
#define cJSON_DeleteItemFromObject cjson_prefix(CJSON_PREFIX, cJSON_DeleteItemFromObject)
#define cJSON_InsertItemInArray cjson_prefix(CJSON_PREFIX, cJSON_InsertItemInArray)
#define cJSON_ReplaceItemInArray cjson_prefix(CJSON_PREFIX, cJSON_ReplaceItemInArray)
#define cJSON_ReplaceItemInObject cjson_prefix(CJSON_PREFIX, cJSON_ReplaceItemInObject)
#define cJSON_Duplicate cjson_prefix(CJSON_PREFIX, cJSON_Duplicate)
#define cJSON_ParseWithOpts cjson_prefix(CJSON_PREFIX, cJSON_ParseWithOpts)
#define cJSON_Minify cjson_prefix(CJSON_PREFIX, cJSON_Minify)
#define cJSON_SetNumberHelper cjson_prefix(CJSON_PREFIX, cJSON_SetNumberHelper)
#define cJSON_NumberIsInt cjson_prefix(CJSON_PREFIX, cJSON_NumberIsInt)
#endif /* CJSON_PREFIX */

/* project version */
#define CJSON_VERSION_MAJOR 1
#define CJSON_VERSION_MINOR 2
#define CJSON_VERSION_PATCH 1

/* returns the version of cJSON as a string */
extern const char* cJSON_Version(void);

#include <stddef.h>

/* cJSON Types: */
#define cJSON_False  (1 << 0)
#define cJSON_True   (1 << 1)
#define cJSON_NULL   (1 << 2)
#define cJSON_Number (1 << 3)
#define cJSON_String (1 << 4)
#define cJSON_Array  (1 << 5)
#define cJSON_Object (1 << 6)
#define cJSON_Raw    (1 << 7) /* raw json */

#define cJSON_IsReference   (1 << 8)
#define cJSON_StringIsConst (1 << 9)

/* The cJSON structure: */
typedef struct cJSON
{
    /* next/prev allow you to walk array/object chains. Alternatively, use GetArraySize/GetArrayItem/GetObjectItem */
    struct cJSON *next;
    struct cJSON *prev;
    /* An array or object item will have a child pointer pointing to a chain of the items in the array/object. */
    struct cJSON *child;

    /* The type of the item, as above. */
    int type;

    /* The item's string, if type==cJSON_String  and type == cJSON_Raw */
    char *valuestring;
    /* The item's number, if type==cJSON_Number */
    int valueint;
    /* The item's number, if type==cJSON_Number */
    double valuedouble;

    /* The item's name string, if this item is the child of, or is in the list of subitems of an object. */
    char *string;
} cJSON;

typedef struct cJSON_Hooks
{
      void *(*malloc_fn)(size_t sz);
      void (*free_fn)(void *ptr);
} cJSON_Hooks;

/* function that is called by cJSON_PrintFlushed to flush the buffered string built */
typedef int (flush_fn)(unsigned char *buf, int len, void *param);

/* Supply malloc, realloc and free functions to cJSON */
extern void cJSON_InitHooks(cJSON_Hooks* hooks);
extern cJSON_Hooks sys_mem_hooks;
extern cJSON_Hooks shm_mem_hooks;


/* Supply a block of JSON, and this returns a cJSON object you can interrogate.
 * The input @value can be safely freed immediately after the parsing.
 * Call cJSON_Delete when finished. */
extern cJSON *cJSON_Parse(const char *value);
/* Render a cJSON entity to text for transfer/storage. Free the char* when finished. */
extern char  *cJSON_Print(const cJSON *item);
/* Purge strings allocated by cJSON_Print() */
void cJSON_PurgeString(char *ptr);
/* Render a cJSON entity to text for transfer/storage without any formatting. Free the char* when finished. */
extern char  *cJSON_PrintUnformatted(const cJSON *item);
/* Render a cJSON entity to text using a buffered strategy. prebuffer is a guess at the final size. guessing well reduces reallocation. fmt=0 gives unformatted, =1 gives formatted */
extern char *cJSON_PrintBuffered(const cJSON *item, int prebuffer, int fmt);
/* Render a cJSON entity to text using a buffer already allocated in memory with length buf_len. Returns 1 on success and 0 on failure. */
extern int cJSON_PrintPreallocated(cJSON *item, char *buf, const int len, const int fmt);
/* Render a cJSON entity to a limited buffer, and call a flush function when the buffer gets full. Returns 1 on success and 0 on failure. */
extern int cJSON_PrintFlushed(cJSON *item, char *buf, const int len, const int fmt, flush_fn *func, void *param);
/* Delete a cJSON entity and all subentities. */
extern void   cJSON_Delete(cJSON *c);

/* Returns the number of items in an array (or object). */
extern int	  cJSON_GetArraySize(const cJSON *array);
/* Retrieve item number "item" from array "array". Returns NULL if unsuccessful. */
extern cJSON *cJSON_GetArrayItem(const cJSON *array, int item);
/* Get item "string" from object. Case insensitive. */
extern cJSON *cJSON_GetObjectItem(const cJSON *object, const char *string);
extern int cJSON_HasObjectItem(const cJSON *object, const char *string);
/* For analysing failed parses. This returns a pointer to the parse error. You'll probably need to look a few chars back to make sense of it. Defined when cJSON_Parse() returns 0. 0 when cJSON_Parse() succeeds. */
extern const char *cJSON_GetErrorPtr(void);

/* These calls create a cJSON item of the appropriate type. */
extern cJSON *cJSON_CreateNull(void);
extern cJSON *cJSON_CreateTrue(void);
extern cJSON *cJSON_CreateFalse(void);
extern cJSON *cJSON_CreateBool(int b);
extern cJSON *cJSON_CreateNumber(double num);
extern cJSON *cJSON_CreateString(const char *string);
extern cJSON *cJSON_CreateStr(const char *string, size_t len);
/* raw json */
extern cJSON *cJSON_CreateRaw(const char *raw);
extern cJSON *cJSON_CreateArray(void);
extern cJSON *cJSON_CreateObject(void);

/* These utilities create an Array of count items. */
extern cJSON *cJSON_CreateIntArray(const int *numbers, int count);
extern cJSON *cJSON_CreateFloatArray(const float *numbers, int count);
extern cJSON *cJSON_CreateDoubleArray(const double *numbers, int count);
extern cJSON *cJSON_CreateStringArray(const char **strings, int count);

/* Append item to the specified array/object. */
extern void cJSON_AddItemToArray(cJSON *array, cJSON *item);
extern void	_cJSON_AddItemToObject(cJSON *object, const str *string, cJSON *item);
extern void	cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item);
/* Use this when string is definitely const (i.e. a literal, or as good as), and will definitely survive the cJSON object.
 * WARNING: When this function was used, make sure to always check that (item->type & cJSON_StringIsConst) is zero before
 * writing to `item->string` */
extern void	cJSON_AddItemToObjectCS(cJSON *object, const char *string, cJSON *item);
/* Append reference to item to the specified array/object. Use this when you want to add an existing cJSON to a new cJSON, but don't want to corrupt your existing cJSON. */
extern void cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item);
extern void	cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON *item);

/* Remove/Detatch items from Arrays/Objects. */
extern cJSON *cJSON_DetachItemFromArray(cJSON *array, int which);
extern void   cJSON_DeleteItemFromArray(cJSON *array, int which);
extern cJSON *cJSON_DetachItemFromObject(cJSON *object, const char *string);
extern void   cJSON_DeleteItemFromObject(cJSON *object, const char *string);

/* Update array items. */
extern void cJSON_InsertItemInArray(cJSON *array, int which, cJSON *newitem); /* Shifts pre-existing items to the right. */
extern void cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem);
extern void cJSON_ReplaceItemInObject(cJSON *object,const char *string,cJSON *newitem);

/* Duplicate a cJSON item */
extern cJSON *cJSON_Duplicate(const cJSON *item, int recurse);
/* Duplicate will create a new, identical cJSON item to the one you pass, in new memory that will
need to be released. With recurse!=0, it will duplicate any children connected to the item.
The item->next and ->prev pointers are always zero on return from Duplicate. */

/* ParseWithOpts allows you to require (and check) that the JSON is null terminated, and to retrieve the pointer to the final byte parsed. */
/* If you supply a ptr in return_parse_end and parsing fails, then return_parse_end will contain a pointer to the error. If not, then cJSON_GetErrorPtr() does the job. */
extern cJSON *cJSON_ParseWithOpts(const char *value, const char **return_parse_end, int require_null_terminated);

extern void cJSON_Minify(char *json);

/* Macros for creating things quickly. */
#define cJSON_AddNullToObject(object,name) cJSON_AddItemToObject(object, name, cJSON_CreateNull())
#define cJSON_AddTrueToObject(object,name) cJSON_AddItemToObject(object, name, cJSON_CreateTrue())
#define cJSON_AddFalseToObject(object,name) cJSON_AddItemToObject(object, name, cJSON_CreateFalse())
#define cJSON_AddBoolToObject(object,name,b) cJSON_AddItemToObject(object, name, cJSON_CreateBool(b))
#define cJSON_AddNumberToObject(object,name,n) cJSON_AddItemToObject(object, name, cJSON_CreateNumber(n))
#define cJSON_AddStringToObject(object,name,s) cJSON_AddItemToObject(object, name, cJSON_CreateString(s))
#define cJSON_AddStrToObject(object,name,s,len) cJSON_AddItemToObject(object, name, cJSON_CreateStr(s,len))
#define _cJSON_AddStrToObject(object,name,s,len) _cJSON_AddItemToObject(object, name, cJSON_CreateStr(s,len))
#define cJSON_AddRawToObject(object,name,s) cJSON_AddItemToObject(object, name, cJSON_CreateRaw(s))

/* When assigning an integer value, it needs to be propagated to valuedouble too. */
#define cJSON_SetIntValue(object, number) ((object) ? (object)->valueint = (object)->valuedouble = (number) : (number))
/* helper for the cJSON_SetNumberValue macro */
extern double cJSON_SetNumberHelper(cJSON *object, double number);
#define cJSON_SetNumberValue(object, number) ((object) ? cJSON_SetNumberHelper(object, (double)number) : (number))

int cJSON_NumberIsInt(cJSON *item);

/* Macro for iterating over an array */
#define cJSON_ArrayForEach(pos, head) for(pos = (head)->child; pos != NULL; pos = pos->next)

cJSON * cJSONUtils_MergePatch(cJSON *target, const cJSON * const patch);

#ifdef __cplusplus
}
#endif

#endif /* OS_cJSON__h */
