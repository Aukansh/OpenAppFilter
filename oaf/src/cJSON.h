/* SPDX-License-Identifier: MIT */
/*
 * cJSON - JSON parser in C.
 * Adapted for Linux kernel use.
 */

#ifndef __CJSON_H__
#define __CJSON_H__

#include <linux/slab.h>
#include <linux/string.h>

/* cJSON Types */
#define cJSON_False  0
#define cJSON_True   1
#define cJSON_NULL   2
#define cJSON_Number 3
#define cJSON_String 4
#define cJSON_Array  5
#define cJSON_Object 6

/* The cJSON structure */
typedef struct cJSON {
	struct cJSON *next;
	struct cJSON *prev;
	struct cJSON *child;	/* An array or object item will have a child pointer pointing to a chain of the items in the array/object */

	int type;		/* The type of the item, as above */

	char *valuestring;	/* The item's string, if type==cJSON_String */
	int valueint;		/* The item's number, if type==cJSON_Number */
	char *string;		/* The item's name string, if this item is the child of, or is in the list of subitems of an object */
} cJSON;

/* Supply a block of JSON, and this returns a cJSON object you can interrogate. Call cJSON_Delete when finished. */
cJSON *cJSON_Parse(const char *value);

/* Render a cJSON entity to text for transfer/storage. Free the char* when finished. */
char *cJSON_Print(cJSON *item);

/* Delete a cJSON entity and all subentities. */
void cJSON_Delete(cJSON *c);

/* Returns the number of items in an array (or object). */
int cJSON_GetArraySize(cJSON *array);

/* Retrieve item number "item" from array "array". Returns NULL if unsuccessful. */
cJSON *cJSON_GetArrayItem(cJSON *array, int item);

/* Get item "string" from object. Case insensitive. */
cJSON *cJSON_GetObjectItem(cJSON *object, const char *string);

/* These calls create a cJSON item of the appropriate type. */
cJSON *cJSON_CreateNull(void);
cJSON *cJSON_CreateTrue(void);
cJSON *cJSON_CreateFalse(void);
cJSON *cJSON_CreateNumber(int num);
cJSON *cJSON_CreateString(const char *string);
cJSON *cJSON_CreateArray(void);
cJSON *cJSON_CreateObject(void);

/* Minify a JSON string in-place */
void cJSON_Minify(char *json);

/* These utilities create an Array of count items. */
cJSON *cJSON_CreateIntArray(int *numbers, int count);
cJSON *cJSON_CreateStringArray(const char **strings, int count);

/* Append item to the specified array/object. */
void cJSON_AddItemToArray(cJSON *array, cJSON *item);
void cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item);

/* Macros for creating and adding items in one step */
#define cJSON_AddNullToObject(object, name) \
	cJSON_AddItemToObject(object, name, cJSON_CreateNull())
#define cJSON_AddTrueToObject(object, name) \
	cJSON_AddItemToObject(object, name, cJSON_CreateTrue())
#define cJSON_AddFalseToObject(object, name) \
	cJSON_AddItemToObject(object, name, cJSON_CreateFalse())
#define cJSON_AddNumberToObject(object, name, n) \
	cJSON_AddItemToObject(object, name, cJSON_CreateNumber(n))
#define cJSON_AddStringToObject(object, name, s) \
	cJSON_AddItemToObject(object, name, cJSON_CreateString(s))

#endif /* __CJSON_H__ */
