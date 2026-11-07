// SPDX-License-Identifier: MIT
/*
 * cJSON - JSON parser in C.
 * Adapted for Linux kernel use.
 */

#include "cJSON.h"

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

#define static_strlen(string_literal) (sizeof(string_literal) - sizeof(""))
#define CJSON_NESTING_LIMIT 64

static void *cJSON_malloc(size_t sz)
{
	return kmalloc(sz, GFP_ATOMIC);
}

static void *cJSON_realloc(void *ptr, size_t sz)
{
	return krealloc(ptr, sz, GFP_ATOMIC);
}

static void cJSON_free(void *ptr)
{
	kfree(ptr);
}

static char *cJSON_strdup(const char *str)
{
	size_t len;
	char *copy;

	len = strlen(str) + 1;
	copy = cJSON_malloc(len);
	if (!copy)
		return NULL;

	memcpy(copy, str, len);
	return copy;
}

/* Internal constructor */
static cJSON *cJSON_New_Item(void)
{
	cJSON *node = cJSON_malloc(sizeof(cJSON));

	if (node)
		memset(node, 0, sizeof(cJSON));
	return node;
}

/* Delete a cJSON structure */
void cJSON_Delete(cJSON *c)
{
	cJSON *next;

	while (c) {
		next = c->next;
		if (c->child)
			cJSON_Delete(c->child);
		if (c->valuestring)
			cJSON_free(c->valuestring);
		if (c->string)
			cJSON_free(c->string);
		cJSON_free(c);
		c = next;
	}
}

/* Parse the input text to generate a number, and populate the result into item */
static const char *parse_number(cJSON *item, const char *num)
{
	int n = 0, sign = 1;

	if (*num == '-') {
		sign = -1;
		num++;
	}
	if (*num == '0') {
		num++;
	}
	if (*num >= '1' && *num <= '9') {
		do {
			n = (n * 10) + (*num++ - '0');
		} while (*num >= '0' && *num <= '9');
	}
	item->valueint = sign * (int)n;
	item->type = cJSON_Number;
	return num;
}

/* Render the number nicely from the given item into a string */
static char *print_number(cJSON *item)
{
	char *str;

	str = cJSON_malloc(21);
	if (str)
		sprintf(str, "%d", item->valueint);
	return str;
}

/* Parse the input text into an unescaped cstring, and populate item */
static const char *parse_string(cJSON *item, const char *str)
{
	static const char firstByteMark[7] = {
		0x00, 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC
	};
	const char *ptr = str + 1;
	char *ptr2;
	char *out;
	int len = 0;
	unsigned int uc;

	if (*str != '\"')
		return NULL;

	while (*ptr != '\"' && *ptr > 31 && ++len) {
		if (*ptr++ == '\\')
			ptr++;
	}

	out = cJSON_malloc(len + 1);
	if (!out)
		return NULL;

	ptr = str + 1;
	ptr2 = out;
	while (*ptr != '\"' && *ptr > 31) {
		if (*ptr != '\\') {
			*ptr2++ = *ptr++;
		} else {
			ptr++;
			switch (*ptr) {
			case 'b': *ptr2++ = '\b'; break;
			case 'f': *ptr2++ = '\f'; break;
			case 'n': *ptr2++ = '\n'; break;
			case 'r': *ptr2++ = '\r'; break;
			case 't': *ptr2++ = '\t'; break;
			case 'u':
				sscanf(ptr + 1, "%4x", &uc);
				len = 3;
				if (uc < 0x80)
					len = 1;
				else if (uc < 0x800)
					len = 2;
				ptr2 += len;

				switch (len) {
				case 3:
					*--ptr2 = ((uc | 0x80) & 0xBF);
					uc >>= 6;
					fallthrough;
				case 2:
					*--ptr2 = ((uc | 0x80) & 0xBF);
					uc >>= 6;
					fallthrough;
				case 1:
					*--ptr2 = (uc | firstByteMark[len]);
				}
				ptr2 += len;
				ptr += 4;
				break;
			default:
				*ptr2++ = *ptr;
				break;
			}
			ptr++;
		}
	}
	*ptr2 = 0;
	if (*ptr == '\"')
		ptr++;
	item->valuestring = out;
	item->type = cJSON_String;
	return ptr;
}

/* Render the cstring provided to an escaped version that can be printed */
static char *print_string_ptr(const char *str)
{
	const char *ptr;
	char *ptr2, *out;
	int len = 0;

	ptr = str;
	while (*ptr && ++len) {
		if (*ptr < 32 || *ptr == '\"' || *ptr == '\\')
			len++;
		ptr++;
	}

	out = cJSON_malloc(len + 3);
	ptr2 = out;
	ptr = str;
	*ptr2++ = '\"';
	while (*ptr) {
		if (*ptr > 31 && *ptr != '\"' && *ptr != '\\') {
			*ptr2++ = *ptr++;
		} else {
			*ptr2++ = '\\';
			switch (*ptr++) {
			case '\\': *ptr2++ = '\\'; break;
			case '\"': *ptr2++ = '\"'; break;
			case '\b': *ptr2++ = 'b'; break;
			case '\f': *ptr2++ = 'f'; break;
			case '\n': *ptr2++ = 'n'; break;
			case '\r': *ptr2++ = 'r'; break;
			case '\t': *ptr2++ = 't'; break;
			default:
				ptr2--;
				break;
			}
		}
	}
	*ptr2++ = '\"';
	*ptr2++ = 0;
	return out;
}

/* Invoke print_string_ptr (which is useful) on an item */
static char *print_string(cJSON *item)
{
	return print_string_ptr(item->valuestring);
}

/* Predeclare these prototypes */
static const char *parse_value(cJSON *item, const char *value, int depth);
static char *print_value(cJSON *item, int depth);
static const char *parse_array(cJSON *item, const char *value, int depth);
static char *print_array(cJSON *item, int depth);
static const char *parse_object(cJSON *item, const char *value, int depth);
static char *print_object(cJSON *item, int depth);

/* Utility to jump whitespace and cr/lf */
static const char *skip(const char *in)
{
	while (in && *in <= 32)
		in++;
	return in;
}

/* Parse an object - create a new root, and populate */
cJSON *cJSON_Parse(const char *value)
{
	cJSON *c = cJSON_New_Item();

	if (!c)
		return NULL;

	if (!parse_value(c, skip(value), 0)) {
		cJSON_Delete(c);
		return NULL;
	}
	return c;
}

/* Render a cJSON item/entity/structure to text */
char *cJSON_Print(cJSON *item)
{
	return print_value(item, 0);
}

/* Parser core - when encountering text, process appropriately */
static const char *parse_value(cJSON *item, const char *value, int depth)
{
	if (depth > CJSON_NESTING_LIMIT)
		return NULL;
	if (!value)
		return NULL;

	if (!strncmp(value, "null", 4)) {
		item->type = cJSON_NULL;
		return value + 4;
	}
	if (!strncmp(value, "false", 5)) {
		item->type = cJSON_False;
		return value + 5;
	}
	if (!strncmp(value, "true", 4)) {
		item->type = cJSON_True;
		item->valueint = 1;
		return value + 4;
	}
	if (*value == '\"')
		return parse_string(item, value);
	if (*value == '-' || (*value >= '0' && *value <= '9'))
		return parse_number(item, value);
	if (*value == '[')
		return parse_array(item, value, depth + 1);
	if (*value == '{')
		return parse_object(item, value, depth + 1);

	return NULL;
}

/* Render a value to text */
static char *print_value(cJSON *item, int depth)
{
	char *out = NULL;

	switch (item->type) {
	case cJSON_NULL:   out = cJSON_strdup("null"); break;
	case cJSON_False:  out = cJSON_strdup("false"); break;
	case cJSON_True:   out = cJSON_strdup("true"); break;
	case cJSON_Number: out = print_number(item); break;
	case cJSON_String: out = print_string(item); break;
	case cJSON_Array:  out = print_array(item, depth); break;
	case cJSON_Object: out = print_object(item, depth); break;
	}
	return out;
}

/* Build an array from input text */
static const char *parse_array(cJSON *item, const char *value, int depth)
{
	cJSON *child;

	if (*value != '[')
		return NULL;

	item->type = cJSON_Array;
	value = skip(value + 1);
	if (*value == ']')
		return value + 1;

	item->child = child = cJSON_New_Item();
	if (!item->child)
		return NULL;
	value = skip(parse_value(child, skip(value), depth));
	if (!value)
		return NULL;

	while (*value == ',') {
		cJSON *new_item;

		new_item = cJSON_New_Item();
		if (!new_item)
			return NULL;
		child->next = new_item;
		new_item->prev = child;
		child = new_item;
		value = skip(parse_value(child, skip(value + 1), depth));
		if (!value)
			return NULL;
	}

	if (*value == ']')
		return value + 1;
	return NULL;
}

/* Render an array to text */
static char *print_array(cJSON *item, int depth)
{
	char *out, *ptr, *ret;
	int len = 5;
	cJSON *child = item->child;

	out = cJSON_malloc(len);
	if (!out)
		return NULL;

	*out = '[';
	ptr = out + 1;
	*ptr = 0;
	while (child) {
		ret = print_value(child, depth + 1);
		if (!ret) {
			cJSON_free(out);
			return NULL;
		}
		len += strlen(ret) + 3;
		out = cJSON_realloc(out, len);
		ptr = out + strlen(out);
		ptr += sprintf(ptr, "%s", ret);
		if (child->next) {
			*ptr++ = ',';
			*ptr++ = ' ';
			*ptr = 0;
		}
		child = child->next;
		cJSON_free(ret);
	}
	*ptr++ = ']';
	*ptr++ = 0;
	return out;
}

/* Build an object from the text */
static const char *parse_object(cJSON *item, const char *value, int depth)
{
	cJSON *child;

	if (*value != '{')
		return NULL;

	item->type = cJSON_Object;
	value = skip(value + 1);
	if (*value == '}') {
		return value + 1;
	}

	item->child = child = cJSON_New_Item();
	value = skip(parse_string(child, skip(value)));
	if (!value)
		return NULL;
	child->string = child->valuestring;
	child->valuestring = 0;
	if (*value != ':') {
		return NULL;
	}
	value = skip(parse_value(child, skip(value + 1), depth));
	if (!value)
		return NULL;

	while (*value == ',') {
		cJSON *new_item;

		new_item = cJSON_New_Item();
		if (!new_item)
			return NULL;
		child->next = new_item;
		new_item->prev = child;
		child = new_item;
		value = skip(parse_string(child, skip(value + 1)));
		if (!value)
			return NULL;
		child->string = child->valuestring;
		child->valuestring = 0;
		if (*value != ':')
			return NULL;
		value = skip(parse_value(child, skip(value + 1), depth));
		if (!value)
			return NULL;
	}

	if (*value == '}')
		return value + 1;
	return NULL;
}

/* Render an object to text */
static char *print_object(cJSON *item, int depth)
{
	char *out, *ptr, *ret, *str;
	int len = 7, i;
	cJSON *child = item->child;

	depth++;
	len += depth;
	out = cJSON_malloc(len);
	if (!out)
		return NULL;

	*out = '{';
	ptr = out + 1;
	*ptr++ = '\n';
	*ptr = 0;
	while (child) {
		str = print_string_ptr(child->string);
		if (!str) {
			cJSON_free(out);
			return NULL;
		}
		ret = print_value(child, depth);
		if (!ret) {
			cJSON_free(str);
			cJSON_free(out);
			return NULL;
		}
		len += strlen(ret) + strlen(str) + 4 + depth;
		out = cJSON_realloc(out, len);
		ptr = out + strlen(out);
		for (i = 0; i < depth; i++)
			*ptr++ = '\t';
		ptr += sprintf(ptr, "%s", str);
		*ptr++ = ':';
		*ptr++ = '\t';
		ptr += sprintf(ptr, "%s", ret);
		if (child->next)
			*ptr++ = ',';
		*ptr++ = '\n';
		*ptr = 0;
		child = child->next;
		cJSON_free(str);
		cJSON_free(ret);
	}
	for (i = 0; i < depth - 1; i++)
		*ptr++ = '\t';
	*ptr++ = '}';
	*ptr++ = 0;
	return out;
}

static void skip_oneline_comment(char **input)
{
	*input += static_strlen("//");

	for (; (*input)[0] != '\0'; ++(*input)) {
		if ((*input)[0] == '\n') {
			*input += static_strlen("\n");
			return;
		}
	}
}

static void skip_multiline_comment(char **input)
{
	*input += static_strlen("/*");

	for (; (*input)[0] != '\0'; ++(*input)) {
		if (((*input)[0] == '*') && ((*input)[1] == '/')) {
			*input += static_strlen("*/");
			return;
		}
	}
}

static void minify_string(char **input, char **output)
{
	(*output)[0] = (*input)[0];
	*input += static_strlen("\"");
	*output += static_strlen("\"");

	for (; (*input)[0] != '\0'; (void)++(*input), ++(*output)) {
		(*output)[0] = (*input)[0];
		if ((*input)[0] == '\"') {
			(*output)[0] = '\"';
			*input += static_strlen("\"");
			*output += static_strlen("\"");
			return;
		} else if (((*input)[0] == '\\') && ((*input)[1] == '\"')) {
			(*output)[1] = (*input)[1];
			*input += static_strlen("\"");
			*output += static_strlen("\"");
		}
	}
}

void cJSON_Minify(char *json)
{
	char *into = json;

	if (json == NULL)
		return;

	while (json[0] != '\0') {
		switch (json[0]) {
		case ' ':
		case '\t':
		case '\r':
		case '\n':
			json++;
			break;
		case '/':
			if (json[1] == '/')
				skip_oneline_comment(&json);
			else if (json[1] == '*')
				skip_multiline_comment(&json);
			else
				json++;
			break;
		case '\"':
			minify_string(&json, (char **)&into);
			break;
		default:
			into[0] = json[0];
			json++;
			into++;
		}
	}
	*into = '\0';
}

/* Get Array size/item / object item */
int cJSON_GetArraySize(cJSON *array)
{
	cJSON *c = array->child;
	int i = 0;

	while (c) {
		i++;
		c = c->next;
	}
	return i;
}

cJSON *cJSON_GetArrayItem(cJSON *array, int item)
{
	cJSON *c = array->child;

	while (c && item) {
		item--;
		c = c->next;
	}
	return c;
}

cJSON *cJSON_GetObjectItem(cJSON *object, const char *string)
{
	cJSON *c = object->child;

	while (c && strcasecmp(c->string, string))
		c = c->next;
	return c;
}

/* Utility for array list handling */
static void suffix_object(cJSON *prev, cJSON *item)
{
	prev->next = item;
	item->prev = prev;
}

/* Add item to array/object */
void cJSON_AddItemToArray(cJSON *array, cJSON *item)
{
	cJSON *c = array->child;

	if (!c) {
		array->child = item;
	} else {
		while (c && c->next)
			c = c->next;
		suffix_object(c, item);
	}
}

void cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)
{
	if (item->string)
		cJSON_free(item->string);
	item->string = cJSON_strdup(string);
	cJSON_AddItemToArray(object, item);
}

/* Create basic types */
cJSON *cJSON_CreateNull(void)
{
	cJSON *item = cJSON_New_Item();

	item->type = cJSON_NULL;
	return item;
}

cJSON *cJSON_CreateTrue(void)
{
	cJSON *item = cJSON_New_Item();

	item->type = cJSON_True;
	return item;
}

cJSON *cJSON_CreateFalse(void)
{
	cJSON *item = cJSON_New_Item();

	item->type = cJSON_False;
	return item;
}

cJSON *cJSON_CreateNumber(int num)
{
	cJSON *item = cJSON_New_Item();

	item->type = cJSON_Number;
	item->valueint = (int)num;
	return item;
}

cJSON *cJSON_CreateString(const char *string)
{
	cJSON *item = cJSON_New_Item();

	item->type = cJSON_String;
	item->valuestring = cJSON_strdup(string);
	return item;
}

cJSON *cJSON_CreateArray(void)
{
	cJSON *item = cJSON_New_Item();

	item->type = cJSON_Array;
	return item;
}

cJSON *cJSON_CreateObject(void)
{
	cJSON *item = cJSON_New_Item();

	item->type = cJSON_Object;
	return item;
}

/* Create Arrays */
cJSON *cJSON_CreateIntArray(int *numbers, int count)
{
	int i;
	cJSON *n = NULL, *p = NULL, *a = cJSON_CreateArray();

	for (i = 0; i < count; i++) {
		n = cJSON_CreateNumber(numbers[i]);
		if (!i)
			a->child = n;
		else
			suffix_object(p, n);
		p = n;
	}
	return a;
}

cJSON *cJSON_CreateStringArray(const char **strings, int count)
{
	int i;
	cJSON *n = NULL, *p = NULL, *a = cJSON_CreateArray();

	for (i = 0; i < count; i++) {
		n = cJSON_CreateString(strings[i]);
		if (!i)
			a->child = n;
		else
			suffix_object(p, n);
		p = n;
	}
	return a;
}
