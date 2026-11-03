/*
Copyright (C) 2020 Derry <destan19@126.com>

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

// SPDX-License-Identifier: MIT
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <uci.h>

#include "appfilter.h"
#include "appfilter_config.h"

#define AF_LOG_FILE_MAX_SIZE	(2 * 1024 * 1024)

static app_name_info_t app_name_table[MAX_SUPPORT_APP_NUM];
static int g_app_count;
int g_cur_class_num;
char CLASS_NAME_TABLE[MAX_APP_TYPE][MAX_CLASS_NAME_LEN];

static pthread_mutex_t af_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static FILE *af_log_fp;

static const char *log_level_str(log_level_t level)
{
	switch (level) {
	case LOG_LEVEL_DEBUG:	return "DEBUG";
	case LOG_LEVEL_INFO:	return "INFO";
	case LOG_LEVEL_WARN:	return "WARN";
	case LOG_LEVEL_ERROR:	return "ERROR";
	default:		return "UNKNOWN";
	}
}

void af_log(log_level_t level, const char *fmt, ...)
{
	char time_str[20];
	struct tm *tm;
	time_t now;
	va_list ap;
	long size;

	if (level > current_log_level)
		return;

	pthread_mutex_lock(&af_log_mutex);

	if (!af_log_fp) {
		af_log_fp = fopen(LOG_FILE_PATH, "a");
		if (!af_log_fp) {
			perror("Failed to open log file");
			goto unlock;
		}
	}

	fseek(af_log_fp, 0, SEEK_END);
	size = ftell(af_log_fp);
	if (size > AF_LOG_FILE_MAX_SIZE) {
		fclose(af_log_fp);
		af_log_fp = NULL;
		rename(LOG_FILE_PATH, LOG_FILE_PATH ".1");
		af_log_fp = fopen(LOG_FILE_PATH, "a");
		if (!af_log_fp) {
			perror("Failed to open log file after rotate");
			goto unlock;
		}
	}

	now = time(NULL);
	tm = localtime(&now);
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);

	fprintf(af_log_fp, "[%s] [%s] ", time_str, log_level_str(level));
	va_start(ap, fmt);
	vfprintf(af_log_fp, fmt, ap);
	va_end(ap);

	if (!fmt[0] || fmt[strlen(fmt) - 1] != '\n')
		fputc('\n', af_log_fp);

	fflush(af_log_fp);
unlock:
	pthread_mutex_unlock(&af_log_mutex);
}

/* ----------------------------------------------------------------------
 * UCI helpers
 * -------------------------------------------------------------------- */

int af_uci_get_int_value(struct uci_context *ctx, const char *key)
{
	char buf[128];
	struct uci_ptr ptr;
	int ret = -1;

	if (!key || strlen(key) >= sizeof(buf))
		return ret;

	snprintf(buf, sizeof(buf), "%s", key);
	if (uci_lookup_ptr(ctx, &ptr, buf, true) != UCI_OK)
		return ret;

	if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
		ctx->err = UCI_ERR_NOTFOUND;
		goto done;
	}

	switch (ptr.last->type) {
	case UCI_TYPE_SECTION:
		ret = -1;
		break;
	case UCI_TYPE_OPTION:
		ret = atoi(ptr.o->v.string);
		break;
	default:
		break;
	}
done:
	if (ptr.p)
		uci_unload(ctx, ptr.p);
	return ret;
}

int af_uci_get_value(struct uci_context *ctx, const char *key,
		     char *out, int out_len)
{
	char buf[128];
	struct uci_ptr ptr;
	int ret = UCI_OK;

	if (!key || !out || out_len <= 0 || strlen(key) >= sizeof(buf))
		return 1;

	snprintf(buf, sizeof(buf), "%s", key);
	if (uci_lookup_ptr(ctx, &ptr, buf, true) != UCI_OK)
		return 1;

	if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
		ctx->err = UCI_ERR_NOTFOUND;
		ret = 1;
		goto done;
	}

	switch (ptr.last->type) {
	case UCI_TYPE_SECTION:
		snprintf(out, out_len, "%s", ptr.s->type);
		break;
	case UCI_TYPE_OPTION:
		snprintf(out, out_len, "%s", ptr.o->v.string);
		break;
	default:
		ret = 1;
		break;
	}
done:
	if (ptr.p)
		uci_unload(ctx, ptr.p);
	return ret;
}

int af_uci_delete(struct uci_context *ctx, const char *key)
{
	char buf[128];
	struct uci_ptr ptr;
	int ret;

	if (!key || strlen(key) >= sizeof(buf))
		return 1;

	snprintf(buf, sizeof(buf), "%s", key);
	if (uci_lookup_ptr(ctx, &ptr, buf, true) != UCI_OK)
		return 1;

	ret = uci_delete(ctx, &ptr);
	if (ret == UCI_OK)
		ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
	return ret;
}

int af_uci_add_list(struct uci_context *ctx, const char *key, const char *value)
{
	char buf[MAX_PARAM_LIST_LEN];
	struct uci_ptr ptr;
	int ret;

	if (!key || !value)
		return -1;
	if (strlen(key) + strlen(value) >= sizeof(buf) - 1) {
		printf("value too long\n");
		return -1;
	}

	snprintf(buf, sizeof(buf), "%s=%s", key, value);
	if (uci_lookup_ptr(ctx, &ptr, buf, true) != UCI_OK)
		return 1;

	ret = uci_add_list(ctx, &ptr);
	if (ret == UCI_OK)
		ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
	return ret;
}

int af_uci_add_int_list(struct uci_context *ctx, const char *key, int value)
{
	char buf[128];
	struct uci_ptr ptr;
	int ret;

	if (!key || strlen(key) + 16 >= sizeof(buf))
		return 1;

	snprintf(buf, sizeof(buf), "%s=%d", key, value);
	if (uci_lookup_ptr(ctx, &ptr, buf, true) != UCI_OK)
		return 1;

	ret = uci_add_list(ctx, &ptr);
	if (ret == UCI_OK)
		ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
	return ret;
}

int af_uci_get_list_value(struct uci_context *ctx, const char *key,
			  char *out, int out_len, const char *delim)
{
	char buf[128];
	struct uci_ptr ptr;
	size_t used = 0, dlen;
	int sep = 0;
	int ret = -1;

	if (!key || strlen(key) >= sizeof(buf))
		return ret;

	snprintf(buf, sizeof(buf), "%s", key);
	if (uci_lookup_ptr(ctx, &ptr, buf, true) != UCI_OK)
		return ret;

	if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
		ctx->err = UCI_ERR_NOTFOUND;
		goto done;
	}

	if (ptr.last->type != UCI_TYPE_OPTION)
		goto done;

	if (ptr.o->type == UCI_TYPE_LIST) {
		struct uci_element *e;

		dlen = strlen(delim);
		memset(out, 0, out_len);
		uci_foreach_element(&ptr.o->v.list, e) {
			size_t need = strlen(e->name) + (sep ? dlen : 0);

			if (used + need + 1 > (size_t)out_len) {
				LOG_WARN("af_uci_get_list_value: output truncated\n");
				break;
			}
			if (sep) {
				memcpy(out + used, delim, dlen);
				used += dlen;
			}
			memcpy(out + used, e->name, strlen(e->name));
			used += strlen(e->name);
			out[used] = '\0';
			sep = 1;
		}
		ret = 0;
	}
done:
	if (ptr.p)
		uci_unload(ctx, ptr.p);
	return ret;
}

int af_uci_set_value(struct uci_context *ctx, const char *key,
		     const char *value)
{
	char buf[2048];
	struct uci_ptr ptr;
	int ret;

	if (!ctx || !key || !value)
		return -1;

	if (strlen(key) + strlen(value) + 2 > sizeof(buf)) {
		fprintf(stderr, "af_uci_set_value: key+value too long (%zu+%zu)\n",
			strlen(key), strlen(value));
		return -1;
	}
	snprintf(buf, sizeof(buf), "%s=%s", key, value);

	if (uci_lookup_ptr(ctx, &ptr, buf, true) != UCI_OK)
		return 1;

	ret = uci_set(ctx, &ptr);
	if (ret == UCI_OK)
		ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
	return ret;
}

int af_uci_set_int_value(struct uci_context *ctx, const char *key, int value)
{
	char buf[128];
	struct uci_ptr ptr;
	int ret;

	if (!key || strlen(key) + 16 >= sizeof(buf))
		return 1;

	snprintf(buf, sizeof(buf), "%s=%d", key, value);
	if (uci_lookup_ptr(ctx, &ptr, buf, true) != UCI_OK)
		return 1;

	ret = uci_set(ctx, &ptr);
	if (ret == UCI_OK)
		ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
	return ret;
}

int af_uci_set_array_value(struct uci_context *ctx, const char *fmt,
			   int index, const char *value)
{
	char key[128];

	snprintf(key, sizeof(key), fmt, index);
	return af_uci_set_value(ctx, key, value);
}

int af_uci_get_array_value(struct uci_context *ctx, const char *fmt,
			   int index, char *out, int out_len)
{
	char key[128];

	snprintf(key, sizeof(key), fmt, index);
	return af_uci_get_value(ctx, key, out, out_len);
}

int af_uci_commit(struct uci_context *ctx, const char *package)
{
	struct uci_ptr ptr;
	int ret = UCI_OK;

	if (!package)
		return -1;

	if (uci_lookup_ptr(ctx, &ptr, (char *)package, true) != UCI_OK)
		return -1;

	if (uci_commit(ctx, &ptr.p, false) != UCI_OK)
		ret = -1;

	if (ptr.p)
		uci_unload(ctx, ptr.p);

	return ret;
}

int af_get_uci_list_num(struct uci_context *ctx, const char *package,
			const char *section)
{
	struct uci_package *pkg = NULL;
	struct uci_element *e;
	int count = 0;

	if (UCI_OK != uci_load(ctx, package, &pkg))
		return -1;

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (strcmp(s->type, section))
			continue;
		count++;
	}
	uci_unload(ctx, pkg);
	return count;
}

int af_uci_add_section(struct uci_context *ctx, const char *pkg_name,
		       const char *section)
{
	struct uci_section *s = NULL;
	struct uci_package *p = NULL;
	int ret;

	ret = uci_load(ctx, pkg_name, &p);
	if (ret != UCI_OK)
		goto done;

	ret = uci_add_section(ctx, p, section, &s);
	if (ret != UCI_OK)
		goto done;

	ret = uci_save(ctx, p);
done:
	if (p)
		uci_unload(ctx, p);
	return ret;
}

/* ----------------------------------------------------------------------
 * Feature tables
 * -------------------------------------------------------------------- */

char *get_app_name_by_id(int id)
{
	int i;

	for (i = 0; i < g_app_count; i++)
		if (id == app_name_table[i].id)
			return app_name_table[i].name;
	return "";
}

void init_app_name_table(void)
{
	char line[2048];
	FILE *fp;

	fp = fopen("/tmp/feature.cfg", "r");
	if (!fp) {
		printf("open file failed\n");
		return;
	}

	g_app_count = 0;
	while (fgets(line, sizeof(line), fp)) {
		char info[128], name[64];
		char *colon;
		size_t plen;
		int id;

		if (strstr(line, "#") || strlen(line) < 10 ||
		    !strstr(line, ":"))
			continue;
		if (g_app_count >= MAX_SUPPORT_APP_NUM) {
			LOG_WARN("app count exceeds %d\n", MAX_SUPPORT_APP_NUM);
			break;
		}

		colon = strstr(line, ":");
		plen = (size_t)(colon - line);
		if (plen >= sizeof(info)) {
			LOG_WARN("feature line prefix too long (%zu), skip\n",
				 plen);
			continue;
		}
		memcpy(info, line, plen);
		info[plen] = '\0';
		if (sscanf(info, "%d %63s", &id, name) != 2)
			continue;

		app_name_table[g_app_count].id = id;
		snprintf(app_name_table[g_app_count].name,
			 sizeof(app_name_table[g_app_count].name), "%s", name);
		g_app_count++;
	}
	fclose(fp);
}

void init_app_class_name_table(void)
{
	char line[2048];
	FILE *fp;

	fp = fopen("/tmp/app_class.txt", "r");
	if (!fp) {
		printf("open file failed\n");
		return;
	}

	g_cur_class_num = 0;
	while (fgets(line, sizeof(line), fp)) {
		int id;
		char name[MAX_CLASS_NAME_LEN];

		if (sscanf(line, "%d %*s %31s", &id, name) != 2) {
			LOG_WARN("bad app_class line: %s\n", line);
			continue;
		}
		if (id < 1 || id > MAX_APP_TYPE) {
			LOG_WARN("app_class id out of range: %d\n", id);
			continue;
		}
		snprintf(CLASS_NAME_TABLE[id - 1],
			 sizeof(CLASS_NAME_TABLE[id - 1]), "%s", name);
		g_cur_class_num++;
	}
	fclose(fp);
}
