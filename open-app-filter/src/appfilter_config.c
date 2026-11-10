/* SPDX-License-Identifier: MIT */
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

static int current_log_level = LOG_LEVEL_ERROR;

typedef struct {
	app_name_info_t app_name_table[MAX_SUPPORT_APP_NUM];
	int app_count;
	char class_name_table[MAX_APP_TYPE][MAX_CLASS_NAME_LEN];
	int class_count;
} feature_manager_t;

static feature_manager_t *get_feature_manager(void)
{
	static feature_manager_t mgr;
	return &mgr;
}

int get_current_log_level(void)
{
	return current_log_level;
}

void set_current_log_level(int level)
{
	if (level < LOG_LEVEL_ERROR)
		level = LOG_LEVEL_ERROR;
	if (level > LOG_LEVEL_DEBUG)
		level = LOG_LEVEL_DEBUG;
	current_log_level = level;
}

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
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	static FILE *log_fp = NULL;
	
	char time_str[20];
	struct tm *tm;
	time_t now;
	va_list ap;
	long size;

	if (level > current_log_level)
		return;

	pthread_mutex_lock(&mutex);

	if (!log_fp) {
		log_fp = fopen(LOG_FILE_PATH, "a");
		if (!log_fp) {
			fprintf(stderr, "[af_log] cannot open %s\n", LOG_FILE_PATH);
			goto unlock;
		}
	}

	fseek(log_fp, 0, SEEK_END);
	size = ftell(log_fp);
	if (size > AF_LOG_FILE_MAX_SIZE) {
		fclose(log_fp);
		log_fp = NULL;
		rename(LOG_FILE_PATH, LOG_FILE_PATH ".1");
		log_fp = fopen(LOG_FILE_PATH, "a");
		if (!log_fp) {
			fprintf(stderr, "[af_log] cannot reopen %s after rotate\n", LOG_FILE_PATH);
			goto unlock;
		}
	}

	now = time(NULL);
	tm = localtime(&now);
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);

	fprintf(log_fp, "[%s] [%s] ", time_str, log_level_str(level));
	va_start(ap, fmt);
	vfprintf(log_fp, fmt, ap);
	va_end(ap);

	if (!fmt[0] || fmt[strlen(fmt) - 1] != '\n')
		fputc('\n', log_fp);

	fflush(log_fp);

unlock:
	pthread_mutex_unlock(&mutex);
}

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

int af_uci_get_value(struct uci_context *ctx, const char *key, char *out, int out_len)
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
		LOG_WARN("af_uci_add_list: key+value too long");
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

int af_uci_get_list_value(struct uci_context *ctx, const char *key, char *out, int out_len, const char *delim)
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
				LOG_WARN("af_uci_get_list_value: output truncated");
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

int af_uci_set_value(struct uci_context *ctx, const char *key, const char *value)
{
	char buf[2048];
	struct uci_ptr ptr;
	int ret;

	if (!ctx || !key || !value)
		return -1;

	if (strlen(key) + strlen(value) + 2 > sizeof(buf)) {
		LOG_WARN("af_uci_set_value: key+value too long (%zu+%zu)", strlen(key), strlen(value));
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

int af_uci_set_array_value(struct uci_context *ctx, const char *fmt, int index, const char *value)
{
	char key[128];

	snprintf(key, sizeof(key), fmt, index);
	return af_uci_set_value(ctx, key, value);
}

int af_uci_get_array_value(struct uci_context *ctx, const char *fmt, int index, char *out, int out_len)
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

int af_get_uci_list_num(struct uci_context *ctx, const char *package, const char *section)
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

int af_uci_add_section(struct uci_context *ctx, const char *pkg_name, const char *section)
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

char *get_app_name_by_id(int id)
{
	feature_manager_t *mgr = get_feature_manager();
	int i;

	for (i = 0; i < mgr->app_count; i++)
		if (id == mgr->app_name_table[i].id)
			return mgr->app_name_table[i].name;
	return "";
}

void init_app_name_table(void)
{
	feature_manager_t *mgr = get_feature_manager();
	char line[2048];
	FILE *fp;

	fp = fopen("/tmp/feature.cfg", "r");
	if (!fp) {
		LOG_ERROR("init_app_name_table: cannot open /tmp/feature.cfg");
		return;
	}

	mgr->app_count = 0;
	while (fgets(line, sizeof(line), fp)) {
		char info[128], name[64];
		char *colon;
		size_t plen;
		int id;

		if (strstr(line, "#") || strlen(line) < 10 || !strstr(line, ":"))
			continue;
		if (mgr->app_count >= MAX_SUPPORT_APP_NUM) {
			LOG_WARN("app count exceeds %d", MAX_SUPPORT_APP_NUM);
			break;
		}

		colon = strstr(line, ":");
		plen = (size_t)(colon - line);
		if (plen >= sizeof(info)) {
			LOG_WARN("feature line prefix too long (%zu), skip", plen);
			continue;
		}
		memcpy(info, line, plen);
		info[plen] = '\0';
		if (sscanf(info, "%d %63s", &id, name) != 2)
			continue;

		mgr->app_name_table[mgr->app_count].id = id;
		snprintf(mgr->app_name_table[mgr->app_count].name,
			 sizeof(mgr->app_name_table[mgr->app_count].name), "%s", name);
		mgr->app_count++;
	}
	fclose(fp);
}

void init_app_class_name_table(void)
{
	feature_manager_t *mgr = get_feature_manager();
	char line[2048];
	FILE *fp;

	fp = fopen("/tmp/app_class.txt", "r");
	if (!fp) {
		LOG_ERROR("init_app_class_name_table: cannot open /tmp/app_class.txt");
		return;
	}

	mgr->class_count = 0;
	while (fgets(line, sizeof(line), fp)) {
		int id;
		char name[MAX_CLASS_NAME_LEN];

		if (sscanf(line, "%d %*s %31s", &id, name) != 2) {
			LOG_WARN("bad app_class line: %s", line);
			continue;
		}
		if (id < 1 || id > MAX_APP_TYPE) {
			LOG_WARN("app_class id out of range: %d", id);
			continue;
		}
		snprintf(mgr->class_name_table[id - 1],
			 sizeof(mgr->class_name_table[id - 1]), "%s", name);
		mgr->class_count++;
	}
	fclose(fp);
}

int get_class_count(void)
{
	return get_feature_manager()->class_count;
}

const char *get_class_name_by_id(int id)
{
	feature_manager_t *mgr = get_feature_manager();
	
	if (id < 0 || id >= MAX_APP_TYPE)
		return "";
	return mgr->class_name_table[id];
}
