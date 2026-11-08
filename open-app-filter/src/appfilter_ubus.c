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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <uci.h>

#include "appfilter.h"
#include "appfilter_config.h"
#include "appfilter_ubus.h"
#include "appfilter_user.h"
#include "utils.h"

#define MAX_STAT_APP_NUM	128
#define MAX_APPFILTER_STR_LEN	8192
#define MSG_ESC_HEADROOM	128

struct all_users_info {
	int flag;
	struct json_object *users_array;
};

typedef struct app_visit_time_info {
	int app_id;
	unsigned long long total_time;
} app_visit_time_info_t;

static struct ubus_context *ubus_ctx;
static int g_enable_agent;

static const struct blobmsg_policy empty_policy[1] = {};

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

static void reload_oaf_rule(void)
{
	system("/usr/bin/oaf_rule reload");
}

static int reply_json(struct ubus_context *ctx, struct ubus_request_data *req,
		      struct json_object *obj)
{
	struct blob_buf b = {};

	blob_buf_init(&b, 0);
	blobmsg_add_object(&b, obj);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);
	return 0;
}

static int reply_code(struct ubus_context *ctx, struct ubus_request_data *req,
		      int code)
{
	struct json_object *obj = json_object_new_object();
	int ret;

	json_object_object_add(obj, "code", json_object_new_int(code));
	ret = reply_json(ctx, req, obj);
	json_object_put(obj);
	return ret;
}

static int app_icon_exists(int app_id)
{
	char path[512];

	snprintf(path, sizeof(path),
		 "/www/luci-static/resources/app_icons/%d.png", app_id);
	return access(path, F_OK) == 0 ? 1 : 0;
}

static void shell_escape_single(const char *src, char *dst, size_t dst_len)
{
	size_t i, j = 0;

	if (!src || !dst || dst_len == 0)
		return;

	for (i = 0; src[i] != '\0' && j + 5 < dst_len; i++) {
		if (src[i] == '\'') {
			memcpy(dst + j, "'\\''", 4);
			j += 4;
		} else {
			dst[j++] = src[i];
		}
	}
	dst[j] = '\0';
}

static void forward_msg_to_agent(const char *api, const char *msg)
{
	size_t esc_len, msg_len;
	char *esc, *cmd;

	if (!api || !msg)
		return;

	msg_len = strlen(msg);
	esc_len = msg_len * 5 + 1;
	esc = malloc(esc_len);
	cmd = malloc(esc_len + MSG_ESC_HEADROOM);
	if (!esc || !cmd) {
		free(esc);
		free(cmd);
		return;
	}

	shell_escape_single(msg, esc, esc_len);
	snprintf(cmd, esc_len + MSG_ESC_HEADROOM,
		 "ubus -t 2 call oaf_agent %s '%s'", api, esc);
	printf("exec %s\n", cmd);
	system(cmd);
	free(esc);
	free(cmd);
}

/* -------------------------------------------------------------------------
 * visit_list (kept, not registered by design)
 * ---------------------------------------------------------------------- */

static void dump_visit_list(struct blob_buf *b, const char *mac)
{
	void *arr = blobmsg_open_array(b, "dev_list");
	int i, j;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			void *visit_arr, *t;

			if (mac && strcmp(mac, node->mac)) {
				node = node->next;
				continue;
			}
			t = blobmsg_open_table(b, NULL);
			blobmsg_add_string(b, "hostname", "unknown");
			blobmsg_add_string(b, "mac", node->mac);
			blobmsg_add_string(b, "ip", node->ip);

			visit_arr = blobmsg_open_array(b, "visit_info");
			for (j = 0; j < MAX_VISIT_HASH_SIZE; j++) {
				visit_info_t *v = node->visit_htable[j];

				while (v) {
					void *s = blobmsg_open_table(b, NULL);

					blobmsg_add_string(b, "appname", "unknown");
					blobmsg_add_u32(b, "appid", v->appid);
					blobmsg_add_u32(b, "latest_action", v->action);
					blobmsg_add_u32(b, "first_time", v->first_time);
					blobmsg_add_u32(b, "latest_time", v->latest_time);
					blobmsg_close_table(b, s);
					v = v->next;
				}
			}
			blobmsg_close_array(b, visit_arr);
			blobmsg_close_table(b, t);
			node = node->next;
		}
	}
	blobmsg_close_array(b, arr);
}

static int appfilter_handle_visit_list(struct ubus_context *ctx,
				       struct ubus_object *obj,
				       struct ubus_request_data *req,
				       const char *method,
				       struct blob_attr *msg)
{
	struct blob_buf b = {};
	struct json_object *req_obj = NULL, *mac_obj = NULL;
	char *s = blobmsg_format_json(msg, true);

	blob_buf_init(&b, 0);
	if (s) {
		req_obj = json_tokener_parse(s);
		if (req_obj)
			mac_obj = json_object_object_get(req_obj, "mac");
	}

	if (!mac_obj)
		dump_visit_list(&b, NULL);
	else
		dump_visit_list(&b, json_object_get_string(mac_obj));

	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);
	if (req_obj)
		json_object_put(req_obj);
	free(s);
	return 0;
}

/* -------------------------------------------------------------------------
 * dev_visit_list
 * ---------------------------------------------------------------------- */

static int cmp_lt(const void *a, const void *b)
{
	struct json_object *ja = *(struct json_object **)a;
	struct json_object *jb = *(struct json_object **)b;
	struct json_object *la, *lb;

	json_object_object_get_ex(ja, "lt", &la);
	json_object_object_get_ex(jb, "lt", &lb);
	return json_object_get_int(lb) - json_object_get_int(la);
}

static int appfilter_handle_dev_visit_list(struct ubus_context *ctx,
					   struct ubus_object *obj,
					   struct ubus_request_data *req,
					   const char *method,
					   struct blob_attr *msg)
{
	struct json_object *root_obj = json_object_new_object();
	struct json_object *visit_array = json_object_new_array();
	struct json_object *paged_array = NULL;
	struct json_object *req_obj = NULL;
	struct json_object *mac_obj, *page_obj, *psize_obj;
	int page = 0, page_size = 20, total_count, start, end, i, j;
	char *s = blobmsg_format_json(msg, true);
	dev_node_t *node;

	if (!s)
		goto out_objs;

	req_obj = json_tokener_parse(s);
	if (!req_obj)
		goto out_objs;

	mac_obj = json_object_object_get(req_obj, "mac");
	if (!mac_obj)
		goto out_req_no_reply;

	page_obj = json_object_object_get(req_obj, "page");
	psize_obj = json_object_object_get(req_obj, "page_size");
	if (page_obj)
		page = json_object_get_int(page_obj);
	if (psize_obj) {
		page_size = json_object_get_int(psize_obj);
		if (page_size <= 0)
			page_size = 20;
		else if (page_size > 1000)
			page_size = 1000;
	}

	node = find_dev_node((char *)json_object_get_string(mac_obj));
	if (!node)
		goto out_req_no_reply;

	json_object_object_add(root_obj, "hostname",
			       json_object_new_string(node->hostname));
	json_object_object_add(root_obj, "mac",
			       json_object_new_string(node->mac));
	json_object_object_add(root_obj, "ip",
			       json_object_new_string(node->ip));

	for (j = 0; j < MAX_VISIT_HASH_SIZE; j++) {
		visit_info_t *v = node->visit_htable[j];

		while (v) {
			struct json_object *vo;

			if (!strlen(get_app_name_by_id(v->appid))) {
				v = v->next;
				continue;
			}
			vo = json_object_new_object();
			json_object_object_add(vo, "name",
					       json_object_new_string(get_app_name_by_id(v->appid)));
			json_object_object_add(vo, "id",
					       json_object_new_int(v->appid));
			json_object_object_add(vo, "icon",
					       json_object_new_int(app_icon_exists(v->appid)));
			json_object_object_add(vo, "act",
					       json_object_new_int(v->action));
			json_object_object_add(vo, "ft",
					       json_object_new_int(v->first_time));
			json_object_object_add(vo, "lt",
					       json_object_new_int(v->latest_time));
			json_object_object_add(vo, "tt",
					       json_object_new_int(v->latest_time - v->first_time));
			json_object_array_add(visit_array, vo);
			v = v->next;
		}
	}

	json_object_array_sort(visit_array, cmp_lt);
	total_count = json_object_array_length(visit_array);

	if (page <= 0) {
		paged_array = json_object_get(visit_array);
	} else {
		start = (page - 1) * page_size;
		end = start + page_size;
		paged_array = json_object_new_array();
		for (i = start; i < end && i < total_count; i++) {
			struct json_object *vo = json_object_array_get_idx(visit_array, i);

			if (vo) {
				json_object_get(vo);
				json_object_array_add(paged_array, vo);
			}
		}
	}

	json_object_object_add(root_obj, "total",
			       json_object_new_int(total_count));
	json_object_object_add(root_obj, "list", paged_array);
	json_object_object_add(root_obj, "page", json_object_new_int(page));
	json_object_object_add(root_obj, "page_size",
			       json_object_new_int(page_size));
	json_object_object_add(root_obj, "total_pages",
			       json_object_new_int(page_size > 0
						   ? (total_count + page_size - 1) / page_size
						   : 0));
	json_object_put(visit_array);

	reply_json(ctx, req, root_obj);
	json_object_put(root_obj);
	json_object_put(req_obj);
	free(s);
	return 0;

out_req_no_reply:
	json_object_put(req_obj);
out_objs:
	json_object_put(visit_array);
	json_object_put(root_obj);
	free(s);
	return 0;
}

/* -------------------------------------------------------------------------
 * Aggregation helpers
 * ---------------------------------------------------------------------- */

static void update_app_visit_time_list(const char *mac,
				       struct app_visit_stat_info *visit_info)
{
	int num = 0, i, j;
	dev_node_t *node = find_dev_node((char *)mac);

	if (!node) {
		printf("not found mac:%s\n", mac);
		return;
	}

	for (i = 0; i < MAX_APP_TYPE; i++) {
		for (j = 0; j < MAX_APP_ID_NUM; j++) {
			if (node->stat[i][j].total_time == 0)
				continue;

			if (num < MAX_APP_STAT_NUM) {
				visit_info->visit_list[num].total_time =
					node->stat[i][j].total_time;
				visit_info->visit_list[num].app_id =
					(i + 1) * 1000 + j + 1;
				num++;
			} else {
				int min_index = 0, s;

				for (s = 0; s < MAX_APP_STAT_NUM; s++) {
					if (visit_info->visit_list[s].total_time <
					    visit_info->visit_list[min_index].total_time)
						min_index = s;
				}
				if (node->stat[i][j].total_time >
				    visit_info->visit_list[min_index].total_time) {
					visit_info->visit_list[min_index].total_time =
						node->stat[i][j].total_time;
					visit_info->visit_list[min_index].app_id =
						(i + 1) * 1000 + j + 1;
				}
			}
		}
	}
	visit_info->num = (num < MAX_APP_STAT_NUM) ? num : MAX_APP_STAT_NUM;
}

static void update_app_class_visit_time_list(const char *mac, int *visit_time)
{
	int i, j;
	dev_node_t *node = find_dev_node((char *)mac);

	if (!node) {
		printf("not found mac:%s\n", mac);
		return;
	}

	for (i = 0; i < MAX_APP_TYPE; i++)
		for (j = 0; j < MAX_APP_ID_NUM; j++)
			if (node->stat[i][j].total_time)
				visit_time[i] += node->stat[i][j].total_time;
}

/* -------------------------------------------------------------------------
 * debug
 * ---------------------------------------------------------------------- */

static int handle_debug(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct json_object *req_obj, *debug_obj;
	struct blob_buf b = {};
	char *s = blobmsg_format_json(msg, true);

	if (!s)
		return 0;

	req_obj = json_tokener_parse(s);
	if (!req_obj) {
		free(s);
		return 0;
	}

	debug_obj = json_object_object_get(req_obj, "debug");
	if (debug_obj) {
		int lvl = json_object_get_int(debug_obj);

		if (lvl < LOG_LEVEL_ERROR)
			lvl = LOG_LEVEL_ERROR;
		if (lvl > LOG_LEVEL_DEBUG)
			lvl = LOG_LEVEL_DEBUG;
		current_log_level = lvl;
		LOG_WARN("debug level set to %d\n", current_log_level);
	}

	blob_buf_init(&b, 0);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	json_object_put(req_obj);
	free(s);
	return 0;
}

/* -------------------------------------------------------------------------
 * dev_list
 * ---------------------------------------------------------------------- */

static int visit_time_compare(const void *a, const void *b)
{
	const app_visit_time_info_t *p1 = a;
	const app_visit_time_info_t *p2 = b;

	return p1->total_time < p2->total_time ? 1 : -1;
}

static void update_top5_app(dev_node_t *node,
			    app_visit_time_info_t top5_app_list[])
{
	app_visit_time_info_t app_visit_array[MAX_STAT_APP_NUM];
	int app_visit_num = 0, i, j;

	memset(app_visit_array, 0, sizeof(app_visit_array));

	for (i = 0; i < MAX_APP_TYPE; i++) {
		for (j = 0; j < MAX_APP_ID_NUM; j++) {
			if (node->stat[i][j].total_time == 0)
				continue;
			if (app_visit_num >= MAX_STAT_APP_NUM)
				break;
			app_visit_array[app_visit_num].app_id =
				(i + 1) * 1000 + j + 1;
			app_visit_array[app_visit_num].total_time =
				node->stat[i][j].total_time;
			app_visit_num++;
		}
		if (app_visit_num >= MAX_STAT_APP_NUM)
			break;
	}

	qsort(app_visit_array, app_visit_num,
	      sizeof(app_visit_time_info_t), visit_time_compare);
	for (i = 0; i < 5; i++)
		top5_app_list[i] = app_visit_array[i];
}

static int appfilter_handle_dev_list(struct ubus_context *ctx,
				     struct ubus_object *obj,
				     struct ubus_request_data *req,
				     const char *method,
				     struct blob_attr *msg)
{
	struct json_object *root_obj = json_object_new_object();
	struct json_object *dev_array = json_object_new_array();
	int i, j;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			struct json_object *dev_obj = json_object_new_object();
			struct json_object *app_array = json_object_new_array();
			app_visit_time_info_t top5_app_list[5];

			memset(top5_app_list, 0, sizeof(top5_app_list));
			update_top5_app(node, top5_app_list);

			for (j = 0; j < 5; j++) {
				struct json_object *app_obj;

				if (top5_app_list[j].app_id == 0 ||
				    !strlen(get_app_name_by_id(top5_app_list[j].app_id)))
					break;

				app_obj = json_object_new_object();
				json_object_object_add(app_obj, "id",
						       json_object_new_int(top5_app_list[j].app_id));
				json_object_object_add(app_obj, "name",
						       json_object_new_string(get_app_name_by_id(top5_app_list[j].app_id)));
				json_object_array_add(app_array, app_obj);
			}

			json_object_object_add(dev_obj, "applist", app_array);
			json_object_object_add(dev_obj, "mac",
					       json_object_new_string(node->mac));
			json_object_object_add(dev_obj, "ip",
					       json_object_new_string(node->ip));
			json_object_object_add(dev_obj, "online",
					       json_object_new_int(node->online));
			json_object_object_add(dev_obj, "hostname",
					       json_object_new_string(node->hostname));
			json_object_object_add(dev_obj, "nickname",
					       json_object_new_string(""));
			json_object_array_add(dev_array, dev_obj);

			node = node->next;
		}
	}

	json_object_object_add(root_obj, "devlist", dev_array);
	reply_json(ctx, req, root_obj);
	json_object_put(root_obj);
	return 0;
}

/* -------------------------------------------------------------------------
 * dev_visit_time (pie chart)
 * ---------------------------------------------------------------------- */

static int appfilter_handle_visit_time(struct ubus_context *ctx,
				       struct ubus_object *obj,
				       struct ubus_request_data *req,
				       const char *method,
				       struct blob_attr *msg)
{
	struct app_visit_stat_info info;
	struct json_object *resp_obj, *app_info_array, *req_obj, *mac_obj;
	char *s = blobmsg_format_json(msg, true);
	int i;

	if (!s)
		return 0;

	memset(&info, 0, sizeof(info));

	req_obj = json_tokener_parse(s);
	if (!req_obj) {
		free(s);
		return 0;
	}

	mac_obj = json_object_object_get(req_obj, "mac");
	if (!mac_obj) {
		printf("mac is NULL\n");
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	update_app_visit_time_list(json_object_get_string(mac_obj), &info);

	resp_obj = json_object_new_object();
	app_info_array = json_object_new_array();
	json_object_object_add(resp_obj, "list", app_info_array);
	json_object_object_add(resp_obj, "total_num",
			       json_object_new_int(info.num));

	for (i = 0; i < info.num; i++) {
		struct json_object *app_info_obj;

		if (!strlen(get_app_name_by_id(info.visit_list[i].app_id)))
			continue;

		app_info_obj = json_object_new_object();
		json_object_object_add(app_info_obj, "id",
				       json_object_new_int(info.visit_list[i].app_id));
		json_object_object_add(app_info_obj, "name",
				       json_object_new_string(get_app_name_by_id(info.visit_list[i].app_id)));
		json_object_object_add(app_info_obj, "t",
				       json_object_new_int(info.visit_list[i].total_time));
		json_object_array_add(app_info_array, app_info_obj);
	}

	reply_json(ctx, req, resp_obj);
	json_object_put(resp_obj);
	json_object_put(req_obj);
	free(s);
	return 0;
}

/* -------------------------------------------------------------------------
 * app_class_visit_time (pie chart)
 * ---------------------------------------------------------------------- */

static int handle_app_class_visit_time(struct ubus_context *ctx,
				       struct ubus_object *obj,
				       struct ubus_request_data *req,
				       const char *method,
				       struct blob_attr *msg)
{
	struct json_object *resp_obj, *app_class_array, *req_obj, *mac_obj;
	int app_class_visit_time[MAX_APP_TYPE];
	char *s = blobmsg_format_json(msg, true);
	int i;

	if (!s)
		return 0;

	req_obj = json_tokener_parse(s);
	if (!req_obj) {
		free(s);
		return 0;
	}

	mac_obj = json_object_object_get(req_obj, "mac");
	if (!mac_obj) {
		printf("mac is NULL\n");
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	memset(app_class_visit_time, 0, sizeof(app_class_visit_time));
	update_app_class_visit_time_list(json_object_get_string(mac_obj),
					 app_class_visit_time);

	resp_obj = json_object_new_object();
	app_class_array = json_object_new_array();
	json_object_object_add(resp_obj, "class_list", app_class_array);

	for (i = 0; i < MAX_APP_TYPE; i++) {
		struct json_object *app_class_obj;

		if (i >= g_cur_class_num)
			break;

		app_class_obj = json_object_new_object();
		json_object_object_add(app_class_obj, "type",
				       json_object_new_int(i));
		json_object_object_add(app_class_obj, "name",
				       json_object_new_string(CLASS_NAME_TABLE[i]));
		json_object_object_add(app_class_obj, "visit_time",
				       json_object_new_int(app_class_visit_time[i]));
		json_object_array_add(app_class_array, app_class_obj);
	}

	reply_json(ctx, req, resp_obj);
	json_object_put(resp_obj);
	json_object_put(req_obj);
	free(s);
	return 0;
}

/* -------------------------------------------------------------------------
 * feature.cfg parsing / class_list
 * ---------------------------------------------------------------------- */

static int parse_feature_cfg(struct json_object *class_list)
{
	FILE *file = fopen("/tmp/feature.cfg", "r");
	struct json_object *current_class = NULL;
	struct json_object *app_list = NULL;
	char line[1024];

	if (!file) {
		perror("Failed to open /tmp/feature.cfg");
		return -1;
	}

	while (fgets(line, sizeof(line), file)) {
		line[strcspn(line, "\n")] = '\0';

		if (!strncmp(line, "#class", 6)) {
			char *name, *class_name = NULL;

			if (current_class) {
				json_object_object_add(current_class, "app_list", app_list);
				json_object_array_add(class_list, current_class);
			}

			if (strlen(line) <= 6 || line[6] != ' ') {
				current_class = NULL;
				app_list = NULL;
				continue;
			}

			name = strtok(line + 7, " ");
			while (name != NULL) {
				class_name = name;
				name = strtok(NULL, " ");
			}
			if (!class_name) {
				current_class = NULL;
				app_list = NULL;
				continue;
			}

			current_class = json_object_new_object();
			json_object_object_add(current_class, "name",
					       json_object_new_string(class_name));
			app_list = json_object_new_array();
		} else if (current_class) {
			char app_buf[128];
			char *p_end, *appid_str, *name;
			size_t app_len;

			p_end = strstr(line, ":");
			if (!p_end)
				continue;

			app_len = (size_t)(p_end - line);
			if (app_len >= sizeof(app_buf)) {
				LOG_WARN("feature line prefix too long (%zu), skip\n",
					 app_len);
				continue;
			}
			memcpy(app_buf, line, app_len);
			app_buf[app_len] = '\0';

			appid_str = strtok(app_buf, " ");
			name = strtok(NULL, " ");
			if (appid_str && name) {
				char combined[256];

				snprintf(combined, sizeof(combined), "%s,%s,%d",
					 appid_str, name,
					 app_icon_exists(atoi(appid_str)));
				json_object_array_add(app_list,
						      json_object_new_string(combined));
			}
		}
	}

	if (current_class) {
		json_object_object_add(current_class, "app_list", app_list);
		json_object_array_add(class_list, current_class);
	}

	fclose(file);
	return 0;
}

static int handle_get_class_list(struct ubus_context *ctx,
				 struct ubus_object *obj,
				 struct ubus_request_data *req,
				 const char *method,
				 struct blob_attr *msg)
{
	struct json_object *response = json_object_new_object();
	struct json_object *class_list = json_object_new_array();

	if (parse_feature_cfg(class_list) != 0) {
		json_object_put(response);
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	json_object_object_add(response, "class_list", class_list);
	reply_json(ctx, req, response);
	json_object_put(response);
	return 0;
}

/* -------------------------------------------------------------------------
 * app_filter (list) get / set
 * ---------------------------------------------------------------------- */

static int handle_get_app_filter(struct ubus_context *ctx,
				 struct ubus_object *obj,
				 struct ubus_request_data *req,
				 const char *method,
				 struct blob_attr *msg)
{
	struct json_object *response = json_object_new_object();
	struct json_object *app_list = json_object_new_array();
	struct uci_context *uci_ctx;
	char *appfilter_buf;
	char *app_id_str;

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		printf("Failed to allocate UCI context\n");
		json_object_put(response);
		json_object_put(app_list);
		return 0;
	}

	appfilter_buf = malloc(MAX_APPFILTER_STR_LEN);
	if (!appfilter_buf) {
		uci_free_context(uci_ctx);
		json_object_put(response);
		json_object_put(app_list);
		return 0;
	}

	appfilter_buf[0] = '\0';
	af_uci_get_list_value(uci_ctx, "appfilter.rule.app_list",
			      appfilter_buf, MAX_APPFILTER_STR_LEN - 1, " ");

	app_id_str = strtok(appfilter_buf, " ");
	while (app_id_str) {
		json_object_array_add(app_list,
				      json_object_new_int(atoi(app_id_str)));
		app_id_str = strtok(NULL, " ");
	}

	json_object_object_add(response, "app_list", app_list);
	reply_json(ctx, req, response);

	uci_free_context(uci_ctx);
	free(appfilter_buf);
	json_object_put(response);
	return 0;
}

static int handle_set_app_filter(struct ubus_context *ctx,
				 struct ubus_object *obj,
				 struct ubus_request_data *req,
				 const char *method,
				 struct blob_attr *msg)
{
	struct json_object *req_obj, *app_list;
	struct uci_context *uci_ctx;
	char *s = blobmsg_format_json(msg, true);
	int i, n;

	if (!s)
		return 0;

	printf("handle_set_app_filter\n");
	req_obj = json_tokener_parse(s);
	if (!req_obj) {
		free(s);
		return 0;
	}

	app_list = json_object_object_get(req_obj, "app_list");
	if (!app_list) {
		printf("app_list is NULL\n");
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		printf("Failed to allocate UCI context\n");
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	af_uci_delete(uci_ctx, "appfilter.rule.app_list");
	n = json_object_array_length(app_list);
	for (i = 0; i < n; i++) {
		struct json_object *id_obj = json_object_array_get_idx(app_list, i);

		af_uci_add_int_list(uci_ctx, "appfilter.rule.app_list",
				    json_object_get_int(id_obj));
	}
	af_uci_commit(uci_ctx, "appfilter");
	reload_oaf_rule();
	g_oaf_config_change = 1;
	uci_free_context(uci_ctx);

	json_object_put(req_obj);
	free(s);
	return reply_code(ctx, req, 0);
}

/* -------------------------------------------------------------------------
 * app_filter_base get / set
 * ---------------------------------------------------------------------- */

static int handle_get_app_filter_base(struct ubus_context *ctx,
				      struct ubus_object *obj,
				      struct ubus_request_data *req,
				      const char *method,
				      struct blob_attr *msg)
{
	struct json_object *response = json_object_new_object();
	struct json_object *data_obj = json_object_new_object();
	struct uci_context *uci_ctx;
	int enable, work_mode, record_enable, disable_quic;
	int app_filter_mode, daily_limit_mode;

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		printf("Failed to allocate UCI context\n");
		json_object_put(response);
		json_object_put(data_obj);
		return 0;
	}

	enable = af_uci_get_int_value(uci_ctx, "appfilter.global.enable");
	work_mode = af_uci_get_int_value(uci_ctx, "appfilter.global.work_mode");
	record_enable = af_uci_get_int_value(uci_ctx, "appfilter.global.record_enable");
	disable_quic = af_uci_get_int_value(uci_ctx, "appfilter.global.disable_quic");
	app_filter_mode = af_uci_get_int_value(uci_ctx, "appfilter.global.app_filter_mode");
	daily_limit_mode = af_uci_get_int_value(uci_ctx, "appfilter.global.daily_limit_mode");

	if (app_filter_mode < 0)
		app_filter_mode = 0;
	if (daily_limit_mode < 0)
		daily_limit_mode = 0;

	json_object_object_add(data_obj, "enable", json_object_new_int(enable));
	json_object_object_add(data_obj, "work_mode", json_object_new_int(work_mode));
	json_object_object_add(data_obj, "record_enable", json_object_new_int(record_enable));
	json_object_object_add(data_obj, "disable_quic", json_object_new_int(disable_quic));
	json_object_object_add(data_obj, "app_filter_mode", json_object_new_int(app_filter_mode));
	json_object_object_add(data_obj, "daily_limit_mode", json_object_new_int(daily_limit_mode));

	json_object_object_add(response, "data", data_obj);
	reply_json(ctx, req, response);

	uci_free_context(uci_ctx);
	json_object_put(response);
	return 0;
}

static int handle_set_app_filter_base(struct ubus_context *ctx,
				      struct ubus_object *obj,
				      struct ubus_request_data *req,
				      const char *method,
				      struct blob_attr *msg)
{
	struct json_object *req_obj, *jval;
	struct uci_context *uci_ctx;
	char *s = blobmsg_format_json(msg, true);

	if (!s)
		return 0;

	printf("handle_set_app_filter_base\n");
	req_obj = json_tokener_parse(s);
	if (!req_obj) {
		free(s);
		return 0;
	}

	jval = json_object_object_get(req_obj, "enable");
	if (!jval || !json_object_object_get(req_obj, "work_mode")) {
		printf("enable_obj or work_mode_obj is NULL\n");
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		printf("Failed to allocate UCI context\n");
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	af_uci_set_int_value(uci_ctx, "appfilter.global.enable",
			     json_object_get_int(jval));
	af_uci_set_int_value(uci_ctx, "appfilter.global.work_mode",
			     json_object_get_int(json_object_object_get(req_obj, "work_mode")));

	if ((jval = json_object_object_get(req_obj, "record_enable")))
		af_uci_set_int_value(uci_ctx, "appfilter.global.record_enable",
				     json_object_get_int(jval));
	if ((jval = json_object_object_get(req_obj, "disable_quic")))
		af_uci_set_int_value(uci_ctx, "appfilter.global.disable_quic",
				     json_object_get_int(jval));
	if ((jval = json_object_object_get(req_obj, "app_filter_mode")))
		af_uci_set_int_value(uci_ctx, "appfilter.global.app_filter_mode",
				     json_object_get_int(jval));
	if ((jval = json_object_object_get(req_obj, "daily_limit_mode")))
		af_uci_set_int_value(uci_ctx, "appfilter.global.daily_limit_mode",
				     json_object_get_int(jval));

	af_uci_commit(uci_ctx, "appfilter");
	reload_oaf_rule();
	g_oaf_config_change = 1;
	uci_free_context(uci_ctx);

	json_object_put(req_obj);
	free(s);
	return reply_code(ctx, req, 0);
}

/* -------------------------------------------------------------------------
 * app_filter_adv get / set
 * ---------------------------------------------------------------------- */

static int handle_get_app_filter_adv(struct ubus_context *ctx,
				     struct ubus_object *obj,
				     struct ubus_request_data *req,
				     const char *method,
				     struct blob_attr *msg)
{
	struct json_object *response = json_object_new_object();
	struct json_object *data_obj = json_object_new_object();
	struct uci_context *uci_ctx;
	char lan_ifname[16] = {0};
	int tcp_rst, disable_hnat, auto_load_engine;

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		printf("Failed to allocate UCI context\n");
		json_object_put(response);
		json_object_put(data_obj);
		return 0;
	}

	tcp_rst = af_uci_get_int_value(uci_ctx, "appfilter.global.tcp_rst");
	af_uci_get_value(uci_ctx, "appfilter.global.lan_ifname",
			 lan_ifname, sizeof(lan_ifname));
	disable_hnat = af_uci_get_int_value(uci_ctx, "appfilter.global.disable_hnat");
	auto_load_engine = af_uci_get_int_value(uci_ctx, "appfilter.global.auto_load_engine");

	json_object_object_add(data_obj, "tcp_rst", json_object_new_int(tcp_rst));
	json_object_object_add(data_obj, "lan_ifname",
			       json_object_new_string(lan_ifname));
	json_object_object_add(data_obj, "disable_hnat",
			       json_object_new_int(disable_hnat));
	json_object_object_add(data_obj, "auto_load_engine",
			       json_object_new_int(auto_load_engine));

	json_object_object_add(response, "data", data_obj);
	reply_json(ctx, req, response);

	uci_free_context(uci_ctx);
	json_object_put(response);
	return 0;
}

static int handle_set_app_filter_adv(struct ubus_context *ctx,
				     struct ubus_object *obj,
				     struct ubus_request_data *req,
				     const char *method,
				     struct blob_attr *msg)
{
	struct json_object *req_obj, *jval;
	struct uci_context *uci_ctx;
	char *s = blobmsg_format_json(msg, true);

	if (!s)
		return 0;

	printf("msg_obj_str: %s\n", s);
	req_obj = json_tokener_parse(s);
	if (!req_obj) {
		free(s);
		return 0;
	}

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		printf("Failed to allocate UCI context\n");
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	if ((jval = json_object_object_get(req_obj, "tcp_rst")))
		af_uci_set_int_value(uci_ctx, "appfilter.global.tcp_rst",
				     json_object_get_int(jval));
	if ((jval = json_object_object_get(req_obj, "lan_ifname")))
		af_uci_set_value(uci_ctx, "appfilter.global.lan_ifname",
				 (char *)json_object_get_string(jval));
	if ((jval = json_object_object_get(req_obj, "disable_hnat")))
		af_uci_set_int_value(uci_ctx, "appfilter.global.disable_hnat",
				     json_object_get_int(jval));
	if ((jval = json_object_object_get(req_obj, "auto_load_engine"))) {
		int auto_load = json_object_get_int(jval);
		int old_auto_load = af_uci_get_int_value(uci_ctx, "appfilter.global.auto_load_engine");
		
		af_uci_set_int_value(uci_ctx, "appfilter.global.auto_load_engine", auto_load);
		
		if (auto_load != old_auto_load) {
			if (auto_load == 0) {
				system("rm -f /etc/modules.d/oaf");
				LOG_WARN("auto_load_engine turned OFF, stopping appfilter and unloading oaf.ko...\n");
				system("(sleep 1; /etc/init.d/appfilter stop 2>/dev/null >/dev/null; sleep 1; rmmod oaf 2>/dev/null) &");
			} else {
				system("echo 'oaf' > /etc/modules.d/oaf");
				LOG_WARN("auto_load_engine turned ON, loading oaf.ko...\n");
				system("modprobe nf_conntrack 2>/dev/null");
				system("modprobe nf_reject_ipv4 2>/dev/null");
				system("modprobe oaf 2>/dev/null");
				system("/etc/init.d/appfilter start 2>/dev/null >/dev/null &");
			}
		}
	}

	af_uci_commit(uci_ctx, "appfilter");
	g_oaf_config_change = 1;
	reload_oaf_rule();
	system("/usr/bin/hnat.sh &");
	if (g_enable_agent)
		forward_msg_to_agent("set_app_filter_adv", s);

	uci_free_context(uci_ctx);
	json_object_put(req_obj);
	free(s);
	return reply_code(ctx, req, 0);
}

/* -------------------------------------------------------------------------
 * app_filter_time get
 * ---------------------------------------------------------------------- */

static void build_daily_time_list(struct uci_context *uci_ctx,
				  struct json_object *data_obj)
{
	struct json_object *daily_time_list_array = json_object_new_array();
	int weekday;

	for (weekday = 0; weekday < 7; weekday++) {
		char uci_key[64] = {0};
		char daily_limit_str[128] = {0};
		struct json_object *day_obj;
		int enable = 0, am_time = 0, pm_time = 0;

		snprintf(uci_key, sizeof(uci_key),
			 "appfilter.time.daily_limit_%d", weekday);
		af_uci_get_value(uci_ctx, uci_key, daily_limit_str,
				 sizeof(daily_limit_str));

		if (strlen(daily_limit_str) > 0) {
			char *first_colon = strchr(daily_limit_str, ':');

			if (first_colon) {
				char *second_colon = strchr(first_colon + 1, ':');

				if (second_colon) {
					enable = atoi(daily_limit_str);
					am_time = atoi(first_colon + 1);
					pm_time = atoi(second_colon + 1);
				} else {
					enable = 1;
					am_time = atoi(daily_limit_str);
					pm_time = atoi(first_colon + 1);
				}
			} else {
				enable = 1;
				am_time = atoi(daily_limit_str);
			}
		}

		day_obj = json_object_new_object();
		json_object_object_add(day_obj, "enable", json_object_new_int(enable));
		json_object_object_add(day_obj, "am_time", json_object_new_int(am_time));
		json_object_object_add(day_obj, "pm_time", json_object_new_int(pm_time));
		json_object_array_add(daily_time_list_array, day_obj);
	}

	json_object_object_add(data_obj, "daily_time_list", daily_time_list_array);
}

static int handle_get_app_filter_time(struct ubus_context *ctx,
				      struct ubus_object *obj,
				      struct ubus_request_data *req,
				      const char *method,
				      struct blob_attr *msg)
{
	struct json_object *response = json_object_new_object();
	struct json_object *data_obj = json_object_new_object();
	struct uci_context *uci_ctx;
	time_t now;
	struct tm *current_time;
	char current_time_str[64] = {0};
	char days_str[128] = {0};
	char days_str_copy[128] = {0};
	char start_time[32] = {0};
	char end_time[32] = {0};
	char time_str[MAX_TIME_LIST_LEN] = {0};
	char time_str_copy[MAX_TIME_LIST_LEN] = {0};
	int global_weekdays[7] = {0};
	int time_mode, deny_time, allow_time;
	struct json_object *days_array, *time_array;
	char *day_token, *saveptr1 = NULL, *time_period;
	int period_count = 0;

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		printf("Failed to allocate UCI context\n");
		json_object_put(response);
		json_object_put(data_obj);
		return 0;
	}

	now = time(NULL);
	current_time = localtime(&now);
	snprintf(current_time_str, sizeof(current_time_str), "%d/%d/%d %d:%02d",
		 current_time->tm_year + 1900,
		 current_time->tm_mon + 1,
		 current_time->tm_mday,
		 current_time->tm_hour,
		 current_time->tm_min);
	json_object_object_add(data_obj, "current_time",
			       json_object_new_string(current_time_str));

	time_mode = af_uci_get_int_value(uci_ctx, "appfilter.time.time_mode");
	json_object_object_add(data_obj, "mode", json_object_new_int(time_mode));

	af_uci_get_value(uci_ctx, "appfilter.time.days", days_str,
			 sizeof(days_str));
	strncpy(days_str_copy, days_str, sizeof(days_str_copy) - 1);
	printf("days_str: %s\n", days_str);

	days_array = json_object_new_array();
	day_token = strtok(days_str, " ");
	while (day_token) {
		json_object_array_add(days_array,
				      json_object_new_int(atoi(day_token)));
		day_token = strtok(NULL, " ");
	}
	json_object_object_add(data_obj, "weekday_list", days_array);

	af_uci_get_value(uci_ctx, "appfilter.time.start_time", start_time,
			 sizeof(start_time));
	af_uci_get_value(uci_ctx, "appfilter.time.end_time", end_time,
			 sizeof(end_time));
	json_object_object_add(data_obj, "start_time",
			       json_object_new_string(start_time));
	json_object_object_add(data_obj, "end_time",
			       json_object_new_string(end_time));

	deny_time = af_uci_get_int_value(uci_ctx, "appfilter.time.deny_time");
	allow_time = af_uci_get_int_value(uci_ctx, "appfilter.time.allow_time");
	json_object_object_add(data_obj, "deny_time",
			       json_object_new_int(deny_time));
	json_object_object_add(data_obj, "allow_time",
			       json_object_new_int(allow_time));

	af_uci_get_list_value(uci_ctx, "appfilter.time.time", time_str,
			      sizeof(time_str), " ");
	printf("time_str from uci: %s\n", time_str);

	/* build global_weekdays fallback map from days_str_copy */
	day_token = strtok(days_str_copy, " ");
	while (day_token) {
		int d = atoi(day_token);

		if (d >= 0 && d < 7)
			global_weekdays[d] = 1;
		day_token = strtok(NULL, " ");
	}

	strncpy(time_str_copy, time_str, sizeof(time_str_copy) - 1);
	printf("ubus parsing time_str_copy: %s\n", time_str_copy);

	time_array = json_object_new_array();
	time_period = strtok_r(time_str_copy, " ", &saveptr1);
	while (time_period) {
		char start[16] = {0};
		char end[16] = {0};
		char weekdays_str[64] = {0};
		int has_weekdays = 0;
		char *semicolon, *delimiter;

		period_count++;
		printf("ubus parsing period[%d]: %s\n", period_count, time_period);

		semicolon = strchr(time_period, ';');
		if (semicolon) {
			has_weekdays = 1;
			strncpy(weekdays_str, time_period,
				semicolon - time_period);
			weekdays_str[semicolon - time_period] = '\0';
			time_period = semicolon + 1;
			printf("ubus period[%d] weekdays: %s, time_part: %s\n",
			       period_count, weekdays_str, time_period);
		}

		delimiter = strchr(time_period, '-');
		if (delimiter) {
			size_t start_len = delimiter - time_period;
			struct json_object *period_obj;
			struct json_object *period_weekdays;

			if (start_len >= sizeof(start))
				start_len = sizeof(start) - 1;
			strncpy(start, time_period, start_len);
			start[start_len] = '\0';

			strncpy(end, delimiter + 1, sizeof(end) - 1);
			end[sizeof(end) - 1] = '\0';

			printf("ubus period[%d] parsed: start=%s, end=%s\n",
			       period_count, start, end);

			period_obj = json_object_new_object();
			json_object_object_add(period_obj, "start",
					       json_object_new_string(start));
			json_object_object_add(period_obj, "end",
					       json_object_new_string(end));

			period_weekdays = json_object_new_array();
			if (has_weekdays) {
				char weekdays_copy[64] = {0};
				char *saveptr2 = NULL, *wd;

				strncpy(weekdays_copy, weekdays_str,
					sizeof(weekdays_copy) - 1);
				wd = strtok_r(weekdays_copy, ",", &saveptr2);
				while (wd) {
					json_object_array_add(period_weekdays,
							      json_object_new_int(atoi(wd)));
					wd = strtok_r(NULL, ",", &saveptr2);
				}
				printf("ubus period[%d] weekday_list size: %zu\n",
				       period_count,
				       json_object_array_length(period_weekdays));
			} else {
				int i;

				for (i = 0; i < 7; i++) {
					if (global_weekdays[i])
						json_object_array_add(period_weekdays,
								      json_object_new_int(i));
				}
			}
			json_object_object_add(period_obj, "weekday_list",
					       period_weekdays);
			json_object_array_add(time_array, period_obj);
			printf("ubus period[%d] added, len=%zu\n",
			       period_count,
			       json_object_array_length(time_array));
		} else {
			printf("ubus period[%d] ERROR: no delimiter\n",
			       period_count);
		}

		time_period = strtok_r(NULL, " ", &saveptr1);
	}
	json_object_object_add(data_obj, "time_list", time_array);

	if (time_mode == 2) {
		int total_am_time = 0, total_pm_time = 0;
		int current_weekday, i;
		daily_limit_config_t *daily_limit;

		build_daily_time_list(uci_ctx, data_obj);

		now = time(NULL);
		current_time = localtime(&now);
		current_weekday = current_time->tm_wday;
		json_object_object_add(data_obj, "current_weekday",
				       json_object_new_int(current_weekday));

		for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
			dev_node_t *node = dev_hash_table[i];

			while (node) {
				if (node->is_selected) {
					total_am_time += node->today_am_active_time;
					total_pm_time += node->today_pm_active_time;
				}
				node = node->next;
			}
		}
		json_object_object_add(data_obj, "current_am_used_time",
				       json_object_new_int(total_am_time));
		json_object_object_add(data_obj, "current_pm_used_time",
				       json_object_new_int(total_pm_time));

		daily_limit = &g_af_config.time.daily_limit[current_weekday];
		json_object_object_add(data_obj, "current_am_limit",
				       json_object_new_int(daily_limit->am_time));
		json_object_object_add(data_obj, "current_pm_limit",
				       json_object_new_int(daily_limit->pm_time));
		json_object_object_add(data_obj, "current_day_enabled",
				       json_object_new_int(daily_limit->enable));
	}

	if (time_mode == 3) {
		struct json_object *dev_list = json_object_new_array();
		int i;
		for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
			dev_node_t *node = dev_hash_table[i];
			while (node) {
				if (node->is_selected && strlen(node->custom_time_json) > 0) {
					struct json_object *dev_obj = json_tokener_parse(node->custom_time_json);
					if (dev_obj) json_object_array_add(dev_list, dev_obj);
				}
				node = node->next;
			}
		}
		json_object_object_add(data_obj, "device_time_list", dev_list);
	}

	json_object_object_add(response, "data", data_obj);
	printf("response_json: %s\n", json_object_to_json_string(response));
	reply_json(ctx, req, response);

	uci_free_context(uci_ctx);
	json_object_put(response);
	return 0;
}

/* -------------------------------------------------------------------------
 * app_filter_time set
 * ---------------------------------------------------------------------- */

static int apply_fixed_mode(struct uci_context *uci_ctx,
			    struct json_object *req_obj)
{
	struct json_object *time_list_obj;
	int time_list_len, i;

	time_list_obj = json_object_object_get(req_obj, "time_list");
	if (!time_list_obj)
		return -1;

	af_uci_delete(uci_ctx, "appfilter.time.time");
	time_list_len = json_object_array_length(time_list_obj);
	if (time_list_len > MAX_TIME_LIST) {
		LOG_WARN("time_list length %d exceeds %d, truncate\n",
			 time_list_len, MAX_TIME_LIST);
		time_list_len = MAX_TIME_LIST;
	}

	for (i = 0; i < time_list_len; i++) {
		struct json_object *time_obj = json_object_array_get_idx(time_list_obj, i);
		struct json_object *start_time_obj, *end_time_obj;
		struct json_object *period_wd_obj;
		char time_str[256] = {0};

		start_time_obj = json_object_object_get(time_obj, "start");
		end_time_obj = json_object_object_get(time_obj, "end");
		if (!start_time_obj || !end_time_obj) {
			printf("start_time_obj or end_time_obj is NULL\n");
			return -1;
		}

		period_wd_obj = json_object_object_get(time_obj, "weekday_list");
		if (period_wd_obj && json_object_array_length(period_wd_obj) > 0) {
			char weekday_str[64] = {0};
			int j, n = json_object_array_length(period_wd_obj);

			for (j = 0; j < n; j++) {
				struct json_object *wd_obj =
					json_object_array_get_idx(period_wd_obj, j);
				char tmp[8];

				if (j > 0)
					strcat(weekday_str, ",");
				snprintf(tmp, sizeof(tmp), "%d",
					 json_object_get_int(wd_obj));
				strcat(weekday_str, tmp);
			}
			snprintf(time_str, sizeof(time_str), "%s;%s-%s",
				 weekday_str,
				 json_object_get_string(start_time_obj),
				 json_object_get_string(end_time_obj));
		} else {
			snprintf(time_str, sizeof(time_str), "%s-%s",
				 json_object_get_string(start_time_obj),
				 json_object_get_string(end_time_obj));
		}

		printf("time_str: %s\n", time_str);
		af_uci_add_list(uci_ctx, "appfilter.time.time", time_str);
	}
	return 0;
}

static int apply_dynamic_mode(struct uci_context *uci_ctx,
			      struct json_object *req_obj)
{
	struct json_object *deny_obj, *allow_obj, *start_obj, *end_obj;

	deny_obj = json_object_object_get(req_obj, "deny_time");
	allow_obj = json_object_object_get(req_obj, "allow_time");
	start_obj = json_object_object_get(req_obj, "start_time");
	end_obj = json_object_object_get(req_obj, "end_time");
	if (!deny_obj || !allow_obj || !start_obj || !end_obj)
		return -1;

	af_uci_set_int_value(uci_ctx, "appfilter.time.deny_time",
			     json_object_get_int(deny_obj));
	af_uci_set_int_value(uci_ctx, "appfilter.time.allow_time",
			     json_object_get_int(allow_obj));
	af_uci_set_value(uci_ctx, "appfilter.time.start_time",
			 (char *)json_object_get_string(start_obj));
	af_uci_set_value(uci_ctx, "appfilter.time.end_time",
			 (char *)json_object_get_string(end_obj));
	return 0;
}

static int apply_daily_mode(struct uci_context *uci_ctx,
			    struct json_object *req_obj)
{
	struct json_object *list_obj;
	int len, i;

	list_obj = json_object_object_get(req_obj, "daily_time_list");
	if (!list_obj)
		return -1;

	len = json_object_array_length(list_obj);
	if (len != 7) {
		printf("daily_time_list length should be 7, got %d\n", len);
		return -1;
	}

	for (i = 0; i < 7; i++) {
		char uci_key[64] = {0};

		snprintf(uci_key, sizeof(uci_key),
			 "appfilter.time.daily_limit_%d", i);
		af_uci_delete(uci_ctx, uci_key);
	}

	for (i = 0; i < 7; i++) {
		struct json_object *day_obj = json_object_array_get_idx(list_obj, i);
		struct json_object *enable_obj, *am_obj, *pm_obj;
		char limit_str[32] = {0};
		char uci_key[64] = {0};
		int enable, am_time, pm_time;

		enable_obj = json_object_object_get(day_obj, "enable");
		am_obj = json_object_object_get(day_obj, "am_time");
		pm_obj = json_object_object_get(day_obj, "pm_time");
		if (!enable_obj || !am_obj || !pm_obj)
			continue;

		enable = json_object_get_int(enable_obj);
		am_time = json_object_get_int(am_obj);
		pm_time = json_object_get_int(pm_obj);

		snprintf(limit_str, sizeof(limit_str), "%d:%d:%d",
			 enable, am_time, pm_time);
		snprintf(uci_key, sizeof(uci_key),
			 "appfilter.time.daily_limit_%d", i);
		printf("daily_limit_%d: %s\n", i, limit_str);
		af_uci_set_value(uci_ctx, uci_key, limit_str);
	}
	return 0;
}

static void drop_keys(struct uci_context *uci_ctx, int mode)
{
	if (mode == 0) {
		af_uci_delete(uci_ctx, "appfilter.time.days");
		af_uci_delete(uci_ctx, "appfilter.time.deny_time");
		af_uci_delete(uci_ctx, "appfilter.time.allow_time");
		af_uci_delete(uci_ctx, "appfilter.time.start_time");
		af_uci_delete(uci_ctx, "appfilter.time.end_time");
		for (int i = 0; i < 7; i++) {
			char key[64] = {0};

			snprintf(key, sizeof(key),
				 "appfilter.time.daily_limit_%d", i);
			af_uci_delete(uci_ctx, key);
		}
	} else if (mode == 1) {
		af_uci_delete(uci_ctx, "appfilter.time.time");
		for (int i = 0; i < 7; i++) {
			char key[64] = {0};

			snprintf(key, sizeof(key),
				 "appfilter.time.daily_limit_%d", i);
			af_uci_delete(uci_ctx, key);
		}
	} else if (mode == 2) {
		af_uci_delete(uci_ctx, "appfilter.time.time");
		af_uci_delete(uci_ctx, "appfilter.time.days");
		af_uci_delete(uci_ctx, "appfilter.time.deny_time");
		af_uci_delete(uci_ctx, "appfilter.time.allow_time");
		af_uci_delete(uci_ctx, "appfilter.time.start_time");
		af_uci_delete(uci_ctx, "appfilter.time.end_time");
	}
}

static int handle_set_app_filter_time(struct ubus_context *ctx,
				      struct ubus_object *obj,
				      struct ubus_request_data *req,
				      const char *method,
				      struct blob_attr *msg)
{
	struct json_object *req_obj, *mode_obj, *weekday_list_obj;
	struct uci_context *uci_ctx;
	char *s = blobmsg_format_json(msg, true);
	int mode = 0, ret = 0;

	if (!s)
		return 0;

	printf("set appfilter time\n");
	printf("msg_obj_str: %s\n", s);
	req_obj = json_tokener_parse(s);
	if (!req_obj) {
		free(s);
		return 0;
	}

	mode_obj = json_object_object_get(req_obj, "mode");
	if (!mode_obj) {
		printf("mode_obj is NULL\n");
		json_object_put(req_obj);
		free(s);
		return 0;
	}
	mode = json_object_get_int(mode_obj);

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		printf("Failed to allocate UCI context\n");
		json_object_put(req_obj);
		free(s);
		return 0;
	}
	af_uci_set_int_value(uci_ctx, "appfilter.time.time_mode", mode);

	weekday_list_obj = json_object_object_get(req_obj, "weekday_list");
	if (weekday_list_obj && (mode == 0 || mode == 1) &&
	    json_object_array_length(weekday_list_obj) > 0) {
		char days_str[128] = {0};
		int i, n = json_object_array_length(weekday_list_obj);

		for (i = 0; i < n; i++) {
			struct json_object *wd_obj =
				json_object_array_get_idx(weekday_list_obj, i);
			char tmp[8];

			snprintf(tmp, sizeof(tmp), "%d",
				 json_object_get_int(wd_obj));
			if (i > 0)
				strcat(days_str, " ");
			strcat(days_str, tmp);
		}
		af_uci_set_value(uci_ctx, "appfilter.time.days", days_str);
	}

	if (mode == 0)
		ret = apply_fixed_mode(uci_ctx, req_obj);
	else if (mode == 1)
		ret = apply_dynamic_mode(uci_ctx, req_obj);
	else if (mode == 2)
		ret = apply_daily_mode(uci_ctx, req_obj);
	else if (mode == 3) {
		int num_old = af_get_uci_list_num(uci_ctx, "appfilter", "device_time");
		for (int k = num_old - 1; k >= 0; k--) {
			char buf[128];
			snprintf(buf, sizeof(buf), "appfilter.@device_time[%d]", k);
			af_uci_delete(uci_ctx, buf);
		}

		struct json_object *dev_list_obj = json_object_object_get(req_obj, "device_time_list");
		if (dev_list_obj && json_object_is_type(dev_list_obj, json_type_array)) {
			int len = json_object_array_length(dev_list_obj);
			for (int i = 0; i < len; i++) {
				struct json_object *dev_obj = json_object_array_get_idx(dev_list_obj, i);
				struct json_object *mac_obj = json_object_object_get(dev_obj, "mac");
				if (!mac_obj) continue;

				char mac[32] = {0};
				mac_copy_lower(mac, json_object_get_string(mac_obj), sizeof(mac));

				af_uci_add_section(uci_ctx, "appfilter", "device_time");
				af_uci_set_value(uci_ctx, "appfilter.@device_time[-1].mac", mac);
				af_uci_set_value(uci_ctx, "appfilter.@device_time[-1].data", json_object_to_json_string(dev_obj));

				dev_node_t *node = find_dev_node(mac);
				if (node) {
					strncpy(node->custom_time_json, json_object_to_json_string(dev_obj), sizeof(node->custom_time_json) - 1);
				}
			}
			ret = 0;
		}
	}

	if (ret < 0)
		goto done;

	drop_keys(uci_ctx, mode);

	af_uci_commit(uci_ctx, "appfilter");
	g_oaf_config_change = 1;
	if (g_enable_agent)
		forward_msg_to_agent("set_app_filter_time", s);

done:
	uci_free_context(uci_ctx);
	json_object_put(req_obj);
	free(s);
	return reply_code(ctx, req, 0);
}

/* -------------------------------------------------------------------------
 * get_all_users
 * ---------------------------------------------------------------------- */

static void all_users_callback(void *arg, dev_node_t *dev)
{
	struct all_users_info *au_info = arg;
	int flag = au_info->flag;
	struct json_object *users_array = au_info->users_array;
	struct json_object *user_obj;
	int online_status;

	user_obj = json_object_new_object();
	json_object_object_add(user_obj, "mac", json_object_new_string(dev->mac));

	online_status = dev->online;
	if (dev->active == 1 && dev->online == 1)
		online_status = 2;
	json_object_object_add(user_obj, "online",
			       json_object_new_int(online_status));
	json_object_object_add(user_obj, "online_time",
			       json_object_new_int(dev->online_time));
	json_object_object_add(user_obj, "offline_time",
			       json_object_new_int(dev->offline_time));
	json_object_object_add(user_obj, "today_am_active_time",
			       json_object_new_int(dev->today_am_active_time));
	json_object_object_add(user_obj, "today_pm_active_time",
			       json_object_new_int(dev->today_pm_active_time));

	if (flag > 0)
		json_object_object_add(user_obj, "ip",
				       json_object_new_string(dev->ip));

	if (flag > 1) {
		json_object_object_add(user_obj, "hostname",
				       json_object_new_string(dev->hostname));
		json_object_object_add(user_obj, "nickname",
				       json_object_new_string(dev->nickname));
		json_object_object_add(user_obj, "is_whitelist",
				       json_object_new_int(dev->is_whitelist));
		json_object_object_add(user_obj, "is_selected",
				       json_object_new_int(dev->is_selected));
	}

	if (flag > 2) {
		struct json_object *app_array = json_object_new_array();
		app_visit_time_info_t top5_app_list[5];
		int i;

		memset(top5_app_list, 0, sizeof(top5_app_list));
		update_top5_app(dev, top5_app_list);
		for (i = 0; i < 5; i++) {
			struct json_object *app_obj;

			if (top5_app_list[i].app_id == 0 ||
			    !strlen(get_app_name_by_id(top5_app_list[i].app_id)))
				break;

			app_obj = json_object_new_object();
			json_object_object_add(app_obj, "id",
					       json_object_new_int(top5_app_list[i].app_id));
			json_object_object_add(app_obj, "icon",
					       json_object_new_int(app_icon_exists(top5_app_list[i].app_id)));
			json_object_object_add(app_obj, "name",
					       json_object_new_string(get_app_name_by_id(top5_app_list[i].app_id)));
			json_object_array_add(app_array, app_obj);
		}
		json_object_object_add(user_obj, "applist", app_array);

		if (strlen(dev->visiting_url) > 0)
			json_object_object_add(user_obj, "url",
					       json_object_new_string(dev->visiting_url));
		else
			json_object_object_add(user_obj, "url",
					       json_object_new_string(""));

		if (dev->visiting_app > 0 &&
		    strlen(get_app_name_by_id(dev->visiting_app)) > 0)
			json_object_object_add(user_obj, "app",
					       json_object_new_string(get_app_name_by_id(dev->visiting_app)));
		else
			json_object_object_add(user_obj, "app",
					       json_object_new_string(""));

		json_object_object_add(user_obj, "up_rate",
				       json_object_new_int(dev->up_rate / 1024));
		json_object_object_add(user_obj, "down_rate",
				       json_object_new_int(dev->down_rate / 1024));
		json_object_object_add(user_obj, "today_up_flow",
				       json_object_new_int64((int64_t)(dev->today_up_bytes / 1024)));
		json_object_object_add(user_obj, "today_down_flow",
				       json_object_new_int64((int64_t)(dev->today_down_bytes / 1024)));
	}

	if (g_af_config.time.time_mode == 3 && strlen(dev->custom_time_json) > 0) {
		struct json_object *jobj = json_tokener_parse(dev->custom_time_json);
		if (jobj) {
			struct json_object *mode_obj = json_object_object_get(jobj, "mode");
			int dev_mode = mode_obj ? json_object_get_int(mode_obj) : -1;
			if (dev_mode == 1) {
				json_object_object_add(user_obj, "dyn_filter", json_object_new_int(dev->time_status.filter));
				json_object_object_add(user_obj, "dyn_deny_time", json_object_new_int(dev->time_status.deny_time));
				json_object_object_add(user_obj, "dyn_allow_time", json_object_new_int(dev->time_status.allow_time));
				json_object_object_add(user_obj, "dyn_match_time", json_object_new_int(dev->time_status.match_time));
			}
			json_object_put(jobj);
		}
	}
	json_object_array_add(users_array, user_obj);
}

static int compare_users(const void *a, const void *b)
{
	struct json_object *ua = *(struct json_object **)a;
	struct json_object *ub = *(struct json_object **)b;
	struct json_object *oa, *ob, *t_a, *t_b;
	int oa_v, ob_v;

	json_object_object_get_ex(ua, "online", &oa);
	json_object_object_get_ex(ub, "online", &ob);
	oa_v = json_object_get_int(oa);
	ob_v = json_object_get_int(ob);

	if (oa_v != ob_v)
		return ob_v - oa_v;

	json_object_object_get_ex(ua, "online_time", &t_a);
	json_object_object_get_ex(ub, "online_time", &t_b);

	if (oa_v == 1 && ob_v == 1)
		return json_object_get_int(t_a) - json_object_get_int(t_b);

	json_object_object_get_ex(ua, "offline_time", &t_a);
	json_object_object_get_ex(ub, "offline_time", &t_b);
	return json_object_get_int(t_a) - json_object_get_int(t_b);
}

static int handle_get_all_users(struct ubus_context *ctx,
				struct ubus_object *obj,
				struct ubus_request_data *req,
				const char *method,
				struct blob_attr *msg)
{
	struct json_object *response = json_object_new_object();
	struct json_object *data_obj = json_object_new_object();
	struct json_object *paged_array = NULL;
	struct json_object *req_obj = NULL;
	struct all_users_info au_info;
	int flag = 0, page = 0, page_size = 20;
	int total_count, i;
	char *s = blobmsg_format_json(msg, true);

	if (s) {
		req_obj = json_tokener_parse(s);
		if (req_obj) {
			struct json_object *obj2;

			if ((obj2 = json_object_object_get(req_obj, "flag")))
				flag = json_object_get_int(obj2);
			if ((obj2 = json_object_object_get(req_obj, "page")))
				page = json_object_get_int(obj2);
			if ((obj2 = json_object_object_get(req_obj, "page_size"))) {
				page_size = json_object_get_int(obj2);
				if (page_size <= 0)
					page_size = 20;
				else if (page_size > 1000)
					page_size = 1000;
			}
		}
	}
	printf("flag: %d, page: %d, page_size: %d\n", flag, page, page_size);

	au_info.flag = flag;
	au_info.users_array = json_object_new_array();

	update_dev_nickname();
	update_dev_visiting_info();
	update_dev_whitelist_flag();
	dev_foreach(&au_info, all_users_callback);

	json_object_array_sort(au_info.users_array, compare_users);
	total_count = json_object_array_length(au_info.users_array);

	if (page <= 0) {
		paged_array = json_object_get(au_info.users_array);
	} else {
		int start = (page - 1) * page_size;
		int end = start + page_size;

		paged_array = json_object_new_array();
		for (i = start; i < end && i < total_count; i++) {
			struct json_object *uo =
				json_object_array_get_idx(au_info.users_array, i);

			if (uo) {
				json_object_get(uo);
				json_object_array_add(paged_array, uo);
			}
		}
	}

	json_object_object_add(data_obj, "list", paged_array);
	json_object_object_add(data_obj, "total",
			       json_object_new_int(total_count));
	json_object_object_add(data_obj, "page", json_object_new_int(page));
	json_object_object_add(data_obj, "page_size",
			       json_object_new_int(page_size));
	json_object_object_add(data_obj, "total_pages",
			       json_object_new_int(page_size > 0
						   ? (total_count + page_size - 1) / page_size
						   : 0));
	json_object_put(au_info.users_array);

	json_object_object_add(response, "data", data_obj);

	if (req_obj)
		json_object_put(req_obj);
	free(s);

	reply_json(ctx, req, response);
	json_object_put(response);
	return 0;
}

/* -------------------------------------------------------------------------
 * app_filter_user get / set / del / add
 * ---------------------------------------------------------------------- */

static int handle_get_app_filter_user(struct ubus_context *ctx,
				      struct ubus_object *obj,
				      struct ubus_request_data *req,
				      const char *method,
				      struct blob_attr *msg)
{
	struct json_object *response = json_object_new_object();
	struct json_object *data_obj = json_object_new_object();
	struct json_object *user_array = json_object_new_array();
	struct uci_context *uci_ctx;
	char mac_str[128];
	int mode, num, i;

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		printf("Failed to allocate UCI context\n");
		json_object_put(user_array);
		json_object_put(data_obj);
		json_object_put(response);
		return 0;
	}

	mode = af_uci_get_int_value(uci_ctx, "appfilter.global.user_mode");
	if (mode < 0)
		mode = 0;
	json_object_object_add(data_obj, "mode", json_object_new_int(mode));

	num = af_get_uci_list_num(uci_ctx, "appfilter", "af_user");
	for (i = 0; i < num; i++) {
		struct json_object *user_obj = json_object_new_object();
		dev_node_t *dev;

		memset(mac_str, 0, sizeof(mac_str));
		af_uci_get_array_value(uci_ctx, "appfilter.@af_user[%d].mac", i,
				       mac_str, sizeof(mac_str));

		json_object_object_add(user_obj, "mac",
				       json_object_new_string(mac_str));

		dev = find_dev_node(mac_str);
		if (dev) {
			json_object_object_add(user_obj, "nickname",
					       json_object_new_string(dev->nickname));
			json_object_object_add(user_obj, "hostname",
					       json_object_new_string(dev->hostname));
		} else {
			json_object_object_add(user_obj, "nickname",
					       json_object_new_string(""));
			json_object_object_add(user_obj, "hostname",
					       json_object_new_string(""));
		}
		json_object_array_add(user_array, user_obj);
	}

	json_object_object_add(data_obj, "list", user_array);
	json_object_object_add(response, "data", data_obj);
	reply_json(ctx, req, response);

	uci_free_context(uci_ctx);
	json_object_put(response);
	return 0;
}

static int handle_set_app_filter_user(struct ubus_context *ctx,
				      struct ubus_object *obj,
				      struct ubus_request_data *req,
				      const char *method,
				      struct blob_attr *msg)
{
	struct json_object *req_obj, *mode_obj;
	struct uci_context *uci_ctx;
	char *s = blobmsg_format_json(msg, true);

	if (!s)
		return 0;

	printf("msg_obj_str: %s\n", s);
	req_obj = json_tokener_parse(s);
	if (!req_obj) {
		free(s);
		return 0;
	}

	mode_obj = json_object_object_get(req_obj, "mode");
	if (!mode_obj) {
		printf("mode_object is NULL\n");
		json_object_put(req_obj);
		free(s);
		return 0;
	}
	printf("mode_object: %d\n", json_object_get_int(mode_obj));

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		printf("Failed to allocate UCI context\n");
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	af_uci_set_int_value(uci_ctx, "appfilter.global.user_mode",
			     json_object_get_int(mode_obj));
	af_uci_commit(uci_ctx, "appfilter");
	reload_oaf_rule();
	g_oaf_config_change = 1;
	if (g_enable_agent)
		forward_msg_to_agent("set_app_filter_user", s);

	uci_free_context(uci_ctx);
	json_object_put(req_obj);
	free(s);
	return reply_code(ctx, req, 0);
}

static int handle_del_app_filter_user(struct ubus_context *ctx,
				      struct ubus_object *obj,
				      struct ubus_request_data *req,
				      const char *method,
				      struct blob_attr *msg)
{
	struct json_object *req_obj, *mac_obj;
	struct uci_context *uci_ctx;
	char mac_str[128];
	char *s = blobmsg_format_json(msg, true);
	int num, i;

	if (!s)
		return 0;

	printf("handle_del_app_filter_user\n");
	printf("msg_obj_str: %s\n", s);
	req_obj = json_tokener_parse(s);
	if (!req_obj) {
		free(s);
		return 0;
	}

	mac_obj = json_object_object_get(req_obj, "mac");
	if (!mac_obj) {
		printf("mac_obj is NULL\n");
		json_object_put(req_obj);
		free(s);
		return 0;
	}
	printf("mac: %s\n", json_object_get_string(mac_obj));

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		printf("Failed to allocate UCI context\n");
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	num = af_get_uci_list_num(uci_ctx, "appfilter", "af_user");
	for (i = 0; i < num; i++) {
		memset(mac_str, 0, sizeof(mac_str));
		af_uci_get_array_value(uci_ctx, "appfilter.@af_user[%d].mac", i,
				       mac_str, sizeof(mac_str));
		if (!strcasecmp(mac_str, json_object_get_string(mac_obj))) {
			char buf[128] = {0};
			dev_node_t *dev;

			printf("delete af_user[%d]\n", i);
			snprintf(buf, sizeof(buf), "appfilter.@af_user[%d]", i);
			af_uci_delete(uci_ctx, buf);

			dev = find_dev_node(mac_str);
			if (dev) {
				dev->is_selected = 0;
				dev->blocked = 0;
				dev->today_am_active_time = 0;
				dev->today_pm_active_time = 0;
				dev->today_up_bytes = 0;
				dev->today_down_bytes = 0;
				dev->last_up_bytes = 0;
				dev->last_down_bytes = 0;
				sync_blocked_macs_to_kernel();
			}
			break;
		}
	}

	af_uci_commit(uci_ctx, "appfilter");
	reload_oaf_rule();
	g_oaf_config_change = 1;
	if (g_enable_agent)
		forward_msg_to_agent("del_app_filter_user", s);

	uci_free_context(uci_ctx);
	json_object_put(req_obj);
	free(s);
	return reply_code(ctx, req, 0);
}

static int handle_add_app_filter_user(struct ubus_context *ctx,
				      struct ubus_object *obj,
				      struct ubus_request_data *req,
				      const char *method,
				      struct blob_attr *msg)
{
	struct json_object *req_obj, *mac_array;
	struct uci_context *uci_ctx;
	char *s = blobmsg_format_json(msg, true);
	int len, i;

	if (!s)
		return 0;

	printf("handle_add_app_filter_user\n");
	printf("msg_obj_str: %s\n", s);
	req_obj = json_tokener_parse(s);
	if (!req_obj) {
		printf("parse json failed\n");
		free(s);
		return 0;
	}

	mac_array = json_object_object_get(req_obj, "mac_list");
	if (!mac_array) {
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		printf("Failed to allocate UCI context\n");
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	len = json_object_array_length(mac_array);
	printf("len: %d\n", len);
	for (i = 0; i < len; i++) {
		struct json_object *mac_obj = json_object_array_get_idx(mac_array, i);
		const char *mac_src = json_object_get_string(mac_obj);
		char mac_lower[32] = {0};

		mac_copy_lower(mac_lower, mac_src ? mac_src : "",
			       sizeof(mac_lower));
		af_uci_add_section(uci_ctx, "appfilter", "af_user");
		af_uci_set_value(uci_ctx, "appfilter.@af_user[-1].mac",
				 mac_lower);
	}
	printf("add af_user ok\n");

	af_uci_commit(uci_ctx, "appfilter");
	reload_oaf_rule();
	g_oaf_config_change = 1;
	if (g_enable_agent)
		forward_msg_to_agent("add_app_filter_user", s);

	uci_free_context(uci_ctx);
	json_object_put(req_obj);
	free(s);
	return reply_code(ctx, req, 0);
}

/* -------------------------------------------------------------------------
 * whitelist get / add / del
 * ---------------------------------------------------------------------- */

static int handle_get_whitelist_user(struct ubus_context *ctx,
				     struct ubus_object *obj,
				     struct ubus_request_data *req,
				     const char *method,
				     struct blob_attr *msg)
{
	struct json_object *response = json_object_new_object();
	struct json_object *data_obj = json_object_new_object();
	struct json_object *user_array = json_object_new_array();
	struct uci_context *uci_ctx;
	char mac_str[128];
	int num, i;

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		printf("Failed to allocate UCI context\n");
		json_object_put(user_array);
		json_object_put(data_obj);
		json_object_put(response);
		return 0;
	}

	num = af_get_uci_list_num(uci_ctx, "appfilter", "whitelist");
	for (i = 0; i < num; i++) {
		struct json_object *user_obj = json_object_new_object();
		dev_node_t *dev;

		memset(mac_str, 0, sizeof(mac_str));
		af_uci_get_array_value(uci_ctx, "appfilter.@whitelist[%d].mac", i,
				       mac_str, sizeof(mac_str));

		json_object_object_add(user_obj, "mac",
				       json_object_new_string(mac_str));

		dev = find_dev_node(mac_str);
		if (dev) {
			json_object_object_add(user_obj, "nickname",
					       json_object_new_string(dev->nickname));
			json_object_object_add(user_obj, "hostname",
					       json_object_new_string(dev->hostname));
		} else {
			json_object_object_add(user_obj, "nickname",
					       json_object_new_string(""));
			json_object_object_add(user_obj, "hostname",
					       json_object_new_string(""));
		}
		json_object_array_add(user_array, user_obj);
	}

	json_object_object_add(data_obj, "list", user_array);
	json_object_object_add(response, "data", data_obj);
	reply_json(ctx, req, response);

	uci_free_context(uci_ctx);
	json_object_put(response);
	return 0;
}

static int handle_add_whitelist_user(struct ubus_context *ctx,
				     struct ubus_object *obj,
				     struct ubus_request_data *req,
				     const char *method,
				     struct blob_attr *msg)
{
	struct json_object *req_obj, *mac_array;
	struct uci_context *uci_ctx;
	char *s = blobmsg_format_json(msg, true);
	int len, i;

	if (!s)
		return 0;

	req_obj = json_tokener_parse(s);
	if (!req_obj) {
		printf("parse json failed\n");
		free(s);
		return 0;
	}

	mac_array = json_object_object_get(req_obj, "mac_list");
	if (!mac_array) {
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	len = json_object_array_length(mac_array);
	for (i = 0; i < len; i++) {
		struct json_object *mac_obj = json_object_array_get_idx(mac_array, i);
		const char *mac_src = json_object_get_string(mac_obj);
		char mac_lower[32] = {0};

		mac_copy_lower(mac_lower, mac_src ? mac_src : "",
			       sizeof(mac_lower));
		af_uci_add_section(uci_ctx, "appfilter", "whitelist");
		af_uci_set_value(uci_ctx, "appfilter.@whitelist[-1].mac",
				 mac_lower);
	}

	af_uci_commit(uci_ctx, "appfilter");
	reload_oaf_rule();
	g_oaf_config_change = 1;
	if (g_enable_agent)
		forward_msg_to_agent("add_whitelist_user", s);

	uci_free_context(uci_ctx);
	json_object_put(req_obj);
	free(s);
	return reply_code(ctx, req, 0);
}

static int handle_del_whitelist_user(struct ubus_context *ctx,
				     struct ubus_object *obj,
				     struct ubus_request_data *req,
				     const char *method,
				     struct blob_attr *msg)
{
	struct json_object *req_obj, *mac_obj;
	struct uci_context *uci_ctx;
	char mac_str[128];
	char *s = blobmsg_format_json(msg, true);
	int num, i;

	if (!s)
		return 0;

	printf("msg_obj_str: %s\n", s);
	req_obj = json_tokener_parse(s);
	if (!req_obj) {
		free(s);
		return 0;
	}

	mac_obj = json_object_object_get(req_obj, "mac");
	if (!mac_obj) {
		printf("mac_obj is NULL\n");
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		printf("Failed to allocate UCI context\n");
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	num = af_get_uci_list_num(uci_ctx, "appfilter", "whitelist");
	for (i = 0; i < num; i++) {
		memset(mac_str, 0, sizeof(mac_str));
		af_uci_get_array_value(uci_ctx, "appfilter.@whitelist[%d].mac", i,
				       mac_str, sizeof(mac_str));
		if (!strcasecmp(mac_str, json_object_get_string(mac_obj))) {
			char buf[128] = {0};

			snprintf(buf, sizeof(buf), "appfilter.@whitelist[%d]", i);
			af_uci_delete(uci_ctx, buf);
			break;
		}
	}

	af_uci_commit(uci_ctx, "appfilter");
	reload_oaf_rule();
	g_oaf_config_change = 1;
	if (g_enable_agent)
		forward_msg_to_agent("del_whitelist_user", s);

	uci_free_context(uci_ctx);
	json_object_put(req_obj);
	free(s);
	return reply_code(ctx, req, 0);
}

/* -------------------------------------------------------------------------
 * set_nickname
 * ---------------------------------------------------------------------- */

static int handle_set_nickname(struct ubus_context *ctx,
			       struct ubus_object *obj,
			       struct ubus_request_data *req,
			       const char *method,
			       struct blob_attr *msg)
{
	struct json_object *req_obj, *mac_obj, *nickname_obj;
	struct uci_context *uci_ctx;
	char mac_str[128];
	char *s = blobmsg_format_json(msg, true);
	int num, i, index = -1;

	if (!s)
		return 0;

	printf("msg_obj_str: %s\n", s);
	req_obj = json_tokener_parse(s);
	if (!req_obj) {
		printf("parse json failed\n");
		free(s);
		return 0;
	}

	mac_obj = json_object_object_get(req_obj, "mac");
	nickname_obj = json_object_object_get(req_obj, "nickname");
	if (!mac_obj || !nickname_obj) {
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		printf("Failed to allocate UCI context\n");
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	num = af_get_uci_list_num(uci_ctx, "user_info", "user_info");
	for (i = 0; i < num; i++) {
		memset(mac_str, 0, sizeof(mac_str));
		af_uci_get_array_value(uci_ctx, "user_info.@user_info[%d].mac", i,
				       mac_str, sizeof(mac_str));
		if (!strcasecmp(mac_str, json_object_get_string(mac_obj))) {
			index = i;
			printf("found nickname index: %d\n", index);
			break;
		}
	}

	if (strlen(json_object_get_string(nickname_obj)) > 0) {
		if (index == -1) {
			if (af_uci_add_section(uci_ctx, "user_info", "user_info") != 0) {
				LOG_ERROR("add user_info section failed\n");
				goto commit;
			}
		}
		af_uci_set_array_value(uci_ctx, "user_info.@user_info[%d].mac",
				       index,
				       (char *)json_object_get_string(mac_obj));
		af_uci_set_array_value(uci_ctx, "user_info.@user_info[%d].nickname",
				       index,
				       (char *)json_object_get_string(nickname_obj));
	} else {
		if (index != -1) {
			char buf[128] = {0};

			snprintf(buf, sizeof(buf),
				 "user_info.@user_info[%d]", index);
			af_uci_delete(uci_ctx, buf);
			printf("delete nickname mac = %s\n",
			       json_object_get_string(mac_obj));
		}
	}

commit:
	af_uci_commit(uci_ctx, "user_info");
	reload_oaf_rule();
	if (g_enable_agent)
		forward_msg_to_agent("set_nickname", s);

	uci_free_context(uci_ctx);
	json_object_put(req_obj);
	free(s);
	return reply_code(ctx, req, 0);
}

/* -------------------------------------------------------------------------
 * get_oaf_status
 * ---------------------------------------------------------------------- */

static void add_daily_limit_status(struct json_object *data_obj,
				   struct tm *current_time)
{
	daily_limit_config_t *daily_limit;
	int current_weekday = current_time->tm_wday;
	int total_am_time = 0, total_pm_time = 0;
	int selected_user_count = 0;
	int i;

	json_object_object_add(data_obj, "remain_time",
			       json_object_new_int(g_af_status.remain_time));
	json_object_object_add(data_obj, "used_time",
			       json_object_new_int(g_af_status.used_time));
	json_object_object_add(data_obj, "period_blocked",
			       json_object_new_int(g_af_status.period_blocked));
	json_object_object_add(data_obj, "current_weekday",
			       json_object_new_int(current_weekday));

	daily_limit = &g_af_config.time.daily_limit[current_weekday];
	if (daily_limit->enable) {
		json_object_object_add(data_obj, "am_time_limit",
				       json_object_new_int(daily_limit->am_time));
		json_object_object_add(data_obj, "pm_time_limit",
				       json_object_new_int(daily_limit->pm_time));
	} else {
		json_object_object_add(data_obj, "am_time_limit",
				       json_object_new_int(0));
		json_object_object_add(data_obj, "pm_time_limit",
				       json_object_new_int(0));
	}

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			if (node->is_selected) {
				total_am_time += node->today_am_active_time;
				total_pm_time += node->today_pm_active_time;
				if (node->online)
					selected_user_count++;
			}
			node = node->next;
		}
	}

	json_object_object_add(data_obj, "current_am_used_time",
			       json_object_new_int(total_am_time));
	json_object_object_add(data_obj, "current_pm_used_time",
			       json_object_new_int(total_pm_time));
	json_object_object_add(data_obj, "selected_user_count",
			       json_object_new_int(selected_user_count));
	json_object_object_add(data_obj, "current_am_limit",
			       json_object_new_int(daily_limit->am_time));
	json_object_object_add(data_obj, "current_pm_limit",
			       json_object_new_int(daily_limit->pm_time));
	json_object_object_add(data_obj, "current_day_enabled",
			       json_object_new_int(daily_limit->enable));
}

static int handle_get_oaf_status(struct ubus_context *ctx,
				 struct ubus_object *obj,
				 struct ubus_request_data *req,
				 const char *method,
				 struct blob_attr *msg)
{
	struct json_object *response = json_object_new_object();
	struct json_object *data_obj = json_object_new_object();
	char result[128] = {0};
	char kernel_version[128] = {0};
	struct uci_context *uci_ctx;
	time_t now;
	struct tm *current_time;
	int enable = 0, engine_status = 0;
	int ret;

	ret = af_read_file_value("/proc/sys/oaf/enable", result, sizeof(result));
	if (ret != 0 || strlen(result) == 0) {
		engine_status = 0;
		enable = 0;
	} else {
		enable = atoi(result);
		engine_status = 1;
	}

	json_object_object_add(data_obj, "enable", json_object_new_int(enable));
	json_object_object_add(data_obj, "version",
			       json_object_new_string(OAF_VERSION));
	json_object_object_add(data_obj, "engine_status",
			       json_object_new_int(engine_status));

	uci_ctx = uci_alloc_context();
	if (uci_ctx) {
		int disable_hnat = af_uci_get_int_value(uci_ctx,
							"appfilter.global.disable_hnat");

		json_object_object_add(data_obj, "disable_hnat",
				       json_object_new_int(disable_hnat));
		uci_free_context(uci_ctx);
	} else {
		json_object_object_add(data_obj, "disable_hnat",
				       json_object_new_int(0));
	}

	ret = exec_with_result_line("cat /proc/sys/oaf/version", kernel_version,
				    sizeof(kernel_version));
	if (ret >= 0)
		json_object_object_add(data_obj, "engine_version",
				       json_object_new_string(kernel_version));
	else
		json_object_object_add(data_obj, "engine_version",
				       json_object_new_string(""));

	ret = exec_with_result_line("uname -r", kernel_version,
				    sizeof(kernel_version));
	if (ret >= 0)
		json_object_object_add(data_obj, "kernel_version",
				       json_object_new_string(kernel_version));
	else
		json_object_object_add(data_obj, "kernel_version",
				       json_object_new_string(""));

	json_object_object_add(data_obj, "config_enable",
			       json_object_new_int(g_af_config.global.enable));
	json_object_object_add(data_obj, "time_mode",
			       json_object_new_int(g_af_config.time.time_mode));
	json_object_object_add(data_obj, "match_time",
			       json_object_new_int(g_af_status.match_time));

	if (g_af_config.time.time_mode == 1) {
		json_object_object_add(data_obj, "filter",
				       json_object_new_int(g_af_status.filter));
		if (g_af_status.filter == 1)
			json_object_object_add(data_obj, "remain_time",
					       json_object_new_int(g_af_config.time.deny_time -
								   g_af_status.deny_time));
		else
			json_object_object_add(data_obj, "remain_time",
					       json_object_new_int(g_af_config.time.allow_time -
								   g_af_status.allow_time));
	} else if (g_af_config.time.time_mode == 2) {
		now = time(NULL);
		current_time = localtime(&now);
		add_daily_limit_status(data_obj, current_time);
	}

	json_object_object_add(response, "data", data_obj);
	reply_json(ctx, req, response);
	json_object_put(response);
	return 0;
}

/* -------------------------------------------------------------------------
 * service_config
 * ---------------------------------------------------------------------- */

static int handle_service_config(struct ubus_context *ctx,
				 struct ubus_object *obj,
				 struct ubus_request_data *req,
				 const char *method,
				 struct blob_attr *msg)
{
	struct json_object *req_obj, *agent_obj;
	char *s = blobmsg_format_json(msg, true);

	if (!s)
		return 0;

	req_obj = json_tokener_parse(s);
	if (!req_obj) {
		printf("parse json failed\n");
		free(s);
		return 0;
	}

	agent_obj = json_object_object_get(req_obj, "agent_enable");
	if (!agent_obj) {
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	g_enable_agent = json_object_get_int(agent_obj);
	printf("g_enable_agent: %d\n", g_enable_agent);

	json_object_put(req_obj);
	free(s);
	return reply_code(ctx, req, 0);
}

/* -------------------------------------------------------------------------
 * cmd
 * ---------------------------------------------------------------------- */

static int handle_cmd(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct json_object *response = json_object_new_object();
	struct json_object *req_obj, *action_obj;
	const char *result_msg = NULL;
	const char *action;
	char *s = blobmsg_format_json(msg, true);
	int ret = 0;

	if (!s)
		return 0;

	printf("handle_cmd: msg_obj_str: %s\n", s);
	req_obj = json_tokener_parse(s);
	if (!req_obj) {
		printf("parse json failed\n");
		free(s);
		return 0;
	}

	action_obj = json_object_object_get(req_obj, "action");
	if (!action_obj) {
		printf("action is NULL\n");
		json_object_put(req_obj);
		free(s);
		return 0;
	}

	action = json_object_get_string(action_obj);
	printf("handle_cmd: action = %s\n", action);

	if (!strcmp(action, "clear_active_time")) {
		reset_all_users_today_active_time();
		result_msg = "Successfully cleared all users' active time";
		g_oaf_config_change = 1;
		printf("handle_cmd: cleared all users' active time\n");
	} else if (!strcmp(action, "clear_user_active_time")) {
		struct json_object *mac_obj =
			json_object_object_get(req_obj, "mac");

		if (!mac_obj) {
			result_msg = "Missing mac parameter";
			ret = -1;
			printf("handle_cmd: clear_user_active_time requires mac\n");
		} else {
			const char *mac = json_object_get_string(mac_obj);

			reset_user_today_active_time(mac);
			result_msg = "Successfully cleared user active time";
			g_oaf_config_change = 1;
			printf("handle_cmd: cleared active time for mac=%s\n",
			       mac);
		}
	} else if (!strcmp(action, "clear_offline_users")) {
		flush_offline_users();
		result_msg = "Successfully cleared all offline users";
		printf("handle_cmd: cleared all offline users\n");
	} else {
		result_msg = "Unknown action";
		ret = -1;
		printf("handle_cmd: unknown action: %s\n", action);
	}

	json_object_object_add(response, "code", json_object_new_int(ret));
	json_object_object_add(response, "message",
			       json_object_new_string(result_msg));
	reply_json(ctx, req, response);

	json_object_put(req_obj);
	free(s);
	json_object_put(response);
	return 0;
}

/* -------------------------------------------------------------------------
 * Object registration
 * ---------------------------------------------------------------------- */

static struct ubus_method appfilter_object_methods[] = {
	UBUS_METHOD("dev_visit_list", appfilter_handle_dev_visit_list, empty_policy),
	UBUS_METHOD("dev_visit_time", appfilter_handle_visit_time, empty_policy),
	UBUS_METHOD("app_class_visit_time", handle_app_class_visit_time, empty_policy),
	UBUS_METHOD("dev_list", appfilter_handle_dev_list, empty_policy),
	UBUS_METHOD("class_list", handle_get_class_list, empty_policy),
	UBUS_METHOD("set_app_filter", handle_set_app_filter, empty_policy),
	UBUS_METHOD("get_app_filter", handle_get_app_filter, empty_policy),
	UBUS_METHOD("set_app_filter_base", handle_set_app_filter_base, empty_policy),
	UBUS_METHOD("get_app_filter_base", handle_get_app_filter_base, empty_policy),
	UBUS_METHOD("set_app_filter_adv", handle_set_app_filter_adv, empty_policy),
	UBUS_METHOD("get_app_filter_adv", handle_get_app_filter_adv, empty_policy),
	UBUS_METHOD("set_app_filter_time", handle_set_app_filter_time, empty_policy),
	UBUS_METHOD("get_app_filter_time", handle_get_app_filter_time, empty_policy),
	UBUS_METHOD("get_all_users", handle_get_all_users, empty_policy),
	UBUS_METHOD("get_app_filter_user", handle_get_app_filter_user, empty_policy),
	UBUS_METHOD("set_app_filter_user", handle_set_app_filter_user, empty_policy),
	UBUS_METHOD("del_app_filter_user", handle_del_app_filter_user, empty_policy),
	UBUS_METHOD("add_app_filter_user", handle_add_app_filter_user, empty_policy),
	UBUS_METHOD("set_nickname", handle_set_nickname, empty_policy),
	UBUS_METHOD("get_oaf_status", handle_get_oaf_status, empty_policy),
	UBUS_METHOD("debug", handle_debug, empty_policy),
	UBUS_METHOD("get_whitelist_user", handle_get_whitelist_user, empty_policy),
	UBUS_METHOD("add_whitelist_user", handle_add_whitelist_user, empty_policy),
	UBUS_METHOD("del_whitelist_user", handle_del_whitelist_user, empty_policy),
	UBUS_METHOD("service_config", handle_service_config, empty_policy),
	UBUS_METHOD("cmd", handle_cmd, empty_policy),
};

static struct ubus_object_type main_object_type =
	UBUS_OBJECT_TYPE("appfilter", appfilter_object_methods);

static struct ubus_object main_object = {
	.name = "appfilter",
	.type = &main_object_type,
	.methods = appfilter_object_methods,
	.n_methods = ARRAY_SIZE(appfilter_object_methods),
};

int appfilter_ubus_init(void)
{
	ubus_ctx = ubus_connect("/var/run/ubus/ubus.sock");
	if (!ubus_ctx)
		ubus_ctx = ubus_connect(NULL);
	if (!ubus_ctx)
		return -EIO;

	ubus_add_object(ubus_ctx, &main_object);
	ubus_add_uloop(ubus_ctx);
	return 0;
}
