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
#include <time.h>
#include <unistd.h>

#include <json-c/json.h>
#include <libubox/utils.h>
#include <libubus.h>

#include "appfilter.h"
#include "appfilter_config.h"
#include "appfilter_user.h"

#define DEV_OFFLINE_TIME	(SECONDS_PER_DAY * 7)

#define MAX_RECORD_TIME		(1 * 24 * 60 * 60)
#define RECORD_REMAIN_TIME	(60 * 60)
#define INVALID_RECORD_TIME	(5 * 60)

dev_node_t *dev_hash_table[MAX_DEV_NODE_HASH_SIZE];

void mac_copy_lower(char *dst, const char *src, size_t dst_len)
{
	size_t i = 0;

	if (!dst || !src || dst_len == 0)
		return;

	while (i + 1 < dst_len && src[i]) {
		char c = src[i];

		if (c >= 'A' && c <= 'Z')
			c = (char)(c + ('a' - 'A'));
		dst[i] = c;
		i++;
	}
	dst[i] = '\0';
}

static unsigned int hash_mac(const char *mac)
{
	unsigned int hash = 0;
	int i;

	if (!mac)
		return 0;

	for (i = 0; mac[i] && i < MAX_MAC_LEN; i++) {
		unsigned char c = mac[i];

		if (c >= 'A' && c <= 'Z')
			c = (unsigned char)(c + ('a' - 'A'));
		hash = hash * 31 + c;
	}
	return hash & (MAX_DEV_NODE_HASH_SIZE - 1);
}

void add_visit_info_node(visit_info_t **head, visit_info_t *node)
{
	if (!*head) {
		*head = node;
	} else {
		node->next = *head;
		*head = node;
	}
}

void init_dev_node_htable(void)
{
	int i;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++)
		dev_hash_table[i] = NULL;
	printf("init dev node htable ok...\n");
}

dev_node_t *add_dev_node(char *mac)
{
	unsigned int hash;
	dev_node_t *node;

	if (!mac)
		return NULL;

	hash = hash_mac(mac);
	node = calloc(1, sizeof(*node));
	if (!node)
		return NULL;
	mac_copy_lower(node->mac, mac, sizeof(node->mac));
	node->online_time = get_timestamp();
	node->offline_time = get_timestamp();

	node->next = dev_hash_table[hash];
	dev_hash_table[hash] = node;
	printf("add mac:%s to htable[%u]....success\n", node->mac, hash);
	return node;
}

dev_node_t *find_dev_node(char *mac)
{
	unsigned int hash;
	dev_node_t *p;

	if (!mac)
		return NULL;

	hash = hash_mac(mac);
	p = dev_hash_table[hash];
	while (p) {
		if (!strcasecmp(p->mac, mac))
			return p;
		p = p->next;
	}
	return NULL;
}

void dev_foreach(void *arg, iter_func iter)
{
	int i;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			iter(arg, node);
			node = node->next;
		}
	}
}

static bool is_target_interface(const char *device, const char *target_iface, const char *user_iface)
{
	if (strstr(device, "wan") || strstr(device, "pppoe")) {
		return false;
	}

	if (strcmp(device, target_iface) == 0 || strcmp(device, user_iface) == 0) {
		return true;
	}

	size_t len = strlen(user_iface);
	if (strncmp(device, user_iface, len) == 0) {
		char next_char = device[len];
		if (next_char == '\0' || next_char == '.') {
			return true;
		}
	}

	return false;
}

static void update_node_from_json(const char *mac_key, struct json_object *val)
{
	dev_node_t *node = find_dev_node((char *)mac_key);
	if (!node) {
		node = add_dev_node((char *)mac_key);
		if (!node) return;
		node->online = 0;
		node->offline_time = get_timestamp();
	}

	struct json_object *name_obj;
	if (json_object_object_get_ex(val, "name", &name_obj)) {
		const char *name = json_object_get_string(name_obj);
		if (name && name[0]) {
			snprintf(node->hostname, sizeof(node->hostname), "%s", name);
		}
	}

	struct json_object *ipaddrs_obj;
	if (json_object_object_get_ex(val, "ipaddrs", &ipaddrs_obj) && json_object_array_length(ipaddrs_obj) > 0) {
		const char *ip = json_object_get_string(json_object_array_get_idx(ipaddrs_obj, 0));
		if (ip && ip[0]) {
			snprintf(node->ip, sizeof(node->ip), "%s", ip);
		}
	}
}

static void update_dev_hostname(void)
{
	const char *user_iface = g_af_config.global.lan_ifname;
	if (!user_iface[0]) user_iface = "br-lan";

	char bridge_iface[64] = {0};
	char link_path[128];
	char link_target[128];

	snprintf(link_path, sizeof(link_path), "/sys/class/net/%s/brport/bridge", user_iface);
	ssize_t len = readlink(link_path, link_target, sizeof(link_target) - 1);
	const char *target_iface = user_iface;
	if (len > 0) {
		link_target[len] = '\0';
		const char *basename = strrchr(link_target, '/');
		if (basename && *(basename + 1)) {
			snprintf(bridge_iface, sizeof(bridge_iface), "%s", basename + 1);
			target_iface = bridge_iface;
		}
	}

	char local_mac[32] = {0};
	snprintf(link_path, sizeof(link_path), "/sys/class/net/%s/address", target_iface);
	FILE *fp = fopen(link_path, "r");
	if (fp) {
		if (fgets(local_mac, sizeof(local_mac), fp)) {
			local_mac[strcspn(local_mac, "\r\n")] = '\0'; 
		}
		fclose(fp);
	}

	char valid_macs[128][32];
	int valid_count = 0;
	fp = fopen("/proc/net/arp", "r");
	if (fp) {
		char line[256];
		fgets(line, sizeof(line), fp);
		while (valid_count < 128 && fgets(line, sizeof(line), fp)) {
			char ip[32], mac[32], device[32];
			unsigned int flags;
			if (sscanf(line, "%31s %*s %x %31s %*s %31s", ip, &flags, mac, device) == 4) {
				if (local_mac[0] && strcasecmp(mac, local_mac) == 0) {
					continue;
				}
				if (is_target_interface(device, target_iface, user_iface)) {
					snprintf(valid_macs[valid_count++], 32, "%s", mac);
				}
			}
		}
		fclose(fp);
	}

	if (valid_count == 0) return;

	fp = popen("ubus call luci-rpc getHostHints", "r");
	if (!fp) {
		LOG_WARN("exec ubus getHostHints failed\n");
		return;
	}

	char buf[16384] = {0};
	size_t read_bytes = fread(buf, 1, sizeof(buf) - 1, fp);
	pclose(fp);

	if (read_bytes == 0) return;

	struct json_object *root = json_tokener_parse(buf);
	if (!root) {
		LOG_WARN("parse getHostHints json failed\n");
		return;
	}

	json_object_object_foreach(root, mac_key, val) {
		for (int i = 0; i < valid_count; i++) {
			if (strcasecmp(mac_key, valid_macs[i]) == 0) {
				update_node_from_json(mac_key, val);
				break;
			}
		}
	}
	json_object_put(root);
}

static void clean_dev_nickname_iter(void *arg, dev_node_t *node)
{
	node->nickname[0] = '\0';
}

void update_dev_nickname(void)
{
	char nickname[128], mac[128];
	struct uci_context *ctx;
	int num, i;

	ctx = uci_alloc_context();
	if (!ctx) {
		LOG_ERROR("uci_alloc_context failed\n");
		return;
	}

	dev_foreach(NULL, clean_dev_nickname_iter);
	num = af_get_uci_list_num(ctx, "user_info", "user_info");
	for (i = 0; i < num; i++) {
		dev_node_t *node;

		af_uci_get_array_value(ctx, "user_info.@user_info[%d].mac", i,
				       mac, sizeof(mac));
		node = find_dev_node(mac);
		if (!node)
			continue;
		af_uci_get_array_value(ctx, "user_info.@user_info[%d].nickname", i,
				       nickname, sizeof(nickname));
		strncpy(node->nickname, nickname, sizeof(node->nickname));
	}
	uci_free_context(ctx);
}

static void clean_dev_whitelist_iter(void *arg, dev_node_t *node)
{
	node->is_whitelist = 0;
}

void update_dev_whitelist_flag(void)
{
	struct uci_context *ctx;
	char mac[128];
	int num, i;

	dev_foreach(NULL, clean_dev_whitelist_iter);

	ctx = uci_alloc_context();
	if (!ctx)
		return;
	num = af_get_uci_list_num(ctx, "appfilter", "whitelist");
	for (i = 0; i < num; i++) {
		dev_node_t *node;

		af_uci_get_array_value(ctx, "appfilter.@whitelist[%d].mac", i,
				       mac, sizeof(mac));
		node = find_dev_node(mac);
		if (node)
			node->is_whitelist = 1;
	}
	uci_free_context(ctx);
}

static void clean_dev_selected_iter(void *arg, dev_node_t *node)
{
	node->is_selected = 0;
}

void update_dev_selected_flag(void)
{
	int user_mode = g_af_config.global.user_mode;

	dev_foreach(NULL, clean_dev_selected_iter);

	if (user_mode == 0) {
		int i;

		for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
			dev_node_t *node = dev_hash_table[i];

			while (node) {
				if (!node->is_whitelist)
					node->is_selected = 1;
				node = node->next;
			}
		}
		LOG_DEBUG("Auto mode: all users except whitelist are selected\n");
	} else {
		struct uci_context *ctx;
		char mac[128];
		int num, i;
		time_t now = time(NULL);
		struct tm *tm = localtime(&now);
		int cur_min = tm->tm_hour * 60 + tm->tm_min;

		ctx = uci_alloc_context();
		if (!ctx) {
			LOG_ERROR("uci_alloc_context failed\n");
			return;
		}
		num = af_get_uci_list_num(ctx, "appfilter", "af_user");
		for (i = 0; i < num; i++) {
			char start[16], end[16], key[128];
			dev_node_t *node;
			int in_time = 1;

			af_uci_get_array_value(ctx, "appfilter.@af_user[%d].mac", i, mac, sizeof(mac));
			node = find_dev_node(mac);
			if (!node) {
				node = add_dev_node(mac);
				if (!node) continue;
				node->online = 0;
			}

			memset(start, 0, sizeof(start));
			memset(end, 0, sizeof(end));
			snprintf(key, sizeof(key),
				 "appfilter.@af_user[%d].time_start", i);
			af_uci_get_value(ctx, key, start, sizeof(start));
			snprintf(key, sizeof(key),
				 "appfilter.@af_user[%d].time_end", i);
			af_uci_get_value(ctx, key, end, sizeof(end));

			if (start[0] && end[0]) {
				int sh = 0, sm = 0, eh = 23, em = 59;
				int s_min, e_min;

				sscanf(start, "%d:%d", &sh, &sm);
				sscanf(end, "%d:%d", &eh, &em);
				s_min = sh * 60 + sm;
				e_min = eh * 60 + em;

				if (s_min <= e_min)
					in_time = (cur_min >= s_min && cur_min <= e_min);
				else
					in_time = (cur_min >= s_min || cur_min <= e_min);

				LOG_INFO("[Time Check] %s | now=%02d:%02d | rule=%s-%s | match=%d\n",
					 node->mac, tm->tm_hour, tm->tm_min,
					 start, end, in_time);
			}

			if (in_time) {
				node->is_selected = 1;
			} else {
				node->is_selected = 0;
				node->blocked = 0;
				LOG_DEBUG("Time rule: mac=%s unselected\n",
					  node->mac);
			}
		}
		uci_free_context(ctx);
		LOG_DEBUG("Manual mode: %d users\n", num);
	}
}

static void clean_dev_online_status(void)
{
	int i;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			if (node->online) {
				node->offline_time = get_timestamp();
				node->online = 0;
			}
			node = node->next;
		}
	}
}

static void update_dev_from_kernel(void)
{
	char line[256];
	FILE *fp;

	fp = fopen("/proc/net/af_client", "r");
	if (!fp) {
		printf("open client file....failed\n");
		return;
	}

	fgets(line, sizeof(line), fp);
	while (fgets(line, sizeof(line), fp)) {
		char mac[32], ip[32], ipv6[128];
		unsigned int up_rate = 0, down_rate = 0;
		int id, parsed;
		dev_node_t *node;

		parsed = sscanf(line, "%d %31s %31s %127s %u %u",
				&id, mac, ip, ipv6, &up_rate, &down_rate);
		if (parsed < 3) {
			printf("invalid line format:%s\n", line);
			continue;
		}
		if (strlen(mac) < 17) {
			printf("invalid mac:%s\n", mac);
			continue;
		}

		node = find_dev_node(mac);
		if (!node) {
			node = add_dev_node(mac);
			if (!node)
				continue;
			strncpy(node->ip, ip, sizeof(node->ip));
		}
		strncpy(node->ip, ip, sizeof(node->ip));

		if (parsed >= 4 && ipv6[0])
			strncpy(node->ipv6, ipv6, sizeof(node->ipv6));
		else
			node->ipv6[0] = '\0';

		node->up_rate = (parsed >= 5) ? up_rate : 0;
		node->down_rate = (parsed >= 6) ? down_rate : 0;
		node->online = 1;
	}
	fclose(fp);
}

void update_dev_online_status(void)
{
	update_dev_from_kernel();
}

int check_dev_expire(void)
{
	int i, j;
	int cur = get_timestamp();
	int expire_count = 0;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			if (node->online)
				goto next;

			if (cur - node->offline_time > DEV_OFFLINE_TIME) {
				int vc = 0;

				node->expire = 1;
				for (j = 0; j < MAX_VISIT_HASH_SIZE; j++) {
					visit_info_t *v = node->visit_htable[j];

					while (v) {
						v->expire = 1;
						vc++;
						v = v->next;
					}
				}
				expire_count++;
				LOG_WARN("dev:%s expired, offline=%ds, visit=%d\n",
					 node->mac,
					 cur - node->offline_time, vc);
			}
next:
			node = node->next;
		}
	}
	return expire_count;
}

void flush_dev_expire_node(void)
{
	int i, j;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i], *prev = NULL;

		while (node) {
			if (node->expire) {
				dev_node_t *expired = node;

				for (j = 0; j < MAX_VISIT_HASH_SIZE; j++) {
					visit_info_t *v = expired->visit_htable[j];

					while (v) {
						visit_info_t *next = v->next;

						free(v);
						v = next;
					}
				}

				if (!prev) {
					dev_hash_table[i] = expired->next;
					node = dev_hash_table[i];
				} else {
					prev->next = expired->next;
					node = prev->next;
				}
				free(expired);
			} else {
				prev = node;
				node = node->next;
			}
		}
	}
}

void flush_offline_users(void)
{
	int i, j;
	int count = 0;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i], *prev = NULL;

		while (node) {
			if (!node->online) {
				for (j = 0; j < MAX_VISIT_HASH_SIZE; j++) {
					visit_info_t *v = node->visit_htable[j];

					while (v) {
						visit_info_t *next = v->next;

						free(v);
						v = next;
					}
				}

				if (!prev) {
					dev_hash_table[i] = node->next;
					free(node);
					node = dev_hash_table[i];
				} else {
					prev->next = node->next;
					free(node);
					node = prev->next;
				}
				count++;
			} else {
				prev = node;
				node = node->next;
			}
		}
	}
	LOG_WARN("Cleared %d offline users\n", count);
}

void save_user_time_to_file(void)
{
	FILE *fp = fopen(OAF_USER_FILE, "w");
	time_t now;
	struct tm *tm;
	int i, count = 0;

	if (!fp) {
		LOG_ERROR("Failed to open %s\n", OAF_USER_FILE);
		return;
	}

	now = time(NULL);
	tm = localtime(&now);
	fprintf(fp, "#%04d-%02d-%02d\n",
		tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			fprintf(fp, "%s,%u,%u\n", node->mac,
				node->today_am_active_time,
				node->today_pm_active_time);
			count++;
			node = node->next;
		}
	}
	fclose(fp);
	LOG_DEBUG("Saved %d users\n", count);
}

void load_user_time_from_file(void)
{
	char line[256];
	FILE *fp = fopen(OAF_USER_FILE, "r");
	int fy = 0, fmon = 0, fday = 0;
	time_t now;
	struct tm *tm;
	int count = 0;

	if (!fp) {
		LOG_DEBUG("No %s, starting fresh\n", OAF_USER_FILE);
		return;
	}

	if (!fgets(line, sizeof(line), fp)) {
		fclose(fp);
		return;
	}
	if (sscanf(line, "#%d-%d-%d", &fy, &fmon, &fday) != 3) {
		LOG_INFO("no date header, skip\n");
		fclose(fp);
		return;
	}

	now = time(NULL);
	tm = localtime(&now);
	if (fy != tm->tm_year + 1900 || fmon != tm->tm_mon + 1 ||
	    fday != tm->tm_mday) {
		LOG_INFO("stale user_list.dat, skip\n");
		fclose(fp);
		return;
	}

	while (fgets(line, sizeof(line), fp)) {
		char mac[32];
		unsigned int am, pm;
		dev_node_t *node;

		if (sscanf(line, "%31[^,],%u,%u", mac, &am, &pm) != 3) {
			LOG_WARN("bad line: %s\n", line);
			continue;
		}
		node = find_dev_node(mac);
		if (!node) {
			node = add_dev_node(mac);
			if (!node) {
				LOG_WARN("cannot create node for %s\n", mac);
				continue;
			}
		}
		node->today_am_active_time = am;
		node->today_pm_active_time = pm;
		count++;
	}
	fclose(fp);
	LOG_INFO("Loaded %d users from %s\n", count, OAF_USER_FILE);
}

void update_dev_visiting_info(void)
{
	char line[256];
	FILE *fp;

	fp = fopen("/proc/net/af_visit", "r");
	if (!fp) {
		printf("open af_visit file....failed\n");
		return;
	}

	fgets(line, sizeof(line), fp);
	while (fgets(line, sizeof(line), fp)) {
		char mac[32], url[32], app[32];
		dev_node_t *node;

		if (sscanf(line, "%31s %31s %31s", mac, app, url) != 3)
			continue;
		node = find_dev_node(mac);
		if (!node)
			continue;
		if (!strcmp(url, "none"))
			node->visiting_url[0] = '\0';
		else
			strncpy(node->visiting_url, url,
				sizeof(node->visiting_url));
		node->visiting_app = atoi(app);
	}
	fclose(fp);
}

void update_dev_custom_time(void)
{
	struct uci_context *ctx = uci_alloc_context();
	if (!ctx) return;

	int num = af_get_uci_list_num(ctx, "appfilter", "device_time");
	for (int i = 0; i < num; i++) {
		char mac[32] = {0};
		char time_cfg[1024] = {0};
		af_uci_get_array_value(ctx, "appfilter.@device_time[%d].mac", i, mac, sizeof(mac));
		af_uci_get_array_value(ctx, "appfilter.@device_time[%d].data", i, time_cfg, sizeof(time_cfg));

		dev_node_t *node = find_dev_node(mac);
		if (!node) {
			node = add_dev_node(mac);
			if (node) node->online = 0;
		}
		if (node) {
			strncpy(node->custom_time_json, time_cfg, sizeof(node->custom_time_json) - 1);
		}
	}
	uci_free_context(ctx);
}

void update_dev_list(void)
{
	clean_dev_online_status();
	update_dev_hostname();
	update_dev_nickname();
	update_dev_online_status();
	update_dev_visiting_info();
	update_dev_selected_flag();
	update_dev_custom_time();
}


void check_dev_visit_info_expire(void)
{
	int i, j;
	int cur = get_timestamp();

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			for (j = 0; j < MAX_VISIT_HASH_SIZE; j++) {
				visit_info_t *v = node->visit_htable[j];

				while (v) {
					int total = v->latest_time - v->first_time;
					int span = cur - v->first_time;

					if (span > MAX_RECORD_TIME || span < 0)
						v->expire = 1;
					else if (span > RECORD_REMAIN_TIME &&
						 total < INVALID_RECORD_TIME)
						v->expire = 1;

					LOG_DEBUG("[%s] appid=%d total=%ds span=%ds expire=%d\n",
						  node->mac, v->appid, total, span,
						  v->expire);
					v = v->next;
				}
			}
			node = node->next;
		}
	}
}

void flush_expire_visit_info(void)
{
	int i, j;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			for (j = 0; j < MAX_VISIT_HASH_SIZE; j++) {
				visit_info_t *v = node->visit_htable[j], *prev = NULL;

				while (v) {
					if (v->expire) {
						if (!prev) {
							node->visit_htable[j] = v->next;
							free(v);
							v = node->visit_htable[j];
						} else {
							prev->next = v->next;
							free(v);
							v = prev->next;
						}
					} else {
						prev = v;
						v = v->next;
					}
				}
			}
			node = node->next;
		}
	}
}

void dump_dev_list(void)
{
	int i;
	FILE *fp = fopen(OAF_DEV_LIST_FILE, "w");

	if (!fp)
		return;
	fprintf(fp, "%-4s %-20s %-20s %-32s %-8s\n",
		"Id", "Mac Addr", "Ip Addr", "Hostname", "Online");
	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			if (node->online)
				fprintf(fp, "%-4d %-20s %-20s %-32s %-8d\n",
					i + 1, node->mac,
					node->ip[0] ? node->ip : "*",
					node->hostname[0] ? node->hostname : "*",
					node->online);
			node = node->next;
		}
	}
	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			if (!node->online)
				fprintf(fp, "%-4d %-20s %-20s %-32s %-8d\n",
					i + 1, node->mac,
					node->ip[0] ? node->ip : "*",
					node->hostname[0] ? node->hostname : "*",
					node->online);
			node = node->next;
		}
	}
	fclose(fp);
}

void clean_invalid_app_records(void)
{
	int i, j;
	int invalid = 0;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			for (j = 0; j < MAX_VISIT_HASH_SIZE; j++) {
				visit_info_t *v = node->visit_htable[j];

				while (v) {
					if (!strlen(get_app_name_by_id(v->appid))) {
						v->expire = 1;
						invalid++;
						LOG_DEBUG("clean: MAC=%s AppID=%d\n",
							  node->mac, v->appid);
					}
					v = v->next;
				}
			}
			node = node->next;
		}
	}
	if (invalid)
		flush_expire_visit_info();
}

void clear_device_app_statistics(void)
{
	int i;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			memset(node->stat, 0, sizeof(node->stat));
			node = node->next;
		}
	}
}

void reset_all_users_today_active_time(void)
{
	int i;
	unsigned int now = get_timestamp();

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			LOG_DEBUG("Reset today time %s: am=%d->0 pm=%d->0\n",
				  node->mac, node->today_am_active_time,
				  node->today_pm_active_time);
			node->today_am_active_time = 0;
			node->today_pm_active_time = 0;
			node->last_up_bytes = node->today_up_bytes;
			node->last_down_bytes = node->today_down_bytes;
			memset(&node->time_status, 0, sizeof(node->time_status));
			node->last_check_sec = now;
			node = node->next;
		}
	}
	g_af_status.period_blocked = 0;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			node->blocked = 0;
			node = node->next;
		}
	}
	sync_blocked_macs_to_kernel();
}

void reset_user_today_active_time(const char *mac)
{
	dev_node_t *node;

	if (!mac || !mac[0])
		return;
	node = find_dev_node((char *)mac);
	if (!node) {
		LOG_WARN("reset: mac %s not found\n", mac);
		return;
	}
	LOG_DEBUG("Reset user: mac=%s am=%d->0 pm=%d->0\n",
		  node->mac, node->today_am_active_time,
		  node->today_pm_active_time);
	node->today_am_active_time = 0;
	node->today_pm_active_time = 0;
	node->blocked = 0;
	memset(&node->time_status, 0, sizeof(node->time_status));
	node->last_check_sec = get_timestamp();
	sync_blocked_macs_to_kernel();
}

void reset_all_users_today_flow(void)
{
	int i;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			node->today_down_bytes = 0;
			node->today_up_bytes = 0;
			node->last_up_bytes = 0;
			node->last_down_bytes = 0;
			node = node->next;
		}
	}
}

void check_all_users_period_time(void)
{
	unsigned int now = get_timestamp();
	struct tm *tm;
	int i;
	time_t t = now;

	tm = localtime(&t);
	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			int sec_diff;
			int minutes;
			int active;

			if (node->last_check_sec == 0) {
				node->last_check_sec = now;
				node->last_up_bytes = node->today_up_bytes;
				node->last_down_bytes = node->today_down_bytes;
				node = node->next;
				continue;
			}

			sec_diff = (int)(now - node->last_check_sec);
			if (sec_diff < 0) {
				node->last_check_sec = now;
				node->last_up_bytes = node->today_up_bytes;
				node->last_down_bytes = node->today_down_bytes;
				node = node->next;
				continue;
			}

			minutes = sec_diff / 60;
			if (minutes > 0) {
				active = (node->today_up_bytes > node->last_up_bytes) ||
					 (node->today_down_bytes > node->last_down_bytes);

				node->last_up_bytes = node->today_up_bytes;
				node->last_down_bytes = node->today_down_bytes;

				if (node->online && node->is_selected &&
				    (active || node->active)) {
					if (tm->tm_hour < 12)
						node->today_am_active_time += minutes;
					else
						node->today_pm_active_time += minutes;
					LOG_DEBUG("period_time %s elapsed=%d am=%u pm=%u\n",
						  node->mac, minutes,
						  node->today_am_active_time,
						  node->today_pm_active_time);
				}

				node->last_check_sec += minutes * 60;
			}
			node = node->next;
		}
	}
}
