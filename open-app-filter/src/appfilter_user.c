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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <json-c/json.h>
#include <linux/socket.h>
#include <sys/socket.h>
#include "appfilter_config.h"
#include "appfilter.h"
#include "appfilter_user.h"

dev_node_t *dev_hash_table[MAX_DEV_NODE_HASH_SIZE];
int g_cur_user_num = 0;

void mac_copy_lower(char *dst, const char *src, size_t dst_len)
{
	size_t i = 0;

	if (!dst || !src || dst_len == 0)
		return;

	while (i + 1 < dst_len && src[i] != '\0') {
		char c = src[i];

		if (c >= 'A' && c <= 'Z')
			c = (char)(c + ('a' - 'A'));
		dst[i] = c;
		i++;
	}
	dst[i] = '\0';
}

unsigned int hash_mac(unsigned char *mac)
{
	unsigned int hash = 0;
	int i;

	if (!mac) {
		return 0;
	}
	for (i = 0; mac[i] != '\0' && i < MAX_MAC_LEN; i++) {
		unsigned char c = mac[i];

		if (c >= 'A' && c <= 'Z')
			c = (unsigned char)(c + ('a' - 'A'));
		hash = hash * 31 + c;
	}
	return hash & (MAX_DEV_NODE_HASH_SIZE - 1);
}

int hash_appid(int appid)
{
	return appid & (MAX_VISIT_HASH_SIZE - 1);
}

void add_visit_info_node(visit_info_t **head, visit_info_t *node)
{
	if (*head == NULL) {
		*head = node;
	} else {
		node->next = *head;
		*head = node;
	}
}

void init_dev_node_htable()
{
	int i;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++)
		dev_hash_table[i] = NULL;
	printf("init dev node htable ok...\n");
}

dev_node_t *add_dev_node(char *mac)
{
	unsigned int hash = 0;
	dev_node_t *node;

	hash = hash_mac(mac);
	if (hash >= MAX_DEV_NODE_HASH_SIZE) {
		printf("hash code error %d\n", hash);
		return NULL;
	}
	node = (dev_node_t *)calloc(1, sizeof(dev_node_t));
	if (!node)
		return NULL;
	mac_copy_lower(node->mac, mac, sizeof(node->mac));
	node->online = 0;
	node->online_time = get_timestamp();
	node->offline_time = get_timestamp();
	if (dev_hash_table[hash] == NULL) {
		dev_hash_table[hash] = node;
	} else {
		node->next = dev_hash_table[hash];
		dev_hash_table[hash] = node;
	}
	g_cur_user_num++;
	printf("add mac:%s to htable[%d]....success\n", node->mac, hash);
	return node;
}

dev_node_t *find_dev_node(char *mac)
{
	unsigned int hash = 0;
	dev_node_t *p = NULL;

	hash = hash_mac(mac);
	if (hash >= MAX_DEV_NODE_HASH_SIZE) {
		printf("hash code error %d\n", hash);
		return NULL;
	}
	p = dev_hash_table[hash];
	while (p) {
		if (0 == strcasecmp(p->mac, mac))
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

char *format_time(int timetamp)
{
	char time_buf[64] = {0};
	time_t seconds = timetamp;
	struct tm *auth_tm = localtime(&seconds);

	strftime(time_buf, sizeof(time_buf), "%Y %m %d %H:%M:%S", auth_tm);
	return strdup(time_buf);
}

void update_dev_hostname(void)
{
	char line_buf[256] = {0};
	char hostname_buf[128] = {0};
	char mac_buf[32] = {0};
	char ip_buf[32] = {0};
	FILE *fp;

	fp = fopen("/tmp/dhcp.leases", "r");
	if (!fp) {
		printf("open dhcp lease file....failed\n");
		return;
	}
	while (fgets(line_buf, sizeof(line_buf), fp)) {
		dev_node_t *node;

		if (strlen(line_buf) <= 16)
			continue;
		sscanf(line_buf, "%*s %31s %31s %127s", mac_buf, ip_buf, hostname_buf);
		node = find_dev_node(mac_buf);
		if (!node) {
			node = add_dev_node(mac_buf);
			if (!node)
				continue;
			strncpy(node->ip, ip_buf, sizeof(node->ip));
			node->online = 0;
			node->offline_time = get_timestamp();
		}

		if (strlen(hostname_buf) > 0 && hostname_buf[0] != '*')
			strncpy(node->hostname, hostname_buf, sizeof(node->hostname));
	}
	fclose(fp);
}

void clean_dev_nickname_iter(void *arg, dev_node_t *node)
{
	node->nickname[0] = '\0';
}

void clean_dev_nickname(void)
{
	dev_foreach(NULL, clean_dev_nickname_iter);
}

void update_dev_nickname(void)
{
	char nickname_buf[128] = {0};
	char mac_str[128] = {0};
	struct uci_context *uci_ctx = uci_alloc_context();
	int num;
	int i;

	if (!uci_ctx) {
		LOG_ERROR("uci_alloc_context failed in update_dev_nickname\n");
		return;
	}

	clean_dev_nickname();
	num = af_get_uci_list_num(uci_ctx, "user_info", "user_info");

	for (i = 0; i < num; i++) {
		dev_node_t *node;

		af_uci_get_array_value(uci_ctx, "user_info.@user_info[%d].mac", i, mac_str,
				       sizeof(mac_str));
		node = find_dev_node(mac_str);
		if (!node)
			continue;

		af_uci_get_array_value(uci_ctx, "user_info.@user_info[%d].nickname", i,
				       nickname_buf, sizeof(nickname_buf));
		strncpy(node->nickname, nickname_buf, sizeof(node->nickname));
	}
	uci_free_context(uci_ctx);
}

void clean_dev_whitelist_flag_iter(void *arg, dev_node_t *node)
{
	node->is_whitelist = 0;
}

void clean_dev_whitelist_flag(void)
{
	dev_foreach(NULL, clean_dev_whitelist_flag_iter);
}

void update_dev_whitelist_flag(void)
{
	clean_dev_whitelist_flag();

	dev_node_t *node = NULL;
	struct uci_context *uci_ctx = uci_alloc_context();
	char mac_str[128] = {0};
	int num;
	int i;

	if (!uci_ctx)
		return;
	num = af_get_uci_list_num(uci_ctx, "appfilter", "whitelist");
	for (i = 0; i < num; i++) {
		af_uci_get_array_value(uci_ctx, "appfilter.@whitelist[%d].mac", i, mac_str,
				       sizeof(mac_str));
		node = find_dev_node(mac_str);
		if (node)
			node->is_whitelist = 1;
	}
	uci_free_context(uci_ctx);
}

void clean_dev_selected_flag_iter(void *arg, dev_node_t *node)
{
	node->is_selected = 0;
}

void clean_dev_selected_flag(void)
{
	dev_foreach(NULL, clean_dev_selected_flag_iter);
}

void update_dev_selected_flag(void)
{
	extern af_config_t g_af_config;
	int user_mode = g_af_config.global.user_mode;

	clean_dev_selected_flag();

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
		struct uci_context *uci_ctx = uci_alloc_context();
		char mac_str[128] = {0};
		int num;
		int i;

		if (!uci_ctx) {
			LOG_ERROR("Failed to allocate UCI context in update_dev_selected_flag\n");
			return;
		}

		num = af_get_uci_list_num(uci_ctx, "appfilter", "af_user");
		for (i = 0; i < num; i++) {
			dev_node_t *node;

			af_uci_get_array_value(uci_ctx, "appfilter.@af_user[%d].mac", i, mac_str,
					       sizeof(mac_str));
			node = find_dev_node(mac_str);
			if (node)
				node->is_selected = 1;
		}
		uci_free_context(uci_ctx);
		LOG_DEBUG("Manual mode: %d users from af_user config are selected\n", num);
	}
}

void clean_dev_online_status(void)
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

void update_dev_from_kernel(void)
{
	char line_buf[256] = {0};
	char mac_buf[32] = {0};
	char ip_buf[32] = {0};
	char ipv6_buf[128] = {0};
	unsigned int up_rate = 0;
	unsigned int down_rate = 0;
	FILE *fp;

	fp = fopen("/proc/net/af_client", "r");
	if (!fp) {
		printf("open client file....failed\n");
		return;
	}
	fgets(line_buf, sizeof(line_buf), fp); /* title */
	while (fgets(line_buf, sizeof(line_buf), fp)) {
		int id;
		int parsed;
		dev_node_t *node;

		parsed = sscanf(line_buf, "%d %31s %31s %127s %u %u", &id, mac_buf, ip_buf,
				ipv6_buf, &up_rate, &down_rate);
		if (parsed < 3) {
			printf("invalid line format:%s\n", line_buf);
			continue;
		}
		if (strlen(mac_buf) < 17) {
			printf("invalid mac:%s\n", mac_buf);
			continue;
		}
		node = find_dev_node(mac_buf);
		if (!node) {
			node = add_dev_node(mac_buf);
			if (!node)
				continue;
			strncpy(node->ip, ip_buf, sizeof(node->ip));
		}

		strncpy(node->ip, ip_buf, sizeof(node->ip));

		if (parsed >= 4 && strlen(ipv6_buf) > 0)
			strncpy(node->ipv6, ipv6_buf, sizeof(node->ipv6));
		else
			node->ipv6[0] = '\0';

		if (parsed >= 5)
			node->up_rate = up_rate;
		else
			node->up_rate = 0;
		if (parsed >= 6)
			node->down_rate = down_rate;
		else
			node->down_rate = 0;
		node->online = 1;
	}
	fclose(fp);
}

void update_dev_online_status(void)
{
	update_dev_from_kernel();
}

#define DEV_OFFLINE_TIME	(SECONDS_PER_DAY * 7)

int check_dev_expire(void)
{
	int i, j;
	int cur_time = get_timestamp();
	int offline_time = 0;
	int expire_count = 0;
	int visit_count = 0;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			if (node->online)
				goto NEXT;
			visit_count = 0;
			offline_time = cur_time - node->offline_time;
			if (offline_time > DEV_OFFLINE_TIME) {
				node->expire = 1;
				for (j = 0; j < MAX_VISIT_HASH_SIZE; j++) {
					visit_info_t *p_info = node->visit_htable[j];

					while (p_info) {
						p_info->expire = 1;
						visit_count++;
						p_info = p_info->next;
					}
				}
				expire_count++;
				LOG_WARN("dev:%s expired, offline time = %ds, count=%d, visit_count=%d\n",
					 node->mac, offline_time, expire_count, visit_count);
			}
NEXT:
			node = node->next;
		}
	}
	return expire_count;
}

void flush_dev_expire_node(void)
{
	int i, j;
	dev_node_t *prev = NULL;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		prev = NULL;
		while (node) {
			if (node->expire) {
				dev_node_t *expired = node;

				/* Free visit records first to avoid leaking them */
				for (j = 0; j < MAX_VISIT_HASH_SIZE; j++) {
					visit_info_t *p_info = expired->visit_htable[j];

					while (p_info) {
						visit_info_t *next = p_info->next;

						free(p_info);
						p_info = next;
					}
				}

				if (NULL == prev) {
					dev_hash_table[i] = expired->next;
					free(expired);
					node = dev_hash_table[i];
					prev = NULL;
				} else {
					prev->next = expired->next;
					free(expired);
					node = prev->next;
				}
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
	dev_node_t *node = NULL;
	dev_node_t *prev = NULL;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		prev = NULL;
		while (node) {
			if (!node->online) { /* Clear all offline users */
				/* Free visit info first */
				for (j = 0; j < MAX_VISIT_HASH_SIZE; j++) {
					visit_info_t *p_info = node->visit_htable[j];

					while (p_info) {
						visit_info_t *next = p_info->next;

						free(p_info);
						p_info = next;
					}
				}

				/* Remove node from hash table */
				if (NULL == prev) {
					dev_hash_table[i] = node->next;
					free(node);
					node = dev_hash_table[i];
					prev = NULL;
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
	int i;
	int count = 0;
	FILE *fp = fopen(OAF_USER_FILE, "w");
	time_t now = time(NULL);
	struct tm *tm_info = localtime(&now);

	if (!fp) {
		LOG_ERROR("Failed to open file %s for writing\n", OAF_USER_FILE);
		return;
	}

	fprintf(fp, "#%04d-%02d-%02d\n", tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday);

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			fprintf(fp, "%s,%u,%u\n",
				node->mac,
				node->today_am_active_time,
				node->today_pm_active_time);
			count++;
			node = node->next;
		}
	}

	fclose(fp);
	LOG_DEBUG("Saved %d users' time data to %s\n", count, OAF_USER_FILE);
}

void load_user_time_from_file(void)
{
	FILE *fp = fopen(OAF_USER_FILE, "r");
	char line_buf[256] = {0};
	int count = 0;
	int file_year = 0, file_mon = 0, file_mday = 0;

	if (!fp) {
		LOG_DEBUG("File %s not found or cannot be opened, starting with empty data\n",
			  OAF_USER_FILE);
		return;
	}

	if (fgets(line_buf, sizeof(line_buf), fp) == NULL) {
		fclose(fp);
		return;
	}

	if (sscanf(line_buf, "#%d-%d-%d", &file_year, &file_mon, &file_mday) != 3) {
		LOG_INFO("user_list.dat has no date header, skipping load\n");
		fclose(fp);
		return;
	}

	time_t now = time(NULL);
	struct tm *tm_info = localtime(&now);
	if (file_year != tm_info->tm_year + 1900 || file_mon  != tm_info->tm_mon + 1 || file_mday != tm_info->tm_mday) {
		LOG_INFO("user_list.dat is from %04d-%02d-%02d, today is %04d-%02d-%02d, skipping load\n",
			 file_year, file_mon, file_mday, tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday);
		fclose(fp);
		return;
	}
	LOG_INFO("Loading today's user time data from %s\n", OAF_USER_FILE);

	while (fgets(line_buf, sizeof(line_buf), fp)) {
		char mac[32] = {0};
		unsigned int am_time = 0;
		unsigned int pm_time = 0;

		if (sscanf(line_buf, "%31[^,],%u,%u", mac, &am_time, &pm_time) == 3) {
			dev_node_t *node = find_dev_node(mac);

			if (!node) {
				/* If node doesn't exist, create a new one */
				node = add_dev_node(mac);
				if (!node) {
					LOG_WARN("Failed to create device node for MAC=%s\n", mac);
					continue;
				}
				LOG_DEBUG("Created new device node for MAC=%s\n", mac);
			}
			node->today_am_active_time = am_time;
			node->today_pm_active_time = pm_time;
			count++;
			LOG_DEBUG("Loaded user time: MAC=%s, AM=%u, PM=%u\n", mac, am_time, pm_time);
		} else {
			LOG_WARN("Failed to parse line: %s\n", line_buf);
		}
	}

	fclose(fp);
	LOG_INFO("Loaded %d users' time data from %s\n", count, OAF_USER_FILE);
}

void update_dev_visiting_info(void)
{
	char line_buf[256] = {0};
	char mac_buf[32] = {0};
	char url_buf[32] = {0};
	char app_buf[32] = {0};
	char time_buf[32] = {0};
	FILE *fp;

	fp = fopen("/proc/net/af_visit", "r");
	if (!fp) {
		printf("open af_visit file....failed\n");
		return;
	}
	fgets(line_buf, sizeof(line_buf), fp); /* title */
	while (fgets(line_buf, sizeof(line_buf), fp)) {
		dev_node_t *node;

		sscanf(line_buf, "%31s %31s %31s", mac_buf, app_buf, url_buf);
		node = find_dev_node(mac_buf);
		if (!node)
			continue;
		if (strcmp(url_buf, "none") == 0)
			node->visiting_url[0] = '\0';
		else
			strncpy(node->visiting_url, url_buf, sizeof(node->visiting_url));
		node->visiting_app = atoi(app_buf);
	}
	fclose(fp);
}

void update_dev_list(void)
{
	clean_dev_online_status();
	update_dev_hostname();
	update_dev_nickname();
	update_dev_online_status();
	update_dev_visiting_info();
	update_dev_selected_flag();
}

void dump_dev_list(void)
{
	int i, j;
	int count = 0;
	char hostname_buf[MAX_HOSTNAME_SIZE] = {0};
	char ip_buf[MAX_IP_LEN] = {0};
	FILE *fp;

	fp = fopen(OAF_DEV_LIST_FILE, "w");
	if (!fp)
		return;
	fprintf(fp, "%-4s %-20s %-20s %-32s %-8s\n", "Id", "Mac Addr", "Ip Addr",
		"Hostname", "Online");
	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			if (node->online != 0) {
				if (strlen(node->hostname) == 0)
					strcpy(hostname_buf, "*");
				else
					strcpy(hostname_buf, node->hostname);
				if (strlen(node->ip) == 0)
					strcpy(ip_buf, "*");
				else
					strcpy(ip_buf, node->ip);
				fprintf(fp, "%-4d %-20s %-20s %-32s %-8d\n",
					i + 1, node->mac, ip_buf, hostname_buf, node->online);
				count++;
			}

			node = node->next;
		}
	}
	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			if (node->online == 0) {
				if (strlen(node->hostname) == 0)
					strcpy(hostname_buf, "*");
				else
					strcpy(hostname_buf, node->hostname);

				if (strlen(node->ip) == 0)
					strcpy(ip_buf, "*");
				else
					strcpy(ip_buf, node->ip);

				fprintf(fp, "%-4d %-20s %-20s %-32s %-8d\n",
					i + 1, node->mac, ip_buf, hostname_buf, node->online);
			}

			node = node->next;
		}
	}
	fclose(fp);
}

#define MAX_RECORD_TIME		(1 * 24 * 60 * 60)	/* 1day */
#define RECORD_REMAIN_TIME	(60 * 60)		/* 1hour */
#define INVALID_RECORD_TIME	(5 * 60)		/* 5min */

void check_dev_visit_info_expire(void)
{
	int i, j;
	int count = 0;
	int cur_time = get_timestamp();

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			for (j = 0; j < MAX_VISIT_HASH_SIZE; j++) {
				visit_info_t *p_info = node->visit_htable[j];

				while (p_info) {
					int total_time = p_info->latest_time - p_info->first_time;
					int interval_time = cur_time - p_info->first_time;

					if (interval_time > MAX_RECORD_TIME || interval_time < 0) {
						p_info->expire = 1;
					} else if (interval_time > RECORD_REMAIN_TIME) {
						if (total_time < INVALID_RECORD_TIME)
							p_info->expire = 1;
					}
					LOG_DEBUG("[%s] appid:%d total_time:%ds interval:%ds, expire = %d\n",
						  node->mac, p_info->appid, total_time,
						  interval_time, p_info->expire);
					p_info = p_info->next;
				}
			}
			node = node->next;
		}
	}
}

void flush_expire_visit_info(void)
{
	int i, j;
	int count = 0;
	visit_info_t *prev = NULL;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			for (j = 0; j < MAX_VISIT_HASH_SIZE; j++) {
				visit_info_t *p_info = node->visit_htable[j];

				prev = NULL;
				while (p_info) {
					if (p_info->expire) {
						LOG_DEBUG("check expire,flush expire visit info: %s, appid=%d\n",
							  node->mac, p_info->appid);
						if (NULL == prev) {
							node->visit_htable[j] = p_info->next;
							free(p_info);
							p_info = node->visit_htable[j];
							prev = NULL;
						} else {
							prev->next = p_info->next;
							free(p_info);
							p_info = prev->next;
						}
					} else {
						prev = p_info;
						p_info = p_info->next;
					}
				}
			}
			node = node->next;
		}
	}
}

void dump_dev_visit_list(void)
{
	int i, j;
	int count = 0;
	FILE *fp = fopen(OAF_VISIT_LIST_FILE, "w");

	if (!fp)
		return;

	fprintf(fp, "%-4s %-20s %-20s %-8s %-32s %-32s %-32s %-8s\n", "Id", "Mac Addr",
		"Ip Addr", "Appid", "First Time", "Latest Time", "Total Time(s)", "Expire");
	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			for (j = 0; j < MAX_VISIT_HASH_SIZE; j++) {
				visit_info_t *p_info = node->visit_htable[j];

				while (p_info) {
					char *first_time_str = format_time(p_info->first_time);
					char *latest_time_str = format_time(p_info->latest_time);
					int total_time = p_info->latest_time - p_info->first_time;

					fprintf(fp, "%-4d %-20s %-20s %-8d %-32s %-32s %-32d %-4d\n",
						count, node->mac, node->ip, p_info->appid,
						first_time_str, latest_time_str, total_time,
						p_info->expire);
					if (first_time_str)
						free(first_time_str);
					if (latest_time_str)
						free(latest_time_str);
					p_info = p_info->next;
					count++;
					if (count > 50)
						goto EXIT;
				}
			}
			node = node->next;
		}
	}
EXIT:
	fclose(fp);
}

void clean_invalid_app_records(void)
{
	int i, j;
	int invalid_count = 0;
	int total_count = 0;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			for (j = 0; j < MAX_VISIT_HASH_SIZE; j++) {
				visit_info_t *p_info = node->visit_htable[j];

				while (p_info) {
					char *app_name;

					total_count++;
					app_name = get_app_name_by_id(p_info->appid);
					if (app_name && strlen(app_name) == 0) {
						p_info->expire = 1;
						invalid_count++;
						LOG_DEBUG("clean: MAC=%s, AppID=%d\n",
							  node->mac, p_info->appid);
					}
					p_info = p_info->next;
				}
			}
			node = node->next;
		}
	}
	if (invalid_count > 0)
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
	extern af_run_time_status_t g_af_status;
	int i;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			LOG_DEBUG("Reset today active time for %s: am=%d->0, pm=%d->0 (day changed)\n",
				  node->mac, node->today_am_active_time,
				  node->today_pm_active_time);
			node->today_am_active_time = 0;
			node->today_pm_active_time = 0;
			node->last_up_bytes   = node->today_up_bytes;
			node->last_down_bytes = node->today_down_bytes;
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
		LOG_WARN("reset_user_today_active_time: mac %s not found\n", mac);
		return;
	}

	LOG_DEBUG("Reset user active time: mac=%s, am=%d->0, pm=%d->0\n",
		  node->mac, node->today_am_active_time, node->today_pm_active_time);
	node->today_am_active_time = 0;
	node->today_pm_active_time = 0;
	node->blocked = 0;
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
	int i;
	static time_t last_run = 0;
	time_t now = time(NULL);
	int minutes_elapsed = 0;

	if (last_run == 0) {
		last_run = now;
		for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
			dev_node_t *node = dev_hash_table[i];

			while (node) {
				node->last_up_bytes   = node->today_up_bytes;
				node->last_down_bytes = node->today_down_bytes;
				node = node->next;
			}
		}

		return;
	}

	minutes_elapsed = (now - last_run) / 60;
	if (minutes_elapsed <= 0)
		return;
	last_run += minutes_elapsed * 60;

	struct tm *tm_info = localtime(&now);
	int current_hour = tm_info->tm_hour;

	for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
		dev_node_t *node = dev_hash_table[i];

		while (node) {
			int byte_active = (node->today_up_bytes   > node->last_up_bytes) || (node->today_down_bytes > node->last_down_bytes);

			node->last_up_bytes   = node->today_up_bytes;
			node->last_down_bytes = node->today_down_bytes;

			if (node->online && node->is_selected && (byte_active || node->active)) {
				if (current_hour < 12)
					node->today_am_active_time += minutes_elapsed;
				else
					node->today_pm_active_time += minutes_elapsed;
				LOG_DEBUG("period_time fallback: mac=%s elapsed=%d min, am=%u pm=%u\n",
					  node->mac, minutes_elapsed,
					  node->today_am_active_time,
					  node->today_pm_active_time);
			}

			node = node->next;
		}
	}
}

/* ====================================================================
 * Per-device time rule
 * ==================================================================== */

dev_time_rule_node_t *dev_time_rule_table[MAX_DEV_TIME_RULE_HASH_SIZE];

static unsigned int hash_time_rule_mac(const char *mac)
{
	unsigned int h = 0;
	int i;

	if (!mac) {
		return 0;
	}
	for (i = 0; mac[i] != '\0' && i < MAX_MAC_LEN; i++) {
		char c = mac[i];

		if (c >= 'A' && c <= 'Z')
			c = (char)(c + ('a' - 'A'));
		h = h * 31 + (unsigned char)c;
	}
	return h & (MAX_DEV_TIME_RULE_HASH_SIZE - 1);
}

void dev_time_rule_init(void)
{
	memset(dev_time_rule_table, 0, sizeof(dev_time_rule_table));
}

void dev_time_rule_flush(void)
{
	int i;

	for (i = 0; i < MAX_DEV_TIME_RULE_HASH_SIZE; i++) {
		dev_time_rule_node_t *p = dev_time_rule_table[i];

		while (p) {
			dev_time_rule_node_t *n = p->next;

			free(p);
			p = n;
		}
		dev_time_rule_table[i] = NULL;
	}
}

dev_time_rule_node_t *dev_time_rule_find(const char *mac)
{
	dev_time_rule_node_t *p;
	unsigned int h;

	if (!mac) {
		return NULL;
	}
	h = hash_time_rule_mac(mac);
	for (p = dev_time_rule_table[h]; p; p = p->next) {
		if (strcasecmp(p->mac, mac) == 0)
			return p;
	}
	return NULL;
}

void dev_time_rule_set(const char *mac, const dev_time_rule_t *rule)
{
	dev_time_rule_node_t *n;
	unsigned int h;

	if (!mac || !rule)
		return;

	n = dev_time_rule_find(mac);
	if (!n) {
		n = (dev_time_rule_node_t *)calloc(1, sizeof(*n));
		if (!n)
			return;
		mac_copy_lower(n->mac, mac, sizeof(n->mac));
		h = hash_time_rule_mac(mac);
		n->next = dev_time_rule_table[h];
		dev_time_rule_table[h] = n;
	}
	n->rule = *rule;
}

void dev_time_rule_del(const char *mac)
{
	dev_time_rule_node_t **pp;
	unsigned int h;

	if (!mac)
		return;
	h = hash_time_rule_mac(mac);
	pp = &dev_time_rule_table[h];
	while (*pp) {
		if (strcasecmp((*pp)->mac, mac) == 0) {
			dev_time_rule_node_t *t = *pp;

			*pp = t->next;
			free(t);
			return;
		}
		pp = &(*pp)->next;
	}
}

void load_dev_time_rules_from_uci(void)
{
	struct uci_context *ctx;
	int num, i;

	dev_time_rule_flush();
	ctx = uci_alloc_context();
	if (!ctx) {
		LOG_ERROR("load_dev_time_rules_from_uci: uci ctx fail\n");
		return;
	}

	num = af_get_uci_list_num(ctx, "appfilter", "af_user");
	for (i = 0; i < num; i++) {
		char mac[32] = {0}, mode_s[8] = {0};
		char start_s[16] = {0}, end_s[16] = {0};
		char key[128];
		dev_time_rule_t rule;
		int sh = 0, sm = 0, eh = 23, em = 59;

		snprintf(key, sizeof(key), "appfilter.@af_user[%d].mac", i);
		af_uci_get_value(ctx, key, mac, sizeof(mac));
		if (strlen(mac) < 11)
			continue;

		snprintf(key, sizeof(key), "appfilter.@af_user[%d].time_mode", i);
		af_uci_get_value(ctx, key, mode_s, sizeof(mode_s));

		memset(&rule, 0, sizeof(rule));
		rule.mode = atoi(mode_s);
		if (rule.mode != 1) {
			dev_time_rule_set(mac, &rule);
			continue;
		}

		snprintf(key, sizeof(key), "appfilter.@af_user[%d].time_start", i);
		af_uci_get_value(ctx, key, start_s, sizeof(start_s));
		snprintf(key, sizeof(key), "appfilter.@af_user[%d].time_end", i);
		af_uci_get_value(ctx, key, end_s, sizeof(end_s));

		if (sscanf(start_s, "%d:%d", &sh, &sm) != 2) {
			sh = 0;
			sm = 0;
		}
		if (sscanf(end_s, "%d:%d", &eh, &em) != 2) {
			eh = 23;
			em = 59;
		}
		rule.start_min = sh * 60 + sm;
		rule.end_min = eh * 60 + em;
		dev_time_rule_set(mac, &rule);
	}
	uci_free_context(ctx);
}

/* start <  end : same day,        e.g. 11:00-23:00
 * start >  end : crosses midnight, e.g. 23:00-11:00
 * start == end : treat as all-day  (defensive) */
int af_dev_time_in_rule(const dev_time_rule_t *rule, time_t now)
{
	struct tm *tm;
	int cur, start, end;

	if (!rule || rule->mode != 1)
		return 1;
	if (rule->start_min == rule->end_min)
		return 1;
	if (rule->start_min < 0 || rule->start_min >= 1440
	    || rule->end_min < 0 || rule->end_min >= 1440)
		return 1;

	tm = localtime(&now);
	if (!tm)
		return 1;
	cur = tm->tm_hour * 60 + tm->tm_min;
	start = rule->start_min;
	end = rule->end_min;

	if (start < end)
		return cur >= start && cur < end;
	return cur >= start || cur < end;
}

void update_time_exempt_macs(void)
{
	static char last_json[8192] = {0};
	static int last_ready = 0;
	char buf[8192] = {0};
	int pos = 0, first = 1, ret, i;
	time_t now = time(NULL);
	FILE *fp;

	if (!last_ready && access("/dev/appfilter", F_OK) != 0)
		return;
	last_ready = 1;

	ret = snprintf(buf, sizeof(buf), "{\"op\":7,\"data\":{\"mac_list\":[");
	if (ret < 0 || ret >= (int)sizeof(buf))
		return;
	pos = ret;

	for (i = 0; i < MAX_DEV_TIME_RULE_HASH_SIZE; i++) {
		dev_time_rule_node_t *p;

		for (p = dev_time_rule_table[i]; p; p = p->next) {
			if (p->rule.mode != 1)
				continue;
			if (af_dev_time_in_rule(&p->rule, now))
				continue;

			ret = snprintf(buf + pos, sizeof(buf) - pos,
				       first ? "\"%s\"" : ",\"%s\"", p->mac);
			if (ret < 0 || pos + ret >= (int)sizeof(buf)) {
				LOG_WARN("time-exempt list truncated, skip sync\n");
				return;
			}
			pos += ret;
			first = 0;
		}
	}
	ret = snprintf(buf + pos, sizeof(buf) - pos, "]}}");
	if (ret < 0 || pos + ret >= (int)sizeof(buf))
		return;
	pos += ret;

	if (strcmp(buf, last_json) == 0)
		return;

	fp = fopen("/dev/appfilter", "w");
	if (fp) {
		fwrite(buf, 1, strlen(buf), fp);
		fclose(fp);
		LOG_INFO("sync time-exempt macs: %s\n", buf);
	} else {
		LOG_ERROR("open /dev/appfilter failed: %s\n", strerror(errno));
	}
	strncpy(last_json, buf, sizeof(last_json) - 1);
	last_json[sizeof(last_json) - 1] = '\0';
}
