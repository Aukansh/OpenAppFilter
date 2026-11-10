/* SPDX-License-Identifier: MIT */
#ifndef _APPFILTER_USER_H
#define _APPFILTER_USER_H

#include <stddef.h>
#include <stdint.h>

#include "appfilter.h"

#define MAX_IP_LEN		32
#define MAX_MAC_LEN		32
#define MAX_VISIT_HASH_SIZE	64
#define MAX_DEV_NODE_HASH_SIZE	64
#define MAX_HOSTNAME_SIZE	64
#define MAX_NICKNAME_SIZE	64
#define MAX_REPORT_URL_LEN	64
#define MAX_APP_STAT_NUM	8
#define SECONDS_PER_DAY		(24 * 3600)

#define OAF_VISIT_LIST_FILE	"/tmp/visit_list"
#define OAF_DEV_LIST_FILE	"/tmp/dev_list"
#define OAF_USER_FILE		"/etc/user_list.dat"

typedef struct visit_info {
	int appid;
	uint32_t first_time;
	uint32_t latest_time;
	int action;
	int expire;
	struct visit_info *next;
} visit_info_t;

typedef struct visit_stat {
	uint32_t total_time;
} visit_stat_t;

typedef struct dev_time_status {
	int filter;
	int deny_time;
	int allow_time;
	int match_time;
	int remain_time;
	int period_blocked;
	unsigned int last_calc_sec;
} dev_time_status_t;

typedef struct dev_node {
	char mac[MAX_MAC_LEN];
	char ip[MAX_IP_LEN];
	char ipv6[64];
	char hostname[MAX_HOSTNAME_SIZE];
	char nickname[MAX_NICKNAME_SIZE];
	int online;
	int expire;
	uint32_t offline_time;
	uint32_t online_time;
	visit_info_t *visit_htable[MAX_VISIT_HASH_SIZE];
	visit_stat_t stat[MAX_APP_TYPE][MAX_APP_ID_NUM];
	char visiting_url[MAX_REPORT_URL_LEN];
	int visiting_app;
	int is_whitelist;
	uint32_t up_rate;
	uint32_t down_rate;
	uint64_t today_up_bytes;
	uint64_t today_down_bytes;
	uint64_t last_up_bytes;
	uint64_t last_down_bytes;
	int active;
	uint32_t today_am_active_time;
	uint32_t today_pm_active_time;
	uint32_t last_check_sec;
	int is_selected;
	int blocked;
	char custom_time_json[1024];
	dev_time_status_t time_status;
	struct dev_node *next;
} dev_node_t;

struct app_visit_info {
	int app_id;
	char app_name[32];
	int total_time;
};

struct app_visit_stat_info {
	int num;
	struct app_visit_info visit_list[MAX_APP_STAT_NUM];
};

typedef void (*iter_func)(void *arg, dev_node_t *dev);

dev_node_t *add_dev_node(char *mac);
void init_dev_node_htable(void);
dev_node_t *find_dev_node(char *mac);
void dev_foreach(void *arg, iter_func iter);
void check_dev_visit_info_expire(void);
void flush_expire_visit_info(void);
int check_dev_expire(void);
void flush_dev_expire_node(void);
void flush_offline_users(void);
void save_user_time_to_file(void);
void load_user_time_from_file(void);
void update_dev_list(void);
void update_dev_nickname(void);
void update_dev_visiting_info(void);
void update_dev_whitelist_flag(void);
void update_dev_selected_flag(void);
void clean_invalid_app_records(void);
void clear_device_app_statistics(void);
void reset_all_users_today_active_time(void);
void reset_user_today_active_time(const char *mac);
void reset_all_users_today_flow(void);
void check_all_users_period_time(void);
void update_dev_online_status(void);
void mac_copy_lower(char *dst, const char *src, size_t dst_len);
void dump_dev_list(void);

#endif /* _APPFILTER_USER_H */
