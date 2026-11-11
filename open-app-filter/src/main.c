/* SPDX-License-Identifier: MIT */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <json-c/json.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>

#include "appfilter.h"
#include "appfilter_config.h"
#include "appfilter_netlink.h"
#include "appfilter_ubus.h"
#include "appfilter_user.h"
#include "utils.h"

#define CMD_GET_LAN_CIDR_FMT		"ip -4 addr show dev %s 2>/dev/null | awk '/inet /{print $2; exit}'"
#define FORCE_DISCONNECT_HOLD_SECS	6
#define TICK_INTERVAL_MS		1000
#define INITIAL_TICK_MS			5000
#define CUSTOM_AD_APPID			"999"

enum {
	FD_STATE_IDLE = 0,
	FD_STATE_ENTER_ALL,
	FD_STATE_WAIT,
};

af_run_time_status_t g_af_status;
af_config_t g_af_config;
int g_oaf_config_change = 1;
int g_feature_update_time;

static volatile sig_atomic_t g_feature_update;
static int g_force_disconnect_hold;

typedef struct {
	int is_morning;
	int *total_active;
	int *selected_count;
} shared_arg_t;

typedef struct {
	int is_morning;
	int max_allowed_time;
	int any_blocked;
} indep_arg_t;

typedef struct {
	struct tm *cur_tm;
	int *cur_blocked;
} mode3_arg_t;

typedef struct {
	int *count;
} count_blocked_arg_t;

typedef struct {
	char *buf;
	int pos;
	int first;
	int max_size;
	int overflow;
} sync_mac_arg_t;

static struct uloop_fd appfilter_nl_fd = {
	.cb = appfilter_nl_handler,
};

static void shared_period_cb(void *arg, dev_node_t *node)
{
	shared_arg_t *s = arg;
	if (node->is_selected) {
		if (s->is_morning) *s->total_active += node->today_am_active_time;
		else *s->total_active += node->today_pm_active_time;
		if (node->online) (*s->selected_count)++;
	}
	node->blocked = 0;
}

static void indep_period_cb(void *arg, dev_node_t *node)
{
	indep_arg_t *s = arg;
	if (node->is_selected) {
		int used = s->is_morning ? node->today_am_active_time : node->today_pm_active_time;
		if (used >= s->max_allowed_time) {
			node->blocked = 1;
			s->any_blocked = 1;
		} else {
			node->blocked = 0;
		}
	} else {
		node->blocked = 0;
	}
}

static void count_blocked_cb(void *arg, dev_node_t *node)
{
	count_blocked_arg_t *c = arg;
	if (node->is_selected && node->blocked) (*c->count)++;
}

static void clear_blocked_cb(void *arg, dev_node_t *node)
{
	(void)arg;
	node->blocked = 0;
}

static void block_selected_cb(void *arg, dev_node_t *node)
{
	(void)arg;
	node->blocked = node->is_selected ? 1 : 0;
}

static void sync_blocked_macs_cb(void *arg, dev_node_t *node)
{
	sync_mac_arg_t *s = arg;
	if (s->overflow) return;

	if (node->is_selected && node->blocked) {
		int ret = snprintf(s->buf + s->pos, s->max_size - s->pos,
				   s->first ? "\"%s\"" : ",\"%s\"",
				   node->mac);
		if (ret < 0 || s->pos + ret >= s->max_size) {
			s->overflow = 1;
			return;
		}
		s->pos += ret;
		s->first = 0;
	}
}

void sync_blocked_macs_to_kernel(void)
{
	static char last_json[4096];
	char buf[4096] = {0};
	int pos = 0;
	int ret;

	ret = snprintf(buf + pos, sizeof(buf) - pos,
		       "{\"op\":%d,\"data\":{\"mac_list\":[",
		       AF_CMD_SET_BLOCKED_MAC_LIST);
	if (ret < 0 || ret >= (int)sizeof(buf))
		return;
	pos += ret;

	sync_mac_arg_t s_arg = { buf, pos, 1, sizeof(buf), 0 };
	dev_foreach(&s_arg, sync_blocked_macs_cb);

	if (s_arg.overflow) {
		LOG_WARN("blocked mac list truncated, skip sync");
		return;
	}
	pos = s_arg.pos;

	ret = snprintf(buf + pos, sizeof(buf) - pos, "]}}");
	if (ret < 0 || pos + ret >= (int)sizeof(buf)) {
		LOG_WARN("blocked mac list tail overflow, skip sync");
		return;
	}
	pos += ret;

	if (strcmp(buf, last_json) == 0)
		return;

	{
		FILE *fp = fopen("/dev/appfilter", "w");
		if (fp) {
			fwrite(buf, 1, strlen(buf), fp);
			fclose(fp);
			LOG_INFO("sync blocked macs to kernel: %s", buf);
		} else {
			LOG_ERROR("open /dev/appfilter failed");
		}
	}

	snprintf(last_json, sizeof(last_json), "%s", buf);
}

static void af_init_time_status(void)
{
	g_af_status.filter = 0;
	g_af_status.deny_time = 0;
	g_af_status.allow_time = 0;
	g_af_status.match_time = 0;
	g_af_status.remain_time = 0;
	g_af_status.used_time = 0;
	g_af_status.period_blocked = 0;
}

static void update_oaf_proc_value(const char *key, const char *value)
{
	char cmd_buf[128] = {0};
	char file_path[128] = {0};
	char old_value[128] = {0};

	snprintf(file_path, sizeof(file_path), "/proc/sys/oaf/%s", key);

	if (af_read_file_value(file_path, old_value, sizeof(old_value)) == -1)
		return;

	if (strcmp(old_value, value) != 0) {
		snprintf(cmd_buf, sizeof(cmd_buf), "echo %s >/proc/sys/oaf/%s", value, key);
		(void)system(cmd_buf);
		LOG_DEBUG("update %s %s-->%s", key, old_value, value);
	}
}

static void update_oaf_proc_u32_value(const char *key, uint32_t value)
{
	char buf[32] = {0};
	snprintf(buf, sizeof(buf), "%u", value);
	update_oaf_proc_value(key, buf);
}

static int is_valid_ifname(const char *name)
{
	const char *p;

	if (!name || !name[0])
		return 0;
	for (p = name; *p; p++) {
		if ((*p >= 'a' && *p <= 'z') ||
		    (*p >= 'A' && *p <= 'Z') ||
		    (*p >= '0' && *p <= '9') ||
		    *p == '.' || *p == '_' || *p == '-')
			continue;
		return 0;
	}
	return 1;
}

static int parse_cidr_ipv4(const char *cidr, char *ip_out, int ip_len, char *mask_out, int mask_len)
{
	char buf[64] = {0};
	char *slash;
	uint32_t mask_h;
	struct in_addr ma;
	int prefix;

	if (!cidr || !ip_out || !mask_out || ip_len <= 0 || mask_len <= 0)
		return -1;
	if (strlen(cidr) >= sizeof(buf))
		return -1;

	snprintf(buf, sizeof(buf), "%s", cidr);
	slash = strchr(buf, '/');
	if (!slash)
		return -1;
	*slash = '\0';
	prefix = atoi(slash + 1);
	if (prefix < 0 || prefix > 32)
		return -1;

	snprintf(ip_out, ip_len, "%s", buf);
	mask_h = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
	ma.s_addr = htonl(mask_h);
	snprintf(mask_out, mask_len, "%s", inet_ntoa(ma));
	return 0;
}

static void update_lan_ip(void)
{
	char cidr[64] = {0};
	char ip_str[32] = {0};
	char mask_str[32] = {0};
	char lan_ifname[32] = {0};
	char cidr_cmd_buf[128] = {0};
	struct in_addr addr, mask_addr;
	struct uci_context *ctx;
	int ret;

	ctx = uci_alloc_context();
	if (!ctx)
		return;

	ret = af_uci_get_value(ctx, "appfilter.global.lan_ifname", lan_ifname, sizeof(lan_ifname) - 1);
	if (ret != 0)
		snprintf(lan_ifname, sizeof(lan_ifname), "br-lan");

	if (!is_valid_ifname(lan_ifname)) {
		LOG_WARN("invalid lan_ifname '%s', fallback to br-lan", lan_ifname);
		snprintf(lan_ifname, sizeof(lan_ifname), "br-lan");
	}

	snprintf(cidr_cmd_buf, sizeof(cidr_cmd_buf), CMD_GET_LAN_CIDR_FMT, lan_ifname);
	exec_with_result_line(cidr_cmd_buf, cidr, sizeof(cidr));

	if (strlen(cidr) == 0 || parse_cidr_ipv4(cidr, ip_str, sizeof(ip_str), mask_str, sizeof(mask_str)) != 0) {
		update_oaf_proc_u32_value("lan_ip", 0);
		update_oaf_proc_u32_value("lan_mask", 0);
		uci_free_context(ctx);
		return;
	}

	if (inet_aton(ip_str, &addr))
		update_oaf_proc_u32_value("lan_ip", addr.s_addr);
	else
		update_oaf_proc_u32_value("lan_ip", 0);

	if (inet_aton(mask_str, &mask_addr))
		update_oaf_proc_u32_value("lan_mask", mask_addr.s_addr);
	else
		update_oaf_proc_u32_value("lan_mask", 0);

	uci_free_context(ctx);
}

static int af_parse_daily_limit(const char *raw, daily_limit_config_t *daily_limit)
{
	const char *first_colon, *second_colon;

	daily_limit->enable = 0;
	daily_limit->am_time = 0;
	daily_limit->pm_time = 0;

	if (!raw || !raw[0])
		return 0;

	first_colon = strchr(raw, ':');
	if (first_colon) {
		second_colon = strchr(first_colon + 1, ':');
		if (second_colon) {
			daily_limit->enable = atoi(raw);
			daily_limit->am_time = atoi(first_colon + 1);
			daily_limit->pm_time = atoi(second_colon + 1);
		} else {
			daily_limit->enable = 1;
			daily_limit->am_time = atoi(raw);
			daily_limit->pm_time = atoi(first_colon + 1);
		}
	} else {
		daily_limit->enable = 1;
		daily_limit->am_time = atoi(raw);
	}
	return 0;
}

static void apply_time_config_to_uci(const af_time_config_t *time_config)
{
	char days_str[128] = {0};
	char weekday_str[64];
	char time_str[256];
	char start_time_str[16];
	char end_time_str[16];
	struct uci_context *uci_ctx;
	int first = 1;
	int i, j;

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		LOG_ERROR("apply_time_config_to_uci: uci_alloc_context failed");
		return;
	}

	af_uci_set_int_value(uci_ctx, "appfilter.time.time_mode", time_config->time_mode);

	for (i = 0; i < 7; i++) {
		if (time_config->days[i] == 1) {
			char tmp[8];
			if (!first) strcat(days_str, " ");
			snprintf(tmp, sizeof(tmp), "%d", i);
			strcat(days_str, tmp);
			first = 0;
		}
	}
	af_uci_set_value(uci_ctx, "appfilter.time.days", days_str);

	if (time_config->time_mode == 0) {
		int time_list_len = time_config->time_num;
		af_uci_delete(uci_ctx, "appfilter.time.time");
		for (i = 0; i < time_list_len; i++) {
			memset(weekday_str, 0, sizeof(weekday_str));
			first = 1;
			for (j = 0; j < 7; j++) {
				if (time_config->time_list[i].days[j] == 1) {
					char tmp[8];
					if (!first) strcat(weekday_str, ",");
					snprintf(tmp, sizeof(tmp), "%d", j);
					strcat(weekday_str, tmp);
					first = 0;
				}
			}
			snprintf(start_time_str, sizeof(start_time_str), "%02d:%02d", time_config->time_list[i].start_time.hour, time_config->time_list[i].start_time.min);
			snprintf(end_time_str, sizeof(end_time_str), "%02d:%02d", time_config->time_list[i].end_time.hour, time_config->time_list[i].end_time.min);

			memset(time_str, 0, sizeof(time_str));
			snprintf(time_str, sizeof(time_str), "%s;%s-%s", weekday_str, start_time_str, end_time_str);
			af_uci_add_list(uci_ctx, "appfilter.time.time", time_str);
		}
	} else {
		af_uci_set_int_value(uci_ctx, "appfilter.time.deny_time", time_config->deny_time);
		af_uci_set_int_value(uci_ctx, "appfilter.time.allow_time", time_config->allow_time);
		snprintf(start_time_str, sizeof(start_time_str), "%02d:%02d", time_config->seg_time.start_time.hour, time_config->seg_time.start_time.min);
		snprintf(end_time_str, sizeof(end_time_str), "%02d:%02d", time_config->seg_time.end_time.hour, time_config->seg_time.end_time.min);
		af_uci_set_value(uci_ctx, "appfilter.time.start_time", start_time_str);
		af_uci_set_value(uci_ctx, "appfilter.time.end_time", end_time_str);
	}

	af_uci_commit(uci_ctx, "appfilter");
	uci_free_context(uci_ctx);
}

static int af_load_time_config(af_time_config_t *t_config)
{
	char time_list_buf[MAX_TIME_LIST_LEN] = {0};
	char time_list_copy[MAX_TIME_LIST_LEN] = {0};
	char days_buf[128] = {0};
	char start_time_buf[128] = {0};
	char end_time_buf[128] = {0};
	struct uci_context *ctx;
	char *saveptr1 = NULL;
	char *p;
	int old_ver_config = 0;
	int period_idx = 0;
	int weekday;

	LOG_DEBUG("af_load_time_config: start");
	ctx = uci_alloc_context();
	if (!ctx)
		return -1;

	memset(t_config, 0, sizeof(*t_config));
	t_config->time_mode = af_uci_get_int_value(ctx, "appfilter.time.time_mode");
	t_config->deny_time = af_uci_get_int_value(ctx, "appfilter.time.deny_time");
	t_config->allow_time = af_uci_get_int_value(ctx, "appfilter.time.allow_time");

	af_uci_get_value(ctx, "appfilter.time.start_time", start_time_buf, sizeof(start_time_buf));
	af_uci_get_value(ctx, "appfilter.time.end_time", end_time_buf, sizeof(end_time_buf));
	af_uci_get_value(ctx, "appfilter.time.days", days_buf, sizeof(days_buf));
	sscanf(start_time_buf, "%d:%d", &t_config->seg_time.start_time.hour, &t_config->seg_time.start_time.min);
	sscanf(end_time_buf, "%d:%d", &t_config->seg_time.end_time.hour, &t_config->seg_time.end_time.min);
	t_config->time_num = 0;

	p = strtok_r(days_buf, " ", &saveptr1);
	while (p) {
		int day_val = atoi(p);
		if (day_val >= 0 && day_val < 7) {
			t_config->days[day_val] = 1;
		} else {
			LOG_WARN("af_load_time_config: invalid day %d, skip", day_val);
		}
		p = strtok_r(NULL, " ", &saveptr1);
	}

	for (weekday = 0; weekday < 7; weekday++) {
		char uci_key[64] = {0};
		char daily_limit_str[128] = {0};
		snprintf(uci_key, sizeof(uci_key), "appfilter.time.daily_limit_%d", weekday);
		af_uci_get_value(ctx, uci_key, daily_limit_str, sizeof(daily_limit_str));
		af_parse_daily_limit(daily_limit_str, &t_config->daily_limit[weekday]);
	}

	af_uci_get_list_value(ctx, "appfilter.time.time", time_list_buf, sizeof(time_list_buf), " ");
	snprintf(time_list_copy, sizeof(time_list_copy), "%s", time_list_buf);

	saveptr1 = NULL;
	p = strtok_r(time_list_copy, " ", &saveptr1);
	if (!p) {
		LOG_DEBUG("af_load_time_config: no time periods found");
		goto out;
	}

	do {
		time_config_t *cfg;
		char *time_part;
		char *semicolon;
		int i, ret;

		if (t_config->time_num >= MAX_TIME_LIST) {
			LOG_WARN("af_load_time_config: time_list full, skip");
			break;
		}

		cfg = &t_config->time_list[t_config->time_num];
		time_part = p;
		for (i = 0; i < 7; i++) cfg->days[i] = t_config->days[i];

		semicolon = strchr(p, ';');
		if (semicolon) {
			char weekday_str[64] = {0};
			char weekday_copy[64] = {0};
			char *saveptr_wd = NULL;
			char *wd;

			snprintf(weekday_str, sizeof(weekday_str), "%.*s", (int)(semicolon - p), p);
			time_part = semicolon + 1;

			for (i = 0; i < 7; i++) cfg->days[i] = 0;

			snprintf(weekday_copy, sizeof(weekday_copy), "%s", weekday_str);
			wd = strtok_r(weekday_copy, ",", &saveptr_wd);
			while (wd) {
				int day_val = atoi(wd);
				if (day_val >= 0 && day_val < 7) cfg->days[day_val] = 1;
				wd = strtok_r(NULL, ",", &saveptr_wd);
			}
		} else {
			LOG_DEBUG("af_load_time_config: period[%d] no weekdays, using global", period_idx);
			old_ver_config = 1;
		}

		ret = sscanf(time_part, "%d:%d-%d:%d", &cfg->start_time.hour, &cfg->start_time.min, &cfg->end_time.hour, &cfg->end_time.min);
		if (ret != 4) {
			LOG_WARN("af_load_time_config: period[%d] ERROR: parse time from %s", period_idx, time_part);
		} else {
			t_config->time_num++;
		}
		period_idx++;
	} while ((p = strtok_r(NULL, " ", &saveptr1)) != NULL);

	LOG_DEBUG("af_load_time_config: total periods loaded: %d", t_config->time_num);

out:
	uci_free_context(ctx);
	return old_ver_config;
}

static void af_load_global_config(af_global_config_t *config)
{
	char lan_ifname[32] = {0};
	struct uci_context *ctx;
	int ret;

	ctx = uci_alloc_context();
	if (!ctx)
		return;

	ret = af_uci_get_int_value(ctx, "appfilter.global.enable"); config->enable = (ret < 0) ? 0 : ret;
	ret = af_uci_get_int_value(ctx, "appfilter.global.record_enable"); config->record_enable = (ret < 0) ? 0 : ret;
	ret = af_uci_get_int_value(ctx, "appfilter.global.user_mode"); config->user_mode = (ret < 0) ? 0 : ret;
	ret = af_uci_get_int_value(ctx, "appfilter.global.work_mode"); config->work_mode = (ret < 0) ? 0 : ret;
	ret = af_uci_get_int_value(ctx, "appfilter.global.tcp_rst"); config->tcp_rst = (ret < 0) ? 1 : ret;
	ret = af_uci_get_int_value(ctx, "appfilter.global.disable_hnat"); config->disable_hnat = (ret < 0) ? 1 : ret;
	ret = af_uci_get_int_value(ctx, "appfilter.global.auto_load_engine"); config->auto_load_engine = (ret < 0) ? 0 : ret;
	ret = af_uci_get_int_value(ctx, "appfilter.global.disable_quic"); config->disable_quic = (ret < 0) ? 0 : ret;
	ret = af_uci_get_int_value(ctx, "appfilter.global.app_filter_mode"); config->app_filter_mode = (ret < 0) ? 0 : ret;
	ret = af_uci_get_int_value(ctx, "appfilter.global.daily_limit_mode"); config->daily_limit_mode = (ret < 0) ? 0 : ret;
	ret = af_uci_get_int_value(ctx, "appfilter.global.custom_ad_enable"); config->custom_ad_enable = (ret < 0) ? 0 : ret;

	ret = af_uci_get_value(ctx, "appfilter.global.lan_ifname", lan_ifname, sizeof(lan_ifname));
	if (ret < 0)
		snprintf(config->lan_ifname, sizeof(config->lan_ifname), "br-lan");
	else
		snprintf(config->lan_ifname, sizeof(config->lan_ifname), "%s", lan_ifname);

	uci_free_context(ctx);
	LOG_DEBUG("enable=%d, user_mode=%d, work_mode=%d, disable_quic=%d, app_filter_mode=%d",
		  config->enable, config->user_mode, config->work_mode, config->disable_quic, config->app_filter_mode);
}

static void af_load_config(af_config_t *config)
{
	memset(config, 0, sizeof(*config));
	af_load_global_config(&config->global);
	if (af_load_time_config(&config->time) == 1)
		apply_time_config_to_uci(&config->time);
}

static void clear_all_blocked_flags(void)
{
	dev_foreach(NULL, clear_blocked_cb);
}

static int af_check_time_manual(const af_time_config_t *t_config)
{
	time_t now = time(NULL);
	struct tm *current_time = localtime(&now);
	int cur_min = current_time->tm_hour * 60 + current_time->tm_min;
	int cur_wday = current_time->tm_wday;
	int i;

	for (i = 0; i < t_config->time_num; i++) {
		int start_min, end_min;
		if (!t_config->time_list[i].days[cur_wday]) continue;

		start_min = t_config->time_list[i].start_time.hour * 60 + t_config->time_list[i].start_time.min;
		end_min = t_config->time_list[i].end_time.hour * 60 + t_config->time_list[i].end_time.min;

		if (cur_min >= start_min && cur_min <= end_min) {
			g_af_status.match_time = 1;
			return 1;
		}
	}
	g_af_status.match_time = 0;
	return 0;
}

static int af_check_time_dynamic(const af_time_config_t *t_config)
{
	(void)t_config;
	return g_af_status.filter;
}

static int update_dynamic_used_time(const af_time_config_t *t_config)
{
	time_t now;
	struct tm *current_time;
	int cur_min, start_min, end_min;

	if (t_config->time_mode != 1) return -1;

	now = time(NULL);
	current_time = localtime(&now);

	if (!t_config->days[current_time->tm_wday]) {
		af_init_time_status();
		return -1;
	}

	cur_min = current_time->tm_hour * 60 + current_time->tm_min;
	start_min = t_config->seg_time.start_time.hour * 60 + t_config->seg_time.start_time.min;
	end_min = t_config->seg_time.end_time.hour * 60 + t_config->seg_time.end_time.min;

	if (!(cur_min >= start_min && cur_min <= end_min)) {
		af_init_time_status();
		return 0;
	}

	g_af_status.match_time = 1;
	if (g_af_status.filter == 1) {
		g_af_status.deny_time++;
		if (g_af_status.deny_time >= t_config->deny_time) {
			g_af_status.filter = 0;
			g_af_status.deny_time = 0;
		}
	} else {
		g_af_status.allow_time++;
		if (g_af_status.allow_time >= t_config->allow_time) {
			g_af_status.filter = 1;
			g_af_status.allow_time = 0;
		}
	}
	return 0;
}

static int af_check_time_period_limit(const af_time_config_t *t_config)
{
	int total_active_time = 0;
	int selected_user_count = 0;
	int max_allowed_time;
	int is_morning;
	int current_weekday;
	int current_hour;
	struct tm *current_time;
	time_t now;

	now = time(NULL);
	current_time = localtime(&now);
	current_weekday = current_time->tm_wday;
	current_hour = current_time->tm_hour;

	{
		const daily_limit_config_t *daily_limit = &t_config->daily_limit[current_weekday];

		if (!daily_limit->enable) {
			g_af_status.match_time = 0;
			g_af_status.remain_time = 0;
			g_af_status.used_time = 0;
			g_af_status.period_blocked = 0;
			clear_all_blocked_flags();
			sync_blocked_macs_to_kernel();
			return 0;
		}

		is_morning = (current_hour < 12);
		max_allowed_time = is_morning ? daily_limit->am_time : daily_limit->pm_time;

		if (max_allowed_time == -1) {
			g_af_status.match_time = 1;
			g_af_status.period_blocked = 1;
			g_af_status.remain_time = 0;
			g_af_status.used_time = 0;

			if (g_af_config.global.daily_limit_mode == 1) {
				dev_foreach(NULL, block_selected_cb);
				sync_blocked_macs_to_kernel();
			}
			return 1;
		}

		if (max_allowed_time <= 0) {
			g_af_status.match_time = 0;
			g_af_status.remain_time = 0;
			g_af_status.used_time = 0;
			g_af_status.period_blocked = 0;
			clear_all_blocked_flags();
			sync_blocked_macs_to_kernel();
			return 0;
		}
	}

	check_all_users_period_time();

	if (g_af_config.global.daily_limit_mode == 0) {
		int remain_time;
		shared_arg_t shared_arg = { is_morning, &total_active_time, &selected_user_count };

		dev_foreach(&shared_arg, shared_period_cb);

		g_af_status.used_time = total_active_time;
		remain_time = max_allowed_time - total_active_time;
		if (remain_time < 0) remain_time = 0;
		g_af_status.remain_time = remain_time;

		sync_blocked_macs_to_kernel();

		g_af_status.match_time = 1;
		if (total_active_time >= max_allowed_time) {
			g_af_status.period_blocked = 1;
			return 1;
		}
		g_af_status.period_blocked = 0;
		return 0;
	}

	{
		indep_arg_t indep_arg = { is_morning, max_allowed_time, 0 };
		dev_foreach(&indep_arg, indep_period_cb);
		int any_blocked = indep_arg.any_blocked;

		sync_blocked_macs_to_kernel();
		g_af_status.match_time = 1;
		g_af_status.period_blocked = any_blocked;
		g_af_status.remain_time = 0;
		g_af_status.used_time = 0;
		return any_blocked ? 1 : 0;
	}
}

static int af_check_time_valid(const af_time_config_t *t_config)
{
	switch (t_config->time_mode) {
	case 0: return af_check_time_manual(t_config);
	case 1: return af_check_time_dynamic(t_config);
	case 2: return af_check_time_period_limit(t_config);
	default: return 0;
	}
}

static void force_disconnect_tick(int trigger)
{
	static int g_fd_state = FD_STATE_IDLE;
	static time_t g_fd_start;
	time_t now;

	if (trigger) {
		if (g_fd_state != FD_STATE_WAIT)
			g_fd_state = FD_STATE_ENTER_ALL;
		g_fd_start = 0;
		LOG_INFO("force_disconnect: scheduled (restart)");
		return;
	}

	switch (g_fd_state) {
	case FD_STATE_IDLE:
		return;
	case FD_STATE_ENTER_ALL:
		update_oaf_proc_value("app_filter_mode", "1");
		g_force_disconnect_hold = 1;
		g_fd_start = time(NULL);
		g_fd_state = FD_STATE_WAIT;
		LOG_INFO("force_disconnect: switched to all-apps mode, hold %d sec", FORCE_DISCONNECT_HOLD_SECS);
		return;
	case FD_STATE_WAIT:
		now = time(NULL);
		if (now - g_fd_start >= FORCE_DISCONNECT_HOLD_SECS) {
			g_force_disconnect_hold = 0;
			update_oaf_proc_value("app_filter_mode", g_af_config.global.app_filter_mode == 1 ? "1" : "0");
			g_fd_state = FD_STATE_IDLE;
			LOG_INFO("force_disconnect: restored correct app_filter_mode");
		}
		return;
	}
}

static int calc_device_fixed(struct json_object *jobj, struct tm *cur_tm)
{
	struct json_object *list_obj = json_object_object_get(jobj, "time_list");
	if (!list_obj || !json_object_is_type(list_obj, json_type_array)) return 0;

	int cur_min = cur_tm->tm_hour * 60 + cur_tm->tm_min;
	int cur_wday = cur_tm->tm_wday;
	int yesterday = (cur_wday + 6) % 7;
	int len = json_object_array_length(list_obj);

	for (int i = 0; i < len; i++) {
		struct json_object *item = json_object_array_get_idx(list_obj, i);
		struct json_object *start_obj = json_object_object_get(item, "start");
		struct json_object *end_obj = json_object_object_get(item, "end");
		struct json_object *wd_obj = json_object_object_get(item, "weekday_list");

		if (!start_obj || !end_obj || !wd_obj) continue;

		int match_today = 0;
		int match_yesterday = 0;
		for (int j = 0; j < json_object_array_length(wd_obj); j++) {
			int d = json_object_get_int(json_object_array_get_idx(wd_obj, j));
			if (d == cur_wday) match_today = 1;
			if (d == yesterday) match_yesterday = 1;
		}
		
		int sh = 0, sm = 0, eh = 0, em = 0;
		sscanf(json_object_get_string(start_obj), "%d:%d", &sh, &sm);
		sscanf(json_object_get_string(end_obj), "%d:%d", &eh, &em);

		int s_min = sh * 60 + sm;
		int e_min = eh * 60 + em;

		if (s_min <= e_min) {
			if (match_today && cur_min >= s_min && cur_min <= e_min) return 1;
		} else {
			if (match_today && cur_min >= s_min) return 1;
			if (match_yesterday && cur_min <= e_min) return 1;
		}
	}
	return 0;
}

static int calc_device_dynamic(struct json_object *jobj, dev_node_t *node, struct tm *cur_tm)
{
	struct json_object *allow_obj = json_object_object_get(jobj, "allow_time");
	struct json_object *deny_obj = json_object_object_get(jobj, "deny_time");
	if (!allow_obj || !deny_obj) return 0;

	int allow_limit = json_object_get_int(allow_obj) * 60;
	int deny_limit = json_object_get_int(deny_obj) * 60;
	int in_range = 0;
	int cur_min = cur_tm->tm_hour * 60 + cur_tm->tm_min;
	int cur_wday = cur_tm->tm_wday;

	struct json_object *wd_obj = json_object_object_get(jobj, "weekday_list");
	if (wd_obj && json_object_array_length(wd_obj) > 0) {
		for (int j = 0; j < json_object_array_length(wd_obj); j++) {
			if (json_object_get_int(json_object_array_get_idx(wd_obj, j)) == cur_wday) {
				in_range = 1; break;
			}
		}
	} else {
		in_range = 1;
	}

	if (in_range) {
		struct json_object *start_obj = json_object_object_get(jobj, "start_time");
		struct json_object *end_obj = json_object_object_get(jobj, "end_time");
		if (start_obj && end_obj) {
			int sh = 0, sm = 0, eh = 23, em = 59;
			sscanf(json_object_get_string(start_obj), "%d:%d", &sh, &sm);
			sscanf(json_object_get_string(end_obj), "%d:%d", &eh, &em);
			int s_min = sh * 60 + sm;
			int e_min = eh * 60 + em;
			if (s_min <= e_min) in_range = (cur_min >= s_min && cur_min <= e_min);
			else in_range = (cur_min >= s_min || cur_min <= e_min);
		}
	}

	if (!in_range) {
		node->time_status.match_time = 0;
		node->time_status.filter = 0;
		node->time_status.deny_time = 0;
		node->time_status.allow_time = 0;
		return 0;
	}

	if (node->time_status.match_time == 0) {
		node->time_status.filter = 1;
		node->time_status.deny_time = 0;
		node->time_status.allow_time = 0;
		node->time_status.match_time = 1;
		node->time_status.last_calc_sec = get_timestamp();
	}

	uint32_t now = get_timestamp();
	int delta = (int)(now - node->time_status.last_calc_sec);

	if (delta < 0) delta = 0;
	node->time_status.last_calc_sec = now;

	if (delta > 0) {
		if (node->time_status.filter == 1) {
			node->time_status.deny_time += delta;
			if (node->time_status.deny_time >= deny_limit) {
				node->time_status.filter = 0;
				node->time_status.deny_time = 0;
				node->time_status.allow_time = 0;
			}
		} else {
			node->time_status.allow_time += delta;
			if (node->time_status.allow_time >= allow_limit) {
				node->time_status.filter = 1;
				node->time_status.allow_time = 0;
				node->time_status.deny_time = 0;
			}
		}
	}
	return node->time_status.filter;
}

static int calc_device_daily(struct json_object *jobj, dev_node_t *node, struct tm *cur_tm)
{
	struct json_object *list_obj = json_object_object_get(jobj, "daily_time_list");
	if (!list_obj || json_object_array_length(list_obj) != 7) return 0;

	struct json_object *day_obj = json_object_array_get_idx(list_obj, cur_tm->tm_wday);
	if (!day_obj) return 0;

	struct json_object *enable_obj = json_object_object_get(day_obj, "enable");
	if (!enable_obj || json_object_get_int(enable_obj) != 1) return 0;

	int is_morning = (cur_tm->tm_hour < 12);
	struct json_object *limit_obj = json_object_object_get(day_obj, is_morning ? "am_time" : "pm_time");
	if (!limit_obj) return 0;

	int limit = json_object_get_int(limit_obj);
	if (limit == -1) return 1;
	if (limit <= 0) return 0;

	int used = is_morning ? node->today_am_active_time : node->today_pm_active_time;
	return (used >= limit) ? 1 : 0;
}

static void mode3_status_cb(void *arg, dev_node_t *node)
{
	mode3_arg_t *m = arg;
	if (!node->is_selected || strlen(node->custom_time_json) == 0) {
		node->blocked = node->is_selected ? 1 : 0;
	} else {
		struct json_object *jobj = json_tokener_parse(node->custom_time_json);
		if (jobj) {
			struct json_object *mode_obj = json_object_object_get(jobj, "mode");
			int dev_mode = mode_obj ? json_object_get_int(mode_obj) : -1;
			if (dev_mode == 0) node->blocked = calc_device_fixed(jobj, m->cur_tm);
			else if (dev_mode == 1) node->blocked = calc_device_dynamic(jobj, node, m->cur_tm);
			else if (dev_mode == 2) node->blocked = calc_device_daily(jobj, node, m->cur_tm);
			json_object_put(jobj);
		}
	}
	if (node->is_selected && node->blocked) (*m->cur_blocked)++;
}

static void update_oaf_status(void)
{
	static int last_ret = -1;
	static int last_blocked_count;
	int cur_blocked_count = 0;
	int need_force = 0;
	int ret = 0;

	if (g_af_config.global.enable == 1) {
		update_oaf_proc_value("enable", "1");
	} else {
		update_oaf_proc_value("enable", "0");
	}

	if (g_af_config.time.time_mode == 3) {
		time_t now = time(NULL);
		struct tm *cur_tm = localtime(&now);
		static int last_mode3_blocked = 0;
		int cur_mode3_blocked = 0;
		mode3_arg_t m3 = { cur_tm, &cur_mode3_blocked };

		dev_foreach(&m3, mode3_status_cb);
		sync_blocked_macs_to_kernel();

		if (cur_mode3_blocked > last_mode3_blocked) {
			force_disconnect_tick(1);
		}
		last_mode3_blocked = cur_mode3_blocked;
		return;
	}

	if (g_af_config.global.enable == 1 && g_af_config.time.time_mode != 3)
		ret = af_check_time_valid(&g_af_config.time);

	count_blocked_arg_t c_arg = { &cur_blocked_count };
	dev_foreach(&c_arg, count_blocked_cb);

	if (ret == 1 && last_ret == 0) need_force = 1;
	if (cur_blocked_count > last_blocked_count) need_force = 1;

	if (need_force && g_af_config.time.time_mode != 1 && g_af_config.global.app_filter_mode == 0) {
		force_disconnect_tick(1);
		LOG_INFO("force_disconnect triggered: ret=%d->%d blocked=%d->%d", last_ret, ret, last_blocked_count, cur_blocked_count);
	}

	last_ret = ret;
	last_blocked_count = cur_blocked_count;
	update_oaf_proc_value("enable", ret == 1 ? "1" : "0");
}

static void update_oaf_record_status(void)
{
	update_oaf_proc_value("record_enable", g_af_config.global.record_enable == 1 ? "1" : "0");
}

static void update_oaf_disable_quic_status(void)
{
	update_oaf_proc_value("disable_quic", g_af_config.global.disable_quic == 1 ? "1" : "0");
}

static void update_oaf_app_filter_mode_status(void)
{
	if (g_force_disconnect_hold) {
		LOG_DEBUG("skip app_filter_mode update during hold");
		return;
	}
	update_oaf_proc_value("app_filter_mode", g_af_config.global.app_filter_mode == 1 ? "1" : "0");
}

static void update_oaf_daily_limit_mode_status(void)
{
	if (g_af_config.time.time_mode == 3) {
		update_oaf_proc_value("daily_limit_mode", "1");
		return;
	}
	update_oaf_proc_value("daily_limit_mode", g_af_config.global.daily_limit_mode == 1 ? "1" : "0");
}

static void update_oaf_custom_ad_status(void)
{
	update_oaf_proc_value("custom_ad_enable", g_af_config.global.custom_ad_enable == 1 ? "1" : "0");
}

static int af_nl_clean_feature(void)
{
	af_msg_t msg;
	if (appfilter_nl_fd.fd < 0) return -1;
	msg.action = AF_MSG_CLEAN_FEATURE;
	send_msg_to_kernel(appfilter_nl_fd.fd, (void *)&msg, sizeof(msg));
	return 0;
}

static int af_nl_add_feature(const char *feature)
{
	char msg_buf[1024] = {0};
	af_msg_t *hdr;
	char *p_data;

	if (appfilter_nl_fd.fd < 0) return -1;

	hdr = (af_msg_t *)msg_buf;
	hdr->action = AF_MSG_ADD_FEATURE;
	p_data = msg_buf + sizeof(af_msg_t);
	snprintf(p_data, sizeof(msg_buf) - sizeof(af_msg_t), "%s", feature);

	send_msg_to_kernel(appfilter_nl_fd.fd, (void *)msg_buf, sizeof(af_msg_t) + strlen(feature) + 1);
	return 0;
}

static void load_custom_ad_to_kernel(void)
{
	FILE *fp = fopen("/etc/appfilter/custom_ad.cfg", "r");
	char line[1024];

	if (!fp) {
		LOG_DEBUG("No custom_ad.cfg found, skip.");
		return;
	}

	while (fgets(line, sizeof(line), fp)) {
		char feature_str[1100];
		line[strcspn(line, "\r\n")] = 0;
		if (strlen(line) == 0 || line[0] == '#') continue;

		snprintf(feature_str, sizeof(feature_str), CUSTOM_AD_APPID " custom_ad:%s", line);
		af_nl_add_feature(feature_str);
	}
	fclose(fp);
}

static int af_load_feature_to_kernel(void)
{
	char line_buf[MAX_FEATURE_LINE_LEN] = {0};
	FILE *fp;

	fp = fopen("/tmp/feature.cfg", "r");
	if (!fp) {
		LOG_ERROR("af_load_feature_to_kernel: cannot open feature.cfg");
		return -1;
	}

	if (af_nl_clean_feature() < 0) {
		fclose(fp);
		return -1;
	}

	while (fgets(line_buf, sizeof(line_buf), fp)) {
		str_trim(line_buf);
		if (strlen(line_buf) < 8) continue;
		if (strstr(line_buf, "#")) continue;
		if (strlen(line_buf) >= MAX_FEATURE_LINE_LEN - 1) continue;
		af_nl_add_feature(line_buf);
	}
	fclose(fp);
	return 0;
}

static int reload_feature(void)
{
	(void)system("gen_class.sh /tmp/feature.cfg");
	init_app_name_table();
	init_app_class_name_table();

	if (af_load_feature_to_kernel() < 0) {
		LOG_ERROR("Failed to load feature to kernel");
		return -1;
	}

	load_custom_ad_to_kernel();

	clean_invalid_app_records();
	clear_device_app_statistics();
	LOG_INFO("reload feature success");
	g_feature_update_time = get_timestamp();
	return 0;
}

static void check_date_change(void)
{
	static int last_day = -1;
	time_t now = time(NULL);
	struct tm *tm_info = localtime(&now);
	int current_day = tm_info->tm_mday;

	if (last_day == current_day) return;

	LOG_INFO("day changed: %d -> %d", last_day, current_day);
	if (last_day != -1) {
		clear_device_app_statistics();
		reset_all_users_today_active_time();
		reset_all_users_today_flow();
	}
	last_day = current_day;
}

static void oaf_timeout_handler(struct uloop_timeout *t)
{
	static int count;

	force_disconnect_tick(0);

	if (count % 5 == 0) update_oaf_status();
	
	if (count % 10 == 0) {
		update_dev_list();
		check_all_users_period_time();
	}

	if (count % 60 == 0) {
		LOG_DEBUG("begin check dev count = %d", count);
		check_dev_visit_info_expire();
		flush_expire_visit_info();
		update_dynamic_used_time(&g_af_config.time);
		update_lan_ip();
		update_dev_selected_flag();
		if (check_dev_expire()) flush_dev_expire_node();
		check_date_change();
		dump_dev_list();
	}

	if (count % 600 == 0 && count > 0 && g_af_config.time.time_mode == 2) {
		save_user_time_to_file();
	}

	if (g_oaf_config_change == 1) {
		LOG_INFO("config changed");
		update_lan_ip();
		af_load_config(&g_af_config);
		update_dev_selected_flag();
		update_dynamic_used_time(&g_af_config.time);
		update_oaf_status();
		update_oaf_record_status();
		update_oaf_disable_quic_status();
		update_oaf_app_filter_mode_status();
		update_oaf_daily_limit_mode_status();
		update_oaf_custom_ad_status();
		g_oaf_config_change = 0;

		if (g_af_config.time.time_mode != 1 && g_af_config.global.app_filter_mode == 0)
			force_disconnect_tick(1);
	}

	if (appfilter_nl_fd.fd < 0 && access("/proc/sys/oaf", F_OK) == 0) {
		appfilter_nl_fd.fd = appfilter_nl_init();
		if (appfilter_nl_fd.fd > 0) {
			uloop_fd_add(&appfilter_nl_fd, ULOOP_READ);
			(void)system("oaf_rule reload &");
			LOG_INFO("netlink connect success");
		}
	}

	if (g_feature_update == 1 && appfilter_nl_fd.fd > 0) {
		if (reload_feature() == 0) g_feature_update = 0;
	}

	count++;
	uloop_timeout_set(t, TICK_INTERVAL_MS);
}

static struct uloop_timeout dev_tm = {
	.cb = oaf_timeout_handler,
};

static void af_load_engine(void)
{
	if (g_af_config.global.auto_load_engine != 1) {
		LOG_INFO("auto load disabled, not load oaf.ko");
		return;
	}

	if (access("/lib/modules/oaf.ko", F_OK) == 0) {
		(void)system("insmod /lib/modules/oaf.ko");
		LOG_INFO("insmod /lib/modules/oaf.ko");
	} else {
		(void)system("modprobe oaf");
		LOG_INFO("modprobe oaf");
	}
}

static void handle_sigusr1(int sig)
{
	(void)sig;
	LOG_INFO("Received SIGUSR1 signal");
	g_feature_update = 1;
	g_oaf_config_change = 1;
}

static void handle_sigusr2(int sig)
{
	(void)sig;
	if (get_current_log_level() == LOG_LEVEL_DEBUG)
		set_current_log_level(LOG_LEVEL_ERROR);
	else
		set_current_log_level(LOG_LEVEL_DEBUG);

	fprintf(stderr, "[appfilter] SIGUSR2: log level -> %d\n",
		get_current_log_level());
}

int main(void)
{
	LOG_INFO("appfilter start");
	g_feature_update = 1;
	af_load_config(&g_af_config);
	af_load_engine();
	af_init_time_status();

	uloop_init();
	signal(SIGUSR1, handle_sigusr1);
	signal(SIGUSR2, handle_sigusr2);
	signal(SIGCHLD, SIG_IGN);

	init_dev_node_htable();
	load_user_time_from_file();
	check_all_users_period_time();

	if (appfilter_ubus_init() < 0) {
		LOG_ERROR("Failed to connect to ubus");
		return 1;
	}

	appfilter_nl_fd.fd = -1;
	uloop_timeout_set(&dev_tm, INITIAL_TICK_MS);
	uloop_run();
	uloop_done();
	
	return 0;
}
