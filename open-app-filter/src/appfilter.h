/* SPDX-License-Identifier: MIT */
#ifndef _APPFILTER_H
#define _APPFILTER_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "utils.h"

#define LOG_FILE_PATH			"/tmp/log/appfilter.log"
#define OAF_VERSION			"6.2.0"
#define AF_CMD_SET_BLOCKED_MAC_LIST	6

#define MAX_TIME_LIST_LEN		1024
#define MAX_TIME_LIST			64

typedef enum {
	LOG_LEVEL_ERROR,
	LOG_LEVEL_WARN,
	LOG_LEVEL_INFO,
	LOG_LEVEL_DEBUG,
} log_level_t;

extern int current_log_level;

#define LOG_DEBUG(fmt, ...)	af_log(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)	af_log(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)	af_log(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)	af_log(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)

typedef struct af_time {
	int hour;
	int min;
} af_time_t;

typedef struct af_global_config {
	int enable;
	int user_mode;
	int work_mode;
	int record_enable;
	int disable_hnat;
	int auto_load_engine;
	int tcp_rst;
	int disable_quic;
	int app_filter_mode;	/* 0 = specified apps, 1 = all apps */
	int daily_limit_mode;	/* 0 = shared, 1 = per-device */
	char lan_ifname[16];
} af_global_config_t;

typedef struct time_config {
	af_time_t start_time;
	af_time_t end_time;
	int days[7];
} time_config_t;

typedef struct daily_limit_config {
	int enable;
	int am_time;
	int pm_time;
} daily_limit_config_t;

typedef struct af_time_config {
	int time_mode;
	time_config_t seg_time;
	int deny_time;
	int allow_time;
	int days[7];
	int time_num;
	time_config_t time_list[MAX_TIME_LIST];
	daily_limit_config_t daily_limit[7];
} af_time_config_t;

typedef struct af_config {
	af_global_config_t global;
	af_time_config_t time;
} af_config_t;

typedef struct af_run_time_status {
	int deny_time;
	int allow_time;
	int filter;
	int match_time;
	int remain_time;
	int used_time;
	int period_blocked;
} af_run_time_status_t;

void af_log(log_level_t level, const char *fmt, ...);
void sync_blocked_macs_to_kernel(void);

extern af_config_t g_af_config;
extern af_run_time_status_t g_af_status;
extern int g_feature_update_time;
extern int g_oaf_config_change;

#endif
