#ifndef __APPFILTER_H__
#define __APPFILTER_H__

#define MIN_INET_ADDR_LEN			7
#define AF_CMD_SET_BLOCKED_MAC_LIST	6

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <stdarg.h>
#include "utils.h"

#define LOG_FILE_PATH	"/tmp/log/appfilter.log"
#define OAF_VERSION		"6.1.8"

typedef enum {
	LOG_LEVEL_ERROR,
	LOG_LEVEL_WARN,
	LOG_LEVEL_INFO,
	LOG_LEVEL_DEBUG
} LogLevel;

extern int current_log_level;

static pthread_mutex_t af_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void af_log(LogLevel level, const char *format, ...)
{
	FILE *log_file;
	time_t now;
	struct tm *t;
	char time_str[20];
	const char *level_str;
	va_list args;

	if (level > current_log_level)
		return;

	pthread_mutex_lock(&af_log_mutex);
	log_file = fopen(LOG_FILE_PATH, "a");
	if (!log_file) {
		perror("Failed to open log file");
		pthread_mutex_unlock(&af_log_mutex);
		return;
	}

	now = time(NULL);
	t = localtime(&now);
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);

	switch (level) {
	case LOG_LEVEL_DEBUG:
		level_str = "DEBUG";
		break;
	case LOG_LEVEL_INFO:
		level_str = "INFO";
		break;
	case LOG_LEVEL_WARN:
		level_str = "WARN";
		break;
	case LOG_LEVEL_ERROR:
		level_str = "ERROR";
		break;
	default:
		level_str = "UNKNOWN";
		break;
	}

	fprintf(log_file, "[%s] [%s] ", time_str, level_str);

	va_start(args, format);
	vfprintf(log_file, format, args);
	va_end(args);

	fclose(log_file);
	pthread_mutex_unlock(&af_log_mutex);
}

#define LOG_DEBUG(format, ...)	af_log(LOG_LEVEL_DEBUG, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...)	af_log(LOG_LEVEL_INFO, format, ##__VA_ARGS__)
#define LOG_WARN(format, ...)	af_log(LOG_LEVEL_WARN, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...)	af_log(LOG_LEVEL_ERROR, format, ##__VA_ARGS__)

#define MAX_TIME_LIST_LEN	1024
#define MAX_TIME_LIST		64

typedef struct af_time {
	int hour;
	int min;
} af_time_t;

typedef struct af_global_config_t {
	int enable;
	int user_mode;
	int work_mode;
	int record_enable;
	int disable_hnat;
	int auto_load_engine;
	int tcp_rst;
	int disable_quic;
	int app_filter_mode;	/* 0 = specified apps, 1 = all apps */
	int daily_limit_mode;	/* 0 = share total time, 1 = independent per device */
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

typedef struct af_time_config_t {
	int time_mode;
	time_config_t seg_time;
	int deny_time;
	int allow_time;
	int days[7];
	int time_num;
	time_config_t time_list[MAX_TIME_LIST];
	daily_limit_config_t daily_limit[7];
} af_time_config_t;

typedef struct af_config_t {
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

void sync_blocked_macs_to_kernel(void);
extern af_config_t g_af_config;

#endif
