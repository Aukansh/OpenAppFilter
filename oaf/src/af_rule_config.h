/* SPDX-License-Identifier: MIT */
#ifndef __AF_RULE_CONFIG_H__
#define __AF_RULE_CONFIG_H__

#include "app_filter.h"
#include "cJSON.h"

#define AF_MAX_APP_TYPE_NUM	33
#define AF_MAX_APP_NUM		513

void af_init_app_status(void);
int af_get_app_status(int appid);

int af_config_add_appid(cJSON *data);
int af_config_del_appid(cJSON *data);
int af_config_clean_appid(cJSON *data);

#endif /* __AF_RULE_CONFIG_H__ */
