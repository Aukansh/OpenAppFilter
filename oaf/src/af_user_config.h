/* SPDX-License-Identifier: MIT */
#ifndef __AF_USER_CONFIG_H__
#define __AF_USER_CONFIG_H__

#include "app_filter.h"
#include "af_utils.h"
#include "cJSON.h"

#define MAX_AF_MAC_HASH_SIZE 64

typedef struct af_mac_node {
	struct list_head list;
	unsigned char mac[MAC_ADDR_LEN];
} af_mac_node_t;

void af_mac_list_init(void);
void af_mac_list_flush(void);
af_mac_node_t *af_mac_find(unsigned char *mac);
af_mac_node_t *af_mac_add(unsigned char *mac);

int af_config_set_mac_list(cJSON *data_obj);

#endif /* __AF_USER_CONFIG_H__ */
