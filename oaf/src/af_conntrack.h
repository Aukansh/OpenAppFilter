/* SPDX-License-Identifier: MIT */
#ifndef __AF_CONNTRACK_H__
#define __AF_CONNTRACK_H__

#include <linux/types.h>
#include <linux/list.h>

#define AF_CONN_TIMEOUT		30
#define AF_CONN_HASH_SIZE	256

typedef enum {
	AF_CONN_NEW = 0,
	AF_CONN_ESTABLISHED,
	AF_CONN_DPI_FINISHED,
} af_conn_state_t;

typedef struct af_conn {
	struct hlist_node node;
	u32 src_ip;
	u32 dst_ip;
	u16 src_port;
	u16 dst_port;
	u8  protocol;
	u32 total_pkts;
	u32 app_id;
	u8  client_hello;
	u8  drop;
	u8  ignore;
	u16 ver;
	af_conn_state_t state;
	unsigned long last_jiffies;
	struct list_head pending_node;
} af_conn_t;

int af_conn_init(void);
void af_conn_exit(void);

af_conn_t *af_conn_get_and_update(u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 protocol);

void af_conn_update(af_conn_t *conn, u32 app_id, u8 drop, u8 ignore, u16 ver, af_conn_state_t state);

void af_conn_clean_timeout(void);

#endif /* __AF_CONNTRACK_H__ */
