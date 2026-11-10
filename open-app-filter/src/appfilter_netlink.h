/* SPDX-License-Identifier: MIT */
#ifndef _APPFILTER_NETLINK_H
#define _APPFILTER_NETLINK_H

struct uloop_fd;

#define DEFAULT_USR_NL_PID		999
#define OAF_NETLINK_ID			29
#define MAX_OAF_NETLINK_MSG_LEN		1024
#define MAX_FEATURE_LINE_LEN		600

struct af_msg_hdr {
	int magic;
	int len;
};

enum af_msg_type {
	AF_MSG_INIT,
	AF_MSG_ADD_FEATURE,
	AF_MSG_CLEAN_FEATURE,
	AF_MSG_MAX,
};

typedef struct af_msg {
	int action;
} af_msg_t;

typedef struct af_feature_msg {
	af_msg_t hdr;
	char feature[MAX_FEATURE_LINE_LEN];
} af_feature_msg_t;

int appfilter_nl_init(void);
void appfilter_nl_handler(struct uloop_fd *u, unsigned int ev);
int send_msg_to_kernel(int fd, void *msg, int len);

#endif /* _APPFILTER_NETLINK_H */
