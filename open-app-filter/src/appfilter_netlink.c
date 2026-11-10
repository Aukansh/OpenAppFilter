/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <json-c/json.h>
#include <libubox/uloop.h>
#include <linux/netlink.h>

#include "appfilter.h"
#include "appfilter_config.h"
#include "appfilter_netlink.h"
#include "appfilter_user.h"
#include "utils.h"

#define MAX_NL_RCV_BUF_SIZE	4096
#define MAX_NL_MSG_LEN		1024
#define REPORT_INTERVAL_SECS	60
#define AF_FEATURE_GRACE_SEC	300
#define AF_MSG_MAGIC		0xa0b0c0d0

static void parse_visit_array(dev_node_t *node, struct json_object *visit_array,
			      uint32_t cur_time)
{
	int n = json_object_array_length(visit_array);
	int i;

	for (i = 0; i < n; i++) {
		struct json_object *v = json_object_array_get_idx(visit_array, i);
		struct json_object *appid_obj, *action_obj;
		visit_info_t *p;
		int appid, action, type, id, hash;

		appid_obj = json_object_object_get(v, "appid");
		action_obj = json_object_object_get(v, "latest_action");
		if (!appid_obj || !action_obj)
			continue;

		appid = json_object_get_int(appid_obj);
		action = json_object_get_int(action_obj);

		if (cur_time - g_feature_update_time < AF_FEATURE_GRACE_SEC) {
			if (!strlen(get_app_name_by_id(appid))) {
				LOG_DEBUG("ignore unknown appid %d", appid);
				continue;
			}
		}

		type = appid / 1000;
		id = appid % 1000;
		if (id <= 0 || type <= 0 || type > MAX_APP_TYPE ||
		    id > MAX_APP_ID_NUM)
			continue;

		node->stat[type - 1][id - 1].total_time += REPORT_INTERVAL_SECS;

		hash = appid & (MAX_VISIT_HASH_SIZE - 1);
		p = node->visit_htable[hash];
		while (p) {
			if (p->appid == appid &&
			    cur_time - p->latest_time < 300)
				break;
			p = p->next;
		}
		if (!p) {
			p = calloc(1, sizeof(*p));
			if (!p)
				continue;
			p->appid = appid;
			p->first_time = cur_time;
			p->next = node->visit_htable[hash];
			node->visit_htable[hash] = p;
		}
		p->action = action;
		p->latest_time = cur_time;
	}
}

void appfilter_nl_handler(struct uloop_fd *u, unsigned int ev)
{
	char buf[MAX_NL_RCV_BUF_SIZE];
	uint32_t cur_time = get_timestamp();
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg;
	struct nlmsghdr *h;
	struct af_msg_hdr *af_hdr;
	struct json_object *root, *visit_array;
	dev_node_t *node;
	char *kmsg, *kdata, *mac;
	size_t kdata_off;
	int ret;

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &nladdr;
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	do {
		ret = recvmsg(u->fd, &msg, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret <= 0)
		return;
	if (ret < (int)sizeof(struct nlmsghdr) || ret >= MAX_NL_RCV_BUF_SIZE) {
		LOG_WARN("netlink bad read: %d", ret);
		return;
	}
	buf[ret] = '\0';

	h = (struct nlmsghdr *)buf;
	if (h->nlmsg_len < sizeof(struct nlmsghdr) + sizeof(struct af_msg_hdr) ||
	    (int)h->nlmsg_len > ret) {
		LOG_WARN("netlink invalid nlmsg_len=%u (ret=%d)", h->nlmsg_len, ret);
		return;
	}

	kmsg = (char *)NLMSG_DATA(h);
	af_hdr = (struct af_msg_hdr *)kmsg;
	if (af_hdr->magic != AF_MSG_MAGIC) {
		LOG_WARN("netlink magic error 0x%x", af_hdr->magic);
		return;
	}
	if (af_hdr->len <= 0 || af_hdr->len >= MAX_OAF_NETLINK_MSG_LEN) {
		LOG_WARN("netlink data len error: %d", af_hdr->len);
		return;
	}

	kdata = kmsg + sizeof(struct af_msg_hdr);
	kdata_off = (size_t)(kdata - buf);
	if (kdata_off + (size_t)af_hdr->len >= sizeof(buf)) {
		LOG_WARN("netlink data offset overflow");
		return;
	}
	kdata[af_hdr->len] = '\0';

	root = json_tokener_parse(kdata);
	if (!root) {
		LOG_WARN("netlink parse json failed: %s", kdata);
		return;
	}
	LOG_DEBUG("netlink report %s", kdata);

	visit_array = NULL;
	{
		struct json_object *mac_obj = json_object_object_get(root, "mac");
		struct json_object *obj;

		if (!mac_obj)
			goto out;

		mac = (char *)json_object_get_string(mac_obj);
		node = find_dev_node(mac);
		if (!node) {
			node = add_dev_node(mac);
			if (!node)
				goto out;
		}

		obj = json_object_object_get(root, "ip");
		if (obj)
			snprintf(node->ip, sizeof(node->ip), "%s", json_object_get_string(obj));

		obj = json_object_object_get(root, "active");
		if (obj)
			node->active = json_object_get_int(obj);

		obj = json_object_object_get(root, "up_flow");
		if (obj)
			node->today_up_bytes += (uint64_t)json_object_get_int64(obj) * 1024;

		obj = json_object_object_get(root, "down_flow");
		if (obj)
			node->today_down_bytes += (uint64_t)json_object_get_int64(obj) * 1024;

		visit_array = json_object_object_get(root, "visit_info");
		if (visit_array)
			parse_visit_array(node, visit_array, cur_time);
	}
out:
	json_object_put(root);
}

int send_msg_to_kernel(int fd, void *msg, int len)
{
	char scratch[MAX_NL_MSG_LEN];
	struct sockaddr_nl dst;
	struct af_msg_hdr *hdr;
	struct nlmsghdr *nlh;
	char *data;
	int payload, ret;

	if (!msg || len <= 0 ||
	    len > MAX_NL_MSG_LEN - (int)sizeof(struct af_msg_hdr))
		return -1;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	dst.nl_pid = 0;

	payload = len + (int)sizeof(struct af_msg_hdr);
	nlh = malloc(NLMSG_SPACE(payload));
	if (!nlh)
		return -1;

	nlh->nlmsg_len = NLMSG_SPACE(payload);
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = 0;
	nlh->nlmsg_seq = 0;
	nlh->nlmsg_pid = DEFAULT_USR_NL_PID;

	hdr = (struct af_msg_hdr *)scratch;
	hdr->magic = AF_MSG_MAGIC;
	hdr->len = len;
	data = scratch + sizeof(struct af_msg_hdr);
	memcpy(data, msg, len);
	memcpy(NLMSG_DATA(nlh), scratch, payload);

	ret = sendto(fd, nlh, nlh->nlmsg_len, 0,
		     (struct sockaddr *)&dst, sizeof(dst));
	free(nlh);
	return ret < 0 ? -1 : 0;
}

int appfilter_nl_init(void)
{
	struct sockaddr_nl nls;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW, OAF_NETLINK_ID);
	if (fd < 0) {
		LOG_DEBUG("netlink socket failed: %s", strerror(errno));
		return -1;
	}

	memset(&nls, 0, sizeof(nls));
	nls.nl_pid = DEFAULT_USR_NL_PID;
	nls.nl_groups = 0;
	nls.nl_family = AF_NETLINK;

	if (bind(fd, (void *)&nls, sizeof(nls))) {
		LOG_DEBUG("netlink bind failed: %s", strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}
