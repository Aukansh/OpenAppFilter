// SPDX-License-Identifier: MIT
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <net/ip.h>
#include <linux/etherdevice.h>

#include "app_filter.h"
#include "af_client.h"
#include "af_log.h"
#include "af_utils.h"
#include "cJSON.h"

DEFINE_RWLOCK(af_client_lock);
struct list_head af_client_list_table[MAX_AF_CLIENT_HASH_SIZE];
static u32 total_client;

#define MAX_EXPIRED_VISIT_INFO_COUNT	10

static void init_client_timer(af_client_info_t *client);
static void stop_client_timer(af_client_info_t *client);

static void nf_client_list_init(void)
{
	int i;

	AF_CLIENT_LOCK_W();
	for (i = 0; i < MAX_AF_CLIENT_HASH_SIZE; i++)
		INIT_LIST_HEAD(&af_client_list_table[i]);
	AF_CLIENT_UNLOCK_W();
	AF_INFO("client list init......ok\n");
}

static void nf_client_list_clear(void)
{
	int i;
	af_client_info_t *p = NULL;
	LIST_HEAD(pending);
	char mac_str[32] = {0};

	AF_DEBUG("clean list\n");
	AF_CLIENT_LOCK_W();
	for (i = 0; i < MAX_AF_CLIENT_HASH_SIZE; i++) {
		while (!list_empty(&af_client_list_table[i])) {
			p = list_first_entry(&af_client_list_table[i],
					     af_client_info_t, hlist);
			list_del(&p->hlist);
			list_add_tail(&p->hlist, &pending);
		}
	}
	total_client = 0;
	AF_CLIENT_UNLOCK_W();

	/*
	 * del_timer_sync() may sleep, so it must not be called with the
	 * write lock held.
	 */
	while (!list_empty(&pending)) {
		p = list_first_entry(&pending, af_client_info_t, hlist);
		list_del(&p->hlist);
		memset(mac_str, 0, sizeof(mac_str));
		sprintf(mac_str, MAC_FMT, MAC_ARRAY(p->mac));
		AF_DEBUG("clean mac:%s\n", mac_str);
		stop_client_timer(p);
		kfree(p);
	}
}

void af_client_list_reset_report_num(void)
{
	int i;
	af_client_info_t *node = NULL;

	AF_CLIENT_LOCK_W();
	for (i = 0; i < MAX_AF_CLIENT_HASH_SIZE; i++) {
		list_for_each_entry(node, &af_client_list_table[i], hlist)
			node->report_count = 0;
	}
	AF_CLIENT_UNLOCK_W();
}

static int get_mac_hash_code(unsigned char *mac)
{
	if (!mac)
		return 0;
	return mac[5] & (MAX_AF_CLIENT_HASH_SIZE - 1);
}

af_client_info_t *find_af_client(unsigned char *mac)
{
	af_client_info_t *node;
	unsigned int index;

	index = get_mac_hash_code(mac);
	list_for_each_entry(node, &af_client_list_table[index], hlist) {
		if (!memcmp(node->mac, mac, 6))
			return node;
	}
	return NULL;
}

af_client_info_t *find_and_add_af_client(unsigned char *mac)
{
	af_client_info_t *nfc;

	nfc = find_af_client(mac);
	if (!nfc)
		nfc = nf_client_add(mac);
	return nfc;
}

af_client_info_t *find_af_client_by_ip(unsigned int ip)
{
	af_client_info_t *node;
	int i;

	for (i = 0; i < MAX_AF_CLIENT_HASH_SIZE; i++) {
		list_for_each_entry(node, &af_client_list_table[i], hlist) {
			if (node->ip == ip) {
				AF_LMT_DEBUG("match node->ip=%pI4, ip=%pI4\n",
					     &node->ip, &ip);
				return node;
			}
		}
	}
	return NULL;
}

af_client_info_t *find_af_client_by_ipv6(struct in6_addr *ipv6)
{
	af_client_info_t *node;
	int i;
	char addr_str[64] = {0};

	for (i = 0; i < MAX_AF_CLIENT_HASH_SIZE; i++) {
		list_for_each_entry(node, &af_client_list_table[i], hlist) {
			if (ipv6_addr_equal(&node->ipv6, ipv6)) {
				AF_INFO("match node->ipv6=%s\n",
					ipv6_to_str(&node->ipv6, addr_str));
				return node;
			}
		}
	}
	return NULL;
}

af_client_info_t *nf_client_add(unsigned char *mac)
{
	af_client_info_t *node;
	int index;

	node = kmalloc(sizeof(*node), GFP_ATOMIC);
	if (!node) {
		AF_ERROR("kmalloc failed\n");
		return NULL;
	}

	memset(node, 0, sizeof(*node));
	memcpy(node->mac, mac, MAC_ADDR_LEN);

	node->create_jiffies = jiffies;
	node->update_jiffies = jiffies;
	index = get_mac_hash_code(mac);

	AF_LMT_INFO("new client mac=" MAC_FMT "\n", MAC_ARRAY(node->mac));
	total_client++;
	init_client_timer(node);
	list_add(&node->hlist, &af_client_list_table[index]);
	return node;
}

void check_client_expire(void)
{
	af_client_info_t *node;
	af_client_info_t *victim = NULL;
	int i;

	AF_CLIENT_LOCK_W();
	for (i = 0; i < MAX_AF_CLIENT_HASH_SIZE; i++) {
		list_for_each_entry(node, &af_client_list_table[i], hlist) {
			AF_DEBUG("mac:" MAC_FMT " update:%lu interval:%lu\n",
				 MAC_ARRAY(node->mac), node->update_jiffies,
				 (jiffies - node->update_jiffies) / HZ);
			if (jiffies > node->update_jiffies + MAX_CLIENT_ACTIVE_TIME * HZ) {
				victim = node;
				break;
			}
		}
		if (victim)
			break;
	}
	if (victim) {
		list_del(&victim->hlist);
		if (total_client)
			total_client--;
	}
	AF_CLIENT_UNLOCK_W();

	/* del_timer_sync() must run outside the write lock. */
	if (victim) {
		AF_INFO("del client:" MAC_FMT "\n", MAC_ARRAY(victim->mac));
		stop_client_timer(victim);
		kfree(victim);
	}
}

static void flush_expired_visit_info(af_client_info_t *node)
{
	int i;
	int count = 0;
	u32 cur_timep;
	int timeout;

	cur_timep = af_get_timestamp_sec();
	for (i = 0; i < MAX_RECORD_APP_NUM; i++) {
		if (node->visit_info[i].app_id == 0)
			return;
	}

	for (i = 0; i < MAX_RECORD_APP_NUM; i++) {
		if (count >= MAX_EXPIRED_VISIT_INFO_COUNT)
			break;

		if (node->visit_info[i].total_num > 3)
			timeout = 180;
		else
			timeout = 60;

		if (cur_timep - node->visit_info[i].latest_time > timeout) {
			memset(&node->visit_info[i], 0, sizeof(app_visit_info_t));
			count++;
		}
	}
}

static int af_client_report_visit_info(af_client_info_t *node)
{
	unsigned char mac_str[32] = {0};
	unsigned char ip_str[32] = {0};
	int i;
	int count = 0;
	char *out = NULL;
	cJSON *visit_obj = NULL;
	cJSON *visit_info_array = NULL;
	cJSON *root_obj = NULL;

	flush_expired_visit_info(node);

	root_obj = cJSON_CreateObject();
	if (!root_obj) {
		AF_ERROR("create json obj failed\n");
		memset(&node->period_flow, 0, sizeof(node->period_flow));
		return 0;
	}

	sprintf(mac_str, MAC_FMT, MAC_ARRAY(node->mac));
	sprintf(ip_str, "%pI4", &node->ip);
	cJSON_AddStringToObject(root_obj, "mac", mac_str);
	cJSON_AddStringToObject(root_obj, "ip", ip_str);
	cJSON_AddNumberToObject(root_obj, "app_num", node->visit_app_num);
	cJSON_AddNumberToObject(root_obj, "up_flow", (u32)(node->period_flow.up_bytes >> 10));
	cJSON_AddNumberToObject(root_obj, "down_flow", (u32)(node->period_flow.down_bytes >> 10));
	cJSON_AddNumberToObject(root_obj, "active", node->active);

	visit_info_array = cJSON_CreateArray();
	for (i = 0; i < MAX_RECORD_APP_NUM; i++) {
		if (node->visit_info[i].app_id == 0)
			continue;

		count++;
		visit_obj = cJSON_CreateObject();
		cJSON_AddNumberToObject(visit_obj, "appid", node->visit_info[i].app_id);
		cJSON_AddNumberToObject(visit_obj, "latest_action", node->visit_info[i].latest_action);
		memset(&node->visit_info[i], 0, sizeof(app_visit_info_t));
		cJSON_AddItemToArray(visit_info_array, visit_obj);
	}

	cJSON_AddItemToObject(root_obj, "visit_info", visit_info_array);
	out = cJSON_Print(root_obj);
	if (!out) {
		cJSON_Delete(root_obj);
		memset(&node->period_flow, 0, sizeof(node->period_flow));
		return 0;
	}
	cJSON_Minify(out);

	AF_INFO("report:%s count=%d\n", out, node->report_count);
	node->report_count++;
	af_send_msg_to_user(out, strlen(out));
	cJSON_Delete(root_obj);

	memset(&node->period_flow, 0, sizeof(node->period_flow));
	kfree(out);
	return 0;
}

static inline int get_packet_dir(struct net_device *in)
{
	if (g_lan_ifname[0] == '\0')
		return PKT_DIR_DOWN;

	if (!strcmp(in->name, g_lan_ifname))
		return PKT_DIR_UP;

	return PKT_DIR_DOWN;
}

static void af_update_client_status(af_client_info_t *node)
{
	if (node->last_flow.down_bytes > 0)
		node->period_flow.down_bytes += (node->flow.down_bytes - node->last_flow.down_bytes);

	if (node->last_flow.up_bytes > 0)
		node->period_flow.up_bytes += (node->flow.up_bytes - node->last_flow.up_bytes);

	AF_LMT_DEBUG("period flow down:%llu up: %llu pkg up %d\n",
		     node->period_flow.down_bytes, node->period_flow.up_bytes,
		     node->rate.pkt_up_rate);

	/* 2s */
	node->rate.up_rate = (node->flow.up_bytes - node->last_flow.up_bytes) >> 1;
	node->rate.down_rate = (node->flow.down_bytes - node->last_flow.down_bytes) >> 1;
	node->rate.pkt_up_rate = (node->flow.up_pkts - node->last_flow.up_pkts) >> 1;
	node->rate.pkt_down_rate = (node->flow.down_pkts - node->last_flow.down_pkts) >> 1;

	node->last_flow.up_bytes = node->flow.up_bytes;
	node->last_flow.down_bytes = node->flow.down_bytes;
	node->last_flow.up_pkts = node->flow.up_pkts;
	node->last_flow.down_pkts = node->flow.down_pkts;

	if (node->rate.pkt_down_rate > 10 || node->rate.pkt_up_rate > 5) {
		node->active_time++;
		node->inactive_time = 0;
		node->active = 1;
	} else {
		node->inactive_time++;
		node->active_time = 0;
		if (node->active && node->inactive_time > 30)
			node->active = 0;
	}
}

static u32 af_client_hook(void *priv, struct sk_buff *skb,
			  const struct nf_hook_state *state)
{
	struct ethhdr *ethhdr = NULL;
	unsigned char smac[ETH_ALEN];
	af_client_info_t *nfc = NULL;
	int pkt_dir;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	enum ip_conntrack_info ctinfo;

	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return NF_ACCEPT;
	if (skb->protocol == htons(ETH_P_IPV6) && AF_MODE_GATEWAY != af_work_mode)
		return NF_ACCEPT;

	if (!skb->dev)
		return NF_ACCEPT;

	pkt_dir = get_packet_dir(skb->dev);
	if (PKT_DIR_UP != pkt_dir)
		return NF_ACCEPT;

	ethhdr = eth_hdr(skb);
	if (ethhdr)
		memcpy(smac, ethhdr->h_source, ETH_ALEN);
	else
		memcpy(smac, &skb->cb[40], ETH_ALEN);

	AF_CLIENT_LOCK_W();
	nfc = find_af_client(smac);
	if (!nfc) {
		if (skb->dev)
			AF_DEBUG("from dev:%s\n", skb->dev->name);
		nfc = nf_client_add(smac);
	}

	if (nfc) {
		if (skb->protocol == htons(ETH_P_IP)) {
			iph = ip_hdr(skb);
			if (iph && nfc->ip != iph->saddr) {
				AF_DEBUG("update node " MAC_FMT " ipv4 %pI4--->%pI4\n",
					 MAC_ARRAY(nfc->mac), &nfc->ip, &iph->saddr);
				nfc->ip = iph->saddr;
			}
		} else if (skb->protocol == htons(ETH_P_IPV6)) {
			ip6h = ipv6_hdr(skb);
			if (ip6h && !ipv6_addr_equal(&nfc->ipv6, &ip6h->saddr))
				nfc->ipv6 = ip6h->saddr;
		}
		nfc->flow.up_bytes += skb->len;
		nfc->flow.up_pkts++;
	}
	AF_CLIENT_UNLOCK_W();

	return NF_ACCEPT;
}

static u32 af_client_hook2(void *priv, struct sk_buff *skb,
			   const struct nf_hook_state *state)
{
	af_client_info_t *nfc = NULL;
	int pkt_dir;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	enum ip_conntrack_info ctinfo;

	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return NF_ACCEPT;

	if (!skb->dev)
		return NF_ACCEPT;

	pkt_dir = get_packet_dir(skb->dev);
	if (PKT_DIR_DOWN != pkt_dir)
		return NF_ACCEPT;

	AF_CLIENT_LOCK_W();
	if (skb->protocol == htons(ETH_P_IP)) {
		iph = ip_hdr(skb);
		nfc = find_af_client_by_ip(iph->daddr);
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		ip6h = ipv6_hdr(skb);
		nfc = find_af_client_by_ipv6(&ip6h->daddr);
		if (nfc)
			AF_LMT_DEBUG("found ipv6 %pI6 client\n", &ip6h->daddr);
		else
			AF_LMT_DEBUG("not found ipv6 %pI6 client\n", &ip6h->daddr);
	}

	if (nfc) {
		nfc->flow.down_bytes += skb->len;
		nfc->flow.down_pkts++;
	}
	AF_CLIENT_UNLOCK_W();

	return NF_ACCEPT;
}

static struct nf_hook_ops af_client_ops[] = {
	{
		.hook		= af_client_hook,
		.pf		= NFPROTO_INET,
		.hooknum	= NF_INET_FORWARD,
		.priority	= NF_IP_PRI_FIRST + 1,
	},
	{
		.hook		= af_client_hook2,
		.pf		= NFPROTO_INET,
		.hooknum	= NF_INET_FORWARD,
		.priority	= NF_IP_PRI_LAST - 1,
	},
};

static void client_timer_handler(struct timer_list *t)
{
	af_client_info_t *client = from_timer(client, t, client_timer);

	if (!client) {
		AF_ERROR("client timer handler: invalid client\n");
		return;
	}

	AF_CLIENT_LOCK_W();
	if (!find_af_client(client->mac)) {
		AF_CLIENT_UNLOCK_W();
		return;
	}

	if (client->timer_count >= 30) {
		af_client_report_visit_info(client);
		client->timer_count = 0;
	}

	af_update_client_status(client);
	client->timer_count++;
	AF_CLIENT_UNLOCK_W();
	mod_timer(&client->client_timer, jiffies + HZ * 2);
}

static void init_client_timer(af_client_info_t *client)
{
	if (!client) {
		AF_ERROR("init_client_timer: invalid client\n");
		return;
	}

	timer_setup(&client->client_timer, client_timer_handler, 0);
	mod_timer(&client->client_timer, jiffies + HZ * 1);
}

static void stop_client_timer(af_client_info_t *client)
{
	if (!client) {
		AF_ERROR("stop_client_timer: invalid client\n");
		return;
	}
	del_timer_sync(&client->client_timer);
}

int af_client_init(void)
{
	int err;

	nf_client_list_init();
	err = nf_register_net_hooks(&init_net, af_client_ops, ARRAY_SIZE(af_client_ops));
	if (err)
		AF_ERROR("oaf register client hooks failed!\n");

	AF_INFO("init app afclient ........ok\n");
	return 0;
}

void af_client_exit(void)
{
	nf_unregister_net_hooks(&init_net, af_client_ops, ARRAY_SIZE(af_client_ops));
	nf_client_list_clear();
}
