// SPDX-License-Identifier: MIT
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>

#include "af_conntrack.h"
#include "af_log.h"

static struct hlist_head af_conn_table[AF_CONN_HASH_SIZE];
static DEFINE_SPINLOCK(af_conn_lock);
static LIST_HEAD(af_conn_pending_old);
static LIST_HEAD(af_conn_pending_new);

static u32 af_conn_hash(u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 protocol)
{
	return jhash_3words(src_ip, dst_ip, ((u32)protocol << 16) | src_port, dst_port) % AF_CONN_HASH_SIZE;
}

static void af_conn_cleanup(void)
{
	int i;
	af_conn_t *p;
	struct hlist_node *n;
	LIST_HEAD(to_free);

	spin_lock_bh(&af_conn_lock);
	for (i = 0; i < AF_CONN_HASH_SIZE; i++) {
		hlist_for_each_entry_safe(p, n, &af_conn_table[i], node) {
			hlist_del(&p->node);
			list_add_tail(&p->pending_node, &to_free);
		}
	}
	list_splice_init(&af_conn_pending_old, &to_free);
	list_splice_init(&af_conn_pending_new, &to_free);
	spin_unlock_bh(&af_conn_lock);
	while (!list_empty(&to_free)) {
		p = list_first_entry(&to_free, af_conn_t, pending_node);
		list_del(&p->pending_node);
		kfree(p);
	}
}

static af_conn_t *__af_conn_find(u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 protocol)
{
	u32 hash = af_conn_hash(src_ip, dst_ip, src_port, dst_port, protocol);
	af_conn_t *conn;

	hlist_for_each_entry(conn, &af_conn_table[hash], node) {
		if (conn->src_ip == src_ip && conn->dst_ip == dst_ip &&
		    conn->src_port == src_port && conn->dst_port == dst_port &&
		    conn->protocol == protocol)
			return conn;
	}
	return NULL;
}

static af_conn_t *__af_conn_add(u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 protocol)
{
	u32 hash = af_conn_hash(src_ip, dst_ip, src_port, dst_port, protocol);
	af_conn_t *conn;

	conn = kmalloc(sizeof(*conn), GFP_ATOMIC);
	if (!conn)
		return NULL;

	conn->src_ip = src_ip;
	conn->dst_ip = dst_ip;
	conn->src_port = src_port;
	conn->dst_port = dst_port;
	conn->protocol = protocol;
	conn->total_pkts = 0;
	conn->app_id = 0;
	conn->client_hello = 0;
	conn->drop = 0;
	conn->ignore = 0;
	conn->ver = 0;
	conn->state = AF_CONN_NEW;
	conn->last_jiffies = jiffies;
	INIT_LIST_HEAD(&conn->pending_node);
	hlist_add_head(&conn->node, &af_conn_table[hash]);
	return conn;
}

af_conn_t *af_conn_get_and_update(u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 protocol)
{
	af_conn_t *conn;

	spin_lock_bh(&af_conn_lock);
	
	conn = __af_conn_find(src_ip, dst_ip, src_port, dst_port, protocol);
	if (!conn)
		conn = __af_conn_add(src_ip, dst_ip, src_port, dst_port, protocol);

	if (conn) {
		conn->last_jiffies = jiffies;
		conn->total_pkts++;
	}
	
	spin_unlock_bh(&af_conn_lock);
	return conn;
}

void af_conn_update(af_conn_t *conn, u32 app_id, u8 drop, u8 ignore, u16 ver, af_conn_state_t state)
{
	if (!conn)
		return;

	spin_lock_bh(&af_conn_lock);
	conn->app_id = app_id;
	conn->drop = drop;
	conn->ignore = ignore;
	conn->ver = ver;
	conn->state = state;
	conn->last_jiffies = jiffies;
	spin_unlock_bh(&af_conn_lock);
}

#define MAX_AF_CONN_CHECK_COUNT 5

void af_conn_clean_timeout(void)
{
	int i;
	af_conn_t *conn;
	struct hlist_node *n;
	unsigned long timeout = AF_CONN_TIMEOUT * HZ;
	static int last_bucket = 0;
	int count = 0;
	LIST_HEAD(to_free);

	spin_lock_bh(&af_conn_lock);
	list_splice_init(&af_conn_pending_old, &to_free);
	spin_unlock_bh(&af_conn_lock);

	while (!list_empty(&to_free)) {
		conn = list_first_entry(&to_free, af_conn_t, pending_node);
		list_del(&conn->pending_node);
		kfree(conn);
	}

	spin_lock_bh(&af_conn_lock);
	list_splice_init(&af_conn_pending_new, &af_conn_pending_old);
	for (i = last_bucket; i < AF_CONN_HASH_SIZE; i++) {
		hlist_for_each_entry_safe(conn, n, &af_conn_table[i], node) {
			if (time_after(jiffies, conn->last_jiffies + timeout)) {
				hlist_del(&conn->node);
				list_add_tail(&conn->pending_node, &af_conn_pending_new);
			}
		}
		last_bucket = i;
		count++;
		if (count > MAX_AF_CONN_CHECK_COUNT)
			break;
		last_bucket = i + 1;
	}
	if (last_bucket >= AF_CONN_HASH_SIZE)
		last_bucket = 0;
	spin_unlock_bh(&af_conn_lock);
}

struct af_conn_iter_state {
	unsigned int bucket;
	int index;
};

static void *af_conn_seq_start(struct seq_file *s, loff_t *pos)
{
	struct af_conn_iter_state *st = s->private;
	struct hlist_node *node;
	loff_t n = *pos;

	spin_lock_bh(&af_conn_lock);
	if (n == 0)
		return SEQ_START_TOKEN;

	n--;
	for (st->bucket = 0; st->bucket < AF_CONN_HASH_SIZE; st->bucket++) {
		node = af_conn_table[st->bucket].first;
		while (node) {
			if (n == 0)
				return node;
			n--;
			node = node->next;
		}
	}
	return NULL;
}

static void *af_conn_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct af_conn_iter_state *st = s->private;
	struct hlist_node *node;

	(*pos)++;
	if (v == SEQ_START_TOKEN) {
		st->bucket = 0;
	} else {
		node = v;
		if (node->next)
			return node->next;
		st->bucket++;
	}

	while (st->bucket < AF_CONN_HASH_SIZE) {
		if (!hlist_empty(&af_conn_table[st->bucket]))
			return af_conn_table[st->bucket].first;
		st->bucket++;
	}
	return NULL;
}

static void af_conn_seq_stop(struct seq_file *s, void *v)
{
	spin_unlock_bh(&af_conn_lock);
}

static int af_conn_seq_show(struct seq_file *s, void *v)
{
	struct af_conn_iter_state *st = s->private;
	af_conn_t *node = v;
	char src_ip_str[32] = {0};
	char dst_ip_str[32] = {0};
	unsigned long inactive_time;

	if (v == SEQ_START_TOKEN) {
		st->index = 0;
		seq_printf(s, "%-4s %-20s %-20s %-12s %-12s %-12s %-12s %-12s %-12s %-12s\n",
			   "Id", "src_ip", "dst_ip", "src_port", "dst_port",
			   "protocol", "app_id", "drop", "inactive", "total_pkts");
		return 0;
	}

	st->index++;
	sprintf(src_ip_str, "%pI4", &node->src_ip);
	sprintf(dst_ip_str, "%pI4", &node->dst_ip);
	inactive_time = jiffies - node->last_jiffies;

	seq_printf(s, "%-4d %-20s %-20s %-12d %-12d %-12d %-12d %-12d %-12lu %-12d\n",
		   st->index, src_ip_str, dst_ip_str,
		   node->src_port, node->dst_port, node->protocol,
		   node->app_id, node->drop, inactive_time, node->total_pkts);
	return 0;
}

static const struct seq_operations af_conn_seq_ops = {
	.start	= af_conn_seq_start,
	.next	= af_conn_seq_next,
	.stop	= af_conn_seq_stop,
	.show	= af_conn_seq_show,
};

static int af_conn_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	struct af_conn_iter_state *iter;
	int err;

	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
	if (!iter)
		return -ENOMEM;

	err = seq_open(file, &af_conn_seq_ops);
	if (err) {
		kfree(iter);
		return err;
	}

	seq = file->private_data;
	seq->private = iter;
	return 0;
}

static const struct proc_ops af_conn_fops = {
	.proc_flags	= PROC_ENTRY_PERMANENT,
	.proc_read	= seq_read,
	.proc_open	= af_conn_open,
	.proc_lseek	= seq_lseek,
	.proc_release	= seq_release_private,
};

int af_conn_init(void)
{
	int i;

	for (i = 0; i < AF_CONN_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&af_conn_table[i]);

	proc_create("af_conn", 0644, init_net.proc_net, &af_conn_fops);
	return 0;
}

void af_conn_exit(void)
{
	remove_proc_entry("af_conn", init_net.proc_net);
	af_conn_cleanup();
}
