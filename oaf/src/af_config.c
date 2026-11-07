// SPDX-License-Identifier: MIT
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/version.h>

#include "cJSON.h"
#include "app_filter.h"
#include "af_config.h"
#include "af_utils.h"
#include "af_log.h"
#include "af_rule_config.h"
#include "af_user_config.h"
#include "af_whitelist_config.h"

#define AF_DEV_NAME "appfilter"
#define AF_MAX_CONFIG_SIZE (256 * 1024)

struct af_config_dev {
	dev_t id;
	struct cdev char_dev;
	struct class *c;
};

struct af_cdev_file {
	size_t size;
	size_t capacity;
	char *buf;
};

static struct mutex af_cdev_mutex;
static struct af_config_dev g_af_dev;

static struct af_config_interface af_config_interfaces[] = {
	{ AF_CMD_ADD_APPID, af_config_add_appid, "Add App ID" },
	{ AF_CMD_DEL_APPID, af_config_del_appid, "Delete App ID" },
	{ AF_CMD_CLEAN_APPID, af_config_clean_appid, "Clean App ID" },
	{ AF_CMD_SET_MAC_LIST, af_config_set_mac_list, "Set MAC List" },
	{ AF_CMD_SET_WHITELIST_MAC_LIST, af_config_set_whitelist_mac_list, "Set Whitelist MAC List" },
	{ AF_CMD_SET_BLOCKED_MAC_LIST, af_config_set_blocked_mac_list, "Set Blocked MAC List" },
	{ 0, NULL, NULL }
};

static af_config_handler_t af_find_handler(enum AF_CONFIG_CMD cmd)
{
	struct af_config_interface *interface = af_config_interfaces;

	while (interface->handler) {
		if (interface->cmd == cmd)
			return interface->handler;
		interface++;
	}
	return NULL;
}

static int af_config_handle(char *config, unsigned int len)
{
	cJSON *config_obj;
	cJSON *cmd_obj;
	cJSON *data_obj;
	int ret = 0;
	af_config_handler_t handler;

	if (!config || len == 0) {
		AF_ERROR("config or len is invalid\n");
		return -1;
	}

	AF_DEBUG("config = %s\n", config);
	config_obj = cJSON_Parse(config);
	if (!config_obj) {
		AF_ERROR("config_obj is NULL\n");
		return -1;
	}

	cmd_obj = cJSON_GetObjectItem(config_obj, "op");
	if (!cmd_obj) {
		AF_ERROR("not find op object\n");
		cJSON_Delete(config_obj);
		return -1;
	}

	data_obj = cJSON_GetObjectItem(config_obj, "data");

	handler = af_find_handler(cmd_obj->valueint);
	if (handler) {
		ret = handler(data_obj);
		atomic_inc(&g_filter_version);
	} else {
		AF_ERROR("invalid cmd %d\n", cmd_obj->valueint);
		ret = -1;
	}

	cJSON_Delete(config_obj);
	return ret;
}

static int af_cdev_open(struct inode *inode, struct file *filp)
{
	struct af_cdev_file *file;

	file = kzalloc(sizeof(*file), GFP_KERNEL);
	if (!file)
		return -ENOMEM;

	filp->private_data = file;
	return 0;
}

static ssize_t af_cdev_read(struct file *filp, char __user *buf,
			    size_t count, loff_t *off)
{
	return 0;
}

static int af_cdev_release(struct inode *inode, struct file *filp)
{
	struct af_cdev_file *file = filp->private_data;

	if (!file)
		return 0;

	if (file->size > 0) {
		AF_DEBUG("config size: %d, data = %s\n",
			 (int)file->size, file->buf);
		mutex_lock(&af_cdev_mutex);
		af_config_handle(file->buf, file->size);
		mutex_unlock(&af_cdev_mutex);
	}

	if (file->buf)
		kfree(file->buf);
	kfree(file);
	filp->private_data = NULL;
	return 0;
}

static ssize_t af_cdev_write(struct file *filp, const char __user *buffer,
			     size_t count, loff_t *off)
{
	struct af_cdev_file *file = filp->private_data;
	size_t new_cap;
	char *new_buf;

	if (!file)
		return -EINVAL;

	if (file->size + count > AF_MAX_CONFIG_SIZE) {
		AF_ERROR("config overflow, cur_size: %zu, block_size: %zu, max_size: %d\n",
			 file->size, count, AF_MAX_CONFIG_SIZE);
		return -EINVAL;
	}

	if (file->size + count + 1 > file->capacity) {
		new_cap = file->size + count + 1;
		if (new_cap < 4096)
			new_cap = 4096;
		else
			new_cap = roundup_pow_of_two(new_cap);

		new_buf = krealloc(file->buf, new_cap, GFP_KERNEL);
		if (!new_buf)
			return -ENOMEM;

		file->buf = new_buf;
		file->capacity = new_cap;
	}

	if (copy_from_user(file->buf + file->size, buffer, count))
		return -EFAULT;

	file->size += count;
	file->buf[file->size] = '\0';
	return count;
}

static const struct file_operations af_cdev_ops = {
	.owner		= THIS_MODULE,
	.open		= af_cdev_open,
	.release	= af_cdev_release,
	.write		= af_cdev_write,
	.read		= af_cdev_read,
};

int af_register_dev(void)
{
	struct device *dev;
	int res;

	mutex_init(&af_cdev_mutex);

	res = alloc_chrdev_region(&g_af_dev.id, 0, 1, AF_DEV_NAME);
	if (res != 0) {
		AF_ERROR("alloc_chrdev_region failed\n");
		return -EINVAL;
	}

	cdev_init(&g_af_dev.char_dev, &af_cdev_ops);
	res = cdev_add(&g_af_dev.char_dev, g_af_dev.id, 1);
	if (res < 0) {
		AF_ERROR("cdev_add failed\n");
		goto REGION_OUT;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	g_af_dev.c = class_create(THIS_MODULE, AF_DEV_NAME);
#else
	g_af_dev.c = class_create(AF_DEV_NAME);
#endif
	if (IS_ERR_OR_NULL(g_af_dev.c)) {
		AF_ERROR("class_create failed\n");
		goto CDEV_OUT;
	}

	dev = device_create(g_af_dev.c, NULL, g_af_dev.id, NULL, AF_DEV_NAME);
	if (IS_ERR_OR_NULL(dev)) {
		AF_ERROR("device_create failed\n");
		goto CLASS_OUT;
	}

	AF_INFO("register char dev....ok\n");
	return 0;

CLASS_OUT:
	class_destroy(g_af_dev.c);
CDEV_OUT:
	cdev_del(&g_af_dev.char_dev);
REGION_OUT:
	unregister_chrdev_region(g_af_dev.id, 1);
	return -EINVAL;
}

void af_unregister_dev(void)
{
	device_destroy(g_af_dev.c, g_af_dev.id);
	class_destroy(g_af_dev.c);
	cdev_del(&g_af_dev.char_dev);
	unregister_chrdev_region(g_af_dev.id, 1);
	AF_INFO("unregister char dev....ok\n");
}
