/* SPDX-License-Identifier: MIT */
#ifndef _APPFILTER_CONFIG_H
#define _APPFILTER_CONFIG_H

#include <uci.h>

#include "appfilter.h"

typedef struct app_name_info {
	int id;
	char name[64];
} app_name_info_t;

void init_app_name_table(void);
void init_app_class_name_table(void);
char *get_app_name_by_id(int id);

int get_class_count(void);
const char *get_class_name_by_id(int id);

int af_uci_delete(struct uci_context *ctx, const char *key);
int af_uci_add_list(struct uci_context *ctx, const char *key, const char *value);
int af_uci_add_int_list(struct uci_context *ctx, const char *key, int value);
int af_uci_get_list_value(struct uci_context *ctx, const char *key, char *out, int out_len, const char *delim);
int af_uci_set_value(struct uci_context *ctx, const char *key, const char *value);
int af_uci_set_int_value(struct uci_context *ctx, const char *key, int value);
int af_uci_get_int_value(struct uci_context *ctx, const char *key);
int af_uci_get_value(struct uci_context *ctx, const char *key, char *out, int out_len);
int af_uci_set_array_value(struct uci_context *ctx, const char *fmt, int index, const char *value);
int af_uci_get_array_value(struct uci_context *ctx, const char *fmt, int index, char *out, int out_len);
int af_uci_add_section(struct uci_context *ctx, const char *pkg, const char *section);
int af_uci_commit(struct uci_context *ctx, const char *package);
int af_get_uci_list_num(struct uci_context *ctx, const char *package, const char *section);

#endif /* _APPFILTER_CONFIG_H */
