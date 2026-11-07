/* SPDX-License-Identifier: MIT */
#ifndef __AF_UTILS_H__
#define __AF_UTILS_H__

#include <linux/types.h>

u32 af_get_timestamp_sec(void);
char *k_trim(char *s);
int k_sscanf(const char *buf, const char *fmt, ...);
int k_atoi(const char *str);
int hash_mac(unsigned char *mac);
int mac_to_hex(u8 *mac, u8 *mac_hex);
void dump_str(char *name, unsigned char *p, int len);

#endif /* __AF_UTILS_H__ */
