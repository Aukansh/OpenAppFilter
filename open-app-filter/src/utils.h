/* SPDX-License-Identifier: MIT */
#ifndef _APPFILTER_UTILS_H
#define _APPFILTER_UTILS_H

char *str_trim(char *s);

int exec_with_result_line(const char *cmd, char *result, int len);

int af_read_file_value(const char *path, char *value, int len);

unsigned int get_timestamp(void);

#endif /* _APPFILTER_UTILS_H */
