/* SPDX-License-Identifier: MIT */
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "utils.h"

char *str_trim(char *s)
{
	char *start, *end;
	size_t len;

	if (!s)
		return NULL;

	start = s;
	while (isspace((unsigned char)*start))
		start++;

	end = start + strlen(start);
	while (end > start && isspace((unsigned char)*(end - 1)))
		end--;

	len = (size_t)(end - start);

	if (start != s) {
		memmove(s, start, len);
	}
	s[len] = '\0';

	return s;
}

int exec_with_result_line(const char *cmd, char *result, int len)
{
	FILE *fp;

	if (!cmd || !result || len <= 0)
		return -1;

	fp = popen(cmd, "r");
	if (!fp)
		return -1;

	if (!fgets(result, len, fp))
		result[0] = '\0';

	str_trim(result);
	(void)pclose(fp);
	
	return 0;
}

unsigned int get_timestamp(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (unsigned int)tv.tv_sec;
}

int af_read_file_value(const char *path, char *value, int len)
{
	FILE *file;
	size_t n;

	if (!path || !value || len <= 0)
		return -1;

	file = fopen(path, "r");
	if (!file)
		return -1;

	if (!fgets(value, (int)len, file)) {
		fclose(file);
		return -2;
	}

	n = strlen(value);
	if (n > 0 && value[n - 1] == '\n')
		value[n - 1] = '\0';

	fclose(file);
	return 0;
}
