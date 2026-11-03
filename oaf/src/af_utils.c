#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/version.h>
#include "af_utils.h"
#define MAX_DUMP_STR_LEN 256

u_int32_t af_get_timestamp_sec(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
	struct timespec64 ts;
	ktime_get_real_ts64(&ts);
	return (u_int32_t)ts.tv_sec;
#else
	struct timespec ts;
	ts = current_kernel_time();
	return ts.tv_sec;
#endif

}

int k_atoi(const char *str) {
	int result = 0;

	// Skip whitespace
	while (*str == ' ' || *str == '\t') {
		str++;
	}

	// Convert characters to integer
	while (*str >= '0' && *str <= '9') {
		result = result * 10 + (*str - '0');
		str++;
	}

	return result;
}

char *k_trim(char *s)
{
	char *start, *last, *bk;
	int len;
	size_t n;

	if (!s)
		return s;

	n = strlen(s);
	if (n == 0)
		return s;

	start = s;
	while (isspace(*start))
		start++;

	bk = last = s + n - 1;
	while (last > start && isspace(*last))
		last--;

	if ((s != start) || (bk != last)) {
		len = (int)(last - start + 1);
		strncpy(s, start, len);
		s[len] = '\0';
	}
	return s;
}

void dump_str(char *name, unsigned char *p, int len)
{
	char buf[MAX_DUMP_STR_LEN] = {0};
	if (len > MAX_DUMP_STR_LEN) {
		len = MAX_DUMP_STR_LEN - 1;
	}
	printk("%s: ",name);
	strncpy(buf, p, len);
	printk("[%s]\n", buf);
}

#ifndef TOLOWER
#define TOLOWER(x) ((x) | 0x20)
#endif

static long long k_simple_strtoll(const char *cp, char **endp, unsigned int base)
{
	if (*cp == '-')
		return -simple_strtoull(cp + 1, endp, base);

	return simple_strtoull(cp, endp, base);
}

static int skip_atoi(const char **s)
{
	int i=0;
	while (isdigit(**s))
		i = i*10 + *((*s)++) - '0';
	return i;
}

char *skip_spaces(const char *str)
{
	while (isspace(*str) && ((unsigned char )*str != 0xa0))
		++str;
	return (char *)str;
}

static int k_vsscanf(const char *buf, const char *fmt, va_list args)
{
	const char *str = buf;
	char *next;
	char digit;
	int num = 0;
	u8 qualifier;
	u8 base;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,22)
	int field_width;
#else 
	s16 field_width;
#endif
	bool is_sign;
	while (*fmt && *str) {
		if (isspace(*fmt)) {
			fmt = skip_spaces(++fmt);
			str = skip_spaces(str);
		}

		if (*fmt != '%' && *fmt) {
			if (*fmt++ != *str++)
				break;
			continue;
		}
		if (!*fmt)
			break;
		++fmt;

		if (*fmt == '*') {
			while (!isspace(*fmt) && *fmt != '%' && *fmt)
				fmt++;
			while (!isspace(*str) && *str)
				str++;
			continue;
		}
		field_width = -1;
		if (isdigit(*fmt))
			field_width = skip_atoi(&fmt);
		qualifier = -1;
		if (*fmt == 'h' || TOLOWER(*fmt) == 'l' ||
		    TOLOWER(*fmt) == 'z') {
			qualifier = *fmt++;
			if (unlikely(qualifier == *fmt)) {
				if (qualifier == 'h') {
					qualifier = 'H';
					fmt++;
				} else if (qualifier == 'l') {
					qualifier = 'L';
					fmt++;
				}
			}
		}
		if (!*fmt || !*str)
			break;
		base = 10;
		is_sign = 0;
		switch (*fmt++) {
		case 'c':
		{
			char *s = (char *)va_arg(args, char*);
			if (field_width == -1)
				field_width = 1;
			do {
				*s++ = *str++;
			} while (--field_width > 0 && *str);
			num++;
		}
		continue;
		case 's':
		{
			char *s = (char *)va_arg(args, char *);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,22)
			if(field_width == -1)
				field_width = INT_MAX;
#else
			if (field_width == -1)
				field_width = SHRT_MAX;
#endif
			str = skip_spaces(str);

			while (*str && (!isspace(*str)  || ((unsigned char )*str == 0xA0) )&& field_width--)
				*s++ = *str++;
			*s = '\0';
			num++;
		}
		continue;
		case 'n':
		{
			int *i = (int *)va_arg(args, int*);
			*i = str - buf;
		}
		continue;
		case 'o':
			base = 8;
			break;
		case 'x':
		case 'X':
			base = 16;
			break;
		case 'i':
			base = 0;
			fallthrough;
		case 'd':
			is_sign = 1;
			fallthrough;
		case 'u':
			break;
		case '%':
			if (*str++ != '%')
				return num;
			continue;
		default:
			return num;
		}
		str = skip_spaces(str);
		digit = *str;
		if (is_sign && digit == '-')
			digit = *(str + 1);
		if (!digit
		    || (base == 16 && !isxdigit(digit))
		    || (base == 10 && !isdigit(digit))
		    || (base == 8 && (!isdigit(digit) || digit > '7'))
		    || (base == 0 && !isdigit(digit)))
			break;

		switch (qualifier) {
		case 'H':	
			if (is_sign) {
				signed char *s = (signed char *)va_arg(args, signed char *);
				*s = (signed char)simple_strtol(str, &next, base);
			} else {
				unsigned char *s = (unsigned char *)va_arg(args, unsigned char *);
				*s = (unsigned char)simple_strtoul(str, &next, base);
			}
			break;
		case 'h':
			if (is_sign) {
				short *s = (short *)va_arg(args, short *);
				*s = (short)simple_strtol(str, &next, base);
			} else {
				unsigned short *s = (unsigned short *)va_arg(args, unsigned short *);
				*s = (unsigned short)simple_strtoul(str, &next, base);
			}
			break;
		case 'l':
			if (is_sign) {
				long *l = (long *)va_arg(args, long *);
				*l = simple_strtol(str, &next, base);
			} else {
				unsigned long *l = (unsigned long *)va_arg(args, unsigned long *);
				*l = simple_strtoul(str, &next, base);
			}
			break;
		case 'L':
			if (is_sign) {
				long long *l = (long long *)va_arg(args, long long *);
				*l = k_simple_strtoll(str, &next, base);
			} else {
				unsigned long long *l = (unsigned long long *)va_arg(args, unsigned long long *);
				*l = simple_strtoull(str, &next, base);
			}
			break;
		case 'Z':
		case 'z':
		{
			size_t *s = (size_t *)va_arg(args, size_t *);
			*s = (size_t)simple_strtoul(str, &next, base);
		}
		break;
		default:
			if (is_sign) {
				int *i = (int *)va_arg(args, int *);
				*i = (int)simple_strtol(str, &next, base);
			} else {
				unsigned int *i = (unsigned int *)va_arg(args, unsigned int*);
				*i = (unsigned int)simple_strtoul(str, &next, base);
			}
			break;
		}
		num++;
		if (!next)
			break;
		str = next;
	}
	if (*fmt == '%' && *(fmt + 1) == 'n') {
		int *p = (int *)va_arg(args, int *);
		*p = str - buf;
	}
	return num;
}


int k_sscanf(const char *buf, const char *fmt, ...)
{
	va_list args;
	int i;
	va_start(args, fmt);
	i = k_vsscanf(buf, fmt, args);
	va_end(args);
	return i;
}


int mac_to_hex(u8 *mac, u8 *mac_hex)
{
	u32 mac_tmp[6];
	int ret = 0, i = 0;

	if (!mac || !mac_hex) {
		return -1;
	}

	ret = sscanf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
				 (unsigned int *)&mac_tmp[0],
				 (unsigned int *)&mac_tmp[1],
				 (unsigned int *)&mac_tmp[2],
				 (unsigned int *)&mac_tmp[3],
				 (unsigned int *)&mac_tmp[4],
				 (unsigned int *)&mac_tmp[5]);
	if (6 != ret)
		return -1;
	for (i = 0; i < 6; i++) {
		mac_hex[i] = mac_tmp[i];
	}
	return 0;
}
