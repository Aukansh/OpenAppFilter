// SPDX-License-Identifier: MIT
/*
 * Minimal regexp matcher used by OAF DPI URL rules.
 *
 * Supported syntax:
 *   chars, '.', '^', '$', '*', '+', '?', '[...]', '[^...]',
 *   '\d', '\D'
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include "regexp.h"

#define MATCH_ONE(reg, text) \
	((reg)->type == DOT || in_list(*(text), (reg)) || *(text) == (reg)->ch)
#define MATCH_ONE_P(reg, text) \
	(in_list(*(text)++, (reg)) || *((text) - 1) == (reg)->ch || \
	 (reg)->type == DOT)

static int matchhere(struct regexp_re *regexp, char *text);

static void *getmem(size_t size)
{
	void *tmp;

	tmp = kmalloc(size, GFP_ATOMIC);
	if (!tmp) {
		printk("malloc failed\n");
		return NULL;
	}
	return tmp;
}

static size_t creat_list(char *str, int start, int end)
{
	size_t cnt = end - start + 1;

	for (; start <= end; start++)
		*str++ = start;
	return (cnt > 0) ? cnt : 0;
}

static int in_list(char ch, struct regexp_re *regexp)
{
	char *str = regexp->ccl;

	if (regexp->type != LIST)
		return 0;
	for (; *str && ch != *str; str++)
		;
	return (*str != '\0') ^ regexp->nccl;
}

void regexp_free(struct regexp_re *regexp)
{
	struct regexp_re *tmp;

	for (; regexp; regexp = tmp) {
		tmp = regexp->next;
		if (regexp->ccl)
			kfree(regexp->ccl);
		kfree(regexp);
	}
}

struct regexp_re *regexp_compile(char *regexp)
{
	struct regexp_re head, *tail, *tmp;
	char *pstr;
	int err_flag = 0;

	for (tail = &head; *regexp != '\0' && err_flag == 0; regexp++) {
		if (tail == &head && (*regexp == '*' || *regexp == '+' || *regexp == '?')) {
			return NULL;
		}
		tmp = getmem(sizeof(struct regexp_re));
		if (!tmp) {
			err_flag = 1;
			break;
		}

		switch (*regexp) {
		case '\\':
			regexp++;
			if (*regexp == 'd') {
				tmp->type = LIST;
				tmp->nccl = 0;
				tmp->ccl = getmem(11);
				if (!tmp->ccl) {
					err_flag = 1;
					break;
				}
				creat_list(tmp->ccl, '0', '9');
				tmp->ccl[10] = '\0';
			} else if (*regexp == 'D') {
				tmp->type = LIST;
				tmp->nccl = 1;
				tmp->ccl = getmem(11);
				if (!tmp->ccl) {
					err_flag = 1;
					break;
				}
				creat_list(tmp->ccl, '0', '9');
				tmp->ccl[10] = '\0';
			} else {
				tmp->type = CHAR;
				tmp->ch = *regexp;
			}
			break;
		case '.':
			tmp->type = DOT;
			break;
		case '^':
			tmp->type = BEGIN;
			tmp->ch = '^';
			break;
		case '$':
			tmp->type = END;
			tmp->ch = '$';
			break;
		case '*':
			tmp->type = STAR;
			break;
		case '+':
			tmp->type = PLUS;
			break;
		case '?':
			tmp->type = QUES;
			break;
		case '[':
			pstr = tmp->ccl = getmem(256);
			if (!tmp->ccl) {
				err_flag = 1;
				break;
			}
			tmp->nccl = 0;
			if (*++regexp == '^') {
				tmp->nccl = 1;
				regexp++;
			}
			while (*regexp != '\0' && *regexp != ']') {
				if (*regexp != '-') {
					if (pstr >= tmp->ccl + 255) {
						err_flag = 1;
						break;
					}
					*pstr++ = *regexp++;
					continue;
				}
				if (pstr == tmp->ccl || *(regexp + 1) == ']') {
					err_flag = 1;
					break;
				}
				if (pstr + (*(regexp + 1) - *(regexp - 1)) >= tmp->ccl + 255) {
					err_flag = 1;
					break;
				}
				pstr += creat_list(pstr, *(regexp - 1) + 1,
						   *(regexp + 1));
				regexp += 2;
			}
			*pstr = '\0';
			if (*regexp == '\0')
				err_flag = 1;
			tmp->type = LIST;
			break;
		default:
			tmp->type = CHAR;
			tmp->ch = *regexp;
		}

		if (err_flag) {
			break;
		}
		tail->next = tmp;
		tail = tmp;
	}

	tail->next = NULL;
	if (err_flag) {
		if (tmp) {
			if (tmp->ccl)
				kfree(tmp->ccl);
			kfree(tmp);
		}
		regexp_free(head.next);
		return NULL;
	}

	return head.next;
}

static int matchstar(struct regexp_re *cur, struct regexp_re *regexp, char *text)
{
	do {
		if (matchhere(regexp, text))
			return 1;
	} while (*text != '\0' && MATCH_ONE_P(cur, text));

	return 0;
}

static int matchplus(struct regexp_re *cur, struct regexp_re *regexp, char *text)
{
	while (*text != '\0' && MATCH_ONE_P(cur, text)) {
		if (matchhere(regexp, text))
			return 1;
	}

	return 0;
}

static int matchques(struct regexp_re *cur, struct regexp_re *regexp, char *text)
{
	if (*text != '\0' && MATCH_ONE(cur, text)) {
		if (matchhere(regexp, text + 1))
			return 1;
	}

	return matchhere(regexp, text);
}

static int matchhere(struct regexp_re *regexp, char *text)
{
	if (!regexp)
		return 1;
	if (regexp->type == END && regexp->next == NULL)
		return *text == '\0';
		
	if (regexp->next) {
		switch (regexp->next->type) {
		case STAR:
			return matchstar(regexp, regexp->next->next, text);
		case PLUS:
			return matchplus(regexp, regexp->next->next, text);
		case QUES:
			return matchques(regexp, regexp->next->next, text);
		default:
			break;
		}
	}

	if (*text != '\0' && MATCH_ONE(regexp, text))
		return matchhere(regexp->next, text + 1);

	return 0;
}

int regexp_match_compiled(struct regexp_re *regexp, char *text)
{
	int ret;

	if (!regexp)
		return 0;

	if (regexp->type == BEGIN) {
		return matchhere(regexp->next, text);
	}

	do {
		ret = matchhere(regexp, text);
		if (ret)
			return ret;
	} while (*text++ != '\0');

	return 0;
}

int regexp_match(char *reg, char *text)
{
	struct regexp_re *regexp = regexp_compile(reg);
	int ret = 0;
	
	if (regexp) {
		ret = regexp_match_compiled(regexp, text);
		regexp_free(regexp);
	}
	return ret;
}
