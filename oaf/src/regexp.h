/* SPDX-License-Identifier: MIT */
#ifndef __REGEXP_H__
#define __REGEXP_H__

enum regexp_type {
	CHAR,
	DOT,
	BEGIN,
	END,
	STAR,
	PLUS,
	QUES,
	LIST,
	TYPENUM
};

struct regexp_re {
	enum regexp_type type;
	int ch;
	char *ccl;
	int nccl;
	struct regexp_re *next;
};

int regexp_match(char *reg, char *text);
struct regexp_re *regexp_compile(char *reg);
int regexp_match_compiled(struct regexp_re *regexp, char *text);
void regexp_free(struct regexp_re *regexp);

#endif /* __REGEXP_H__ */
