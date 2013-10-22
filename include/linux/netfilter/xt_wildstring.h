#ifndef _XT_WILDSTRING_H
#define _XT_WILDSTRING_H

#include <linux/types.h>

#define XT_WILDSTRING_MAX_PATTERN_SIZE 128
#define XT_WILDSTRING_MAX_ALGO_NAME_SIZE 16

enum {
	XT_WILDSTRING_FLAG_INVERT		= 0x01,
	XT_WILDSTRING_FLAG_IGNORECASE	= 0x02
};

struct xt_wildstring_info
{
	__u16 from_offset;
	__u16 to_offset;
	char	  algo[XT_WILDSTRING_MAX_ALGO_NAME_SIZE];
	char 	  pattern[XT_WILDSTRING_MAX_PATTERN_SIZE];
	char 	  pattern_part1[XT_WILDSTRING_MAX_PATTERN_SIZE];
	char 	  pattern_part2[XT_WILDSTRING_MAX_PATTERN_SIZE];
	char 	  pattern_part3[XT_WILDSTRING_MAX_PATTERN_SIZE];
	__u8  patlen;
	__u8  patlen_part1;
	__u8  patlen_part2;
	__u8  patlen_part3;
	union {
		struct {
			__u8  invert;
		} v0;

		struct {
			__u8  flags;
		} v1;
	} u;

	/* Used internally by the kernel */
	struct ts_config __attribute__((aligned(8))) *config;
	struct ts_config __attribute__((aligned(8))) *config_part1;
	struct ts_config __attribute__((aligned(8))) *config_part2;
	struct ts_config __attribute__((aligned(8))) *config_part3;
};

#endif
