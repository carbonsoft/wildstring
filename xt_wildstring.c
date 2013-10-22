/* wildstring matching match for iptables
 *
 * (C) 2005 Pablo Neira Ayuso <pablo@eurodev.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_wildstring.h>
#include <linux/textsearch.h>

MODULE_AUTHOR("Pablo Neira Ayuso <pablo@eurodev.net>");
MODULE_DESCRIPTION("Xtables: wildstring-based matching");
MODULE_LICENSE("GPL");

static bool
wildstring_mt(const struct sk_buff *skb, const struct xt_match_param *par)
{
	const struct xt_wildstring_info *conf = par->matchinfo;
	struct ts_state state;
	int invert;
	unsigned int skb_find = 0;

	memset(&state, 0, sizeof(struct ts_state));

	invert = (par->match->revision == 0 ? conf->u.v0.invert :
				    conf->u.v1.flags & XT_WILDSTRING_FLAG_INVERT);

	/* pattern 1 */
	printk("I played iptables, then wild tcp packet appears\n");
	skb_find = skb_find_text((struct sk_buff *)skb, conf->from_offset,
			conf->to_offset, conf->config_part1, &state);
	if (skb_find == UINT_MAX)
		return false;

	/* pattern 2 */
	memset(&state, 0, sizeof(struct ts_state));

	skb_find = skb_find_text((struct sk_buff *)skb, conf->from_offset,
			conf->to_offset, conf->config_part2, &state);
	if (skb_find == UINT_MAX)
		return false;

	/* pattern 3 */
	memset(&state, 0, sizeof(struct ts_state));
	skb_find = skb_find_text((struct sk_buff *)skb, conf->from_offset,
			conf->to_offset, conf->config_part3, &state);

	if (skb_find == UINT_MAX)
		return false;

	return true;
}

#define WILDSTRING_TEXT_PRIV(m) ((struct xt_wildstring_info *)(m))

static bool wildstring_mt_check(const struct xt_mtchk_param *par)
{
	struct xt_wildstring_info *conf = par->matchinfo;
	struct ts_config *ts_conf;
	int flags = TS_AUTOLOAD;
	char *s;
	char delim[2] = "*";

	/* Damn, can't handle this case properly with iptables... */
	if (conf->from_offset > conf->to_offset)
		return false;
	if (conf->algo[XT_WILDSTRING_MAX_ALGO_NAME_SIZE - 1] != '\0')
		return false;
	if (conf->patlen > XT_WILDSTRING_MAX_PATTERN_SIZE)
		return false;
	if (par->match->revision == 1) {
		if (conf->u.v1.flags &
		    ~(XT_WILDSTRING_FLAG_IGNORECASE | XT_WILDSTRING_FLAG_INVERT))
			return false;
		if (conf->u.v1.flags & XT_WILDSTRING_FLAG_IGNORECASE)
			flags |= TS_IGNORECASE;
	}

	s = (char *) conf->pattern;
	/* pattern 1 */
	conf->pattern_part1 = strsep(&s, delim);
	if (!conf->pattern_part1)
		return false;
	conf->patlen_part1 = strlen(conf->pattern_part1);
	printk("pattern1 %s\n", conf->pattern_part1);

	ts_conf = textsearch_prepare(conf->algo, conf->pattern_part1, 
			conf->patlen_part1, GFP_KERNEL, flags);
	if (IS_ERR(ts_conf))
		return false;

	conf->config_part1 = ts_conf;

	/* pattern 2 */
	conf->pattern_part2 = strsep(&s, delim);
	if (!conf->pattern_part2)
		return false;
	conf->patlen_part2 = strlen(conf->pattern_part2);
	printk("pattern2 %s\n", conf->pattern_part2);

	ts_conf = textsearch_prepare(conf->algo, conf->pattern_part2, 
			conf->patlen_part2, GFP_KERNEL, flags);
	if (IS_ERR(ts_conf))
		return false;

	conf->config_part2 = ts_conf;

	/* pattern 3 */
	conf->pattern_part3 = strsep(&s, delim);
	if (!conf->pattern_part3)
		return false;
	conf->patlen_part3 = strlen(conf->pattern_part3);

	printk("pattern3 %s\n", conf->pattern_part3);
	ts_conf = textsearch_prepare(conf->algo, conf->pattern_part3, 
			conf->patlen_part3, GFP_KERNEL, flags);
	if (IS_ERR(ts_conf))
		return false;

	conf->config_part3 = ts_conf;
	return true;
}

static void wildstring_mt_destroy(const struct xt_mtdtor_param *par)
{
	textsearch_destroy(WILDSTRING_TEXT_PRIV(par->matchinfo)->config_part1);
	textsearch_destroy(WILDSTRING_TEXT_PRIV(par->matchinfo)->config_part2);
	textsearch_destroy(WILDSTRING_TEXT_PRIV(par->matchinfo)->config_part3);
}

static struct xt_match xt_wildstring_mt_reg[] __read_mostly = {
	{
		.name 		= "wildstring",
		.revision	= 0,
		.family		= NFPROTO_UNSPEC,
		.checkentry	= wildstring_mt_check,
		.match 		= wildstring_mt,
		.destroy 	= wildstring_mt_destroy,
		.matchsize	= sizeof(struct xt_wildstring_info),
		.me 		= THIS_MODULE
	},
	{
		.name 		= "wildstring",
		.revision	= 1,
		.family		= NFPROTO_UNSPEC,
		.checkentry	= wildstring_mt_check,
		.match 		= wildstring_mt,
		.destroy 	= wildstring_mt_destroy,
		.matchsize	= sizeof(struct xt_wildstring_info),
		.me 		= THIS_MODULE
	},
};

static int __init wildstring_mt_init(void)
{
	return xt_register_matches(xt_wildstring_mt_reg,
				   ARRAY_SIZE(xt_wildstring_mt_reg));
}

static void __exit wildstring_mt_exit(void)
{
	xt_unregister_matches(xt_wildstring_mt_reg, ARRAY_SIZE(xt_wildstring_mt_reg));
}

module_init(wildstring_mt_init);
module_exit(wildstring_mt_exit);
