/*
 * Copyright (C) 2007-2008 1&1 Internet AG
 *
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 */

/**
 * @file route_func.c
 * @brief Routing and balancing functions.
 */

#include <ctype.h>
#include <assert.h>
#include <stdlib.h>
#include "route_func.h"
#include "route_tree.h"
#include "route_db.h"
#include "../../sr_module.h"
#include "../../action.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_from.h"
#include "../../ut.h"
#include "../../parser/digest/digest.h"
#include "../../parser/hf.h"
#include "../../mem/mem.h"
#include "../../qvalue.h"
#include "../../dset.h"
#include "../../prime_hash.h"
#include "carrierroute.h"


/**
 * Loads user carrier from subscriber table and stores it in an AVP.
 *
 * @param _msg the current SIP message
 * @param user the user to determine the route tree
 * @param domain the domain to determine the route tree
 * @param dstavp the name of the AVP where to store the carrier tree id
 *
 * @return 1 on success, -1 on failure
 */
int cr_load_user_carrier(struct sip_msg * _msg, str *user, str *domain, pv_spec_t *dstavp) {
	int_str avp_val;
	int avp_name;
	unsigned short name_type;

	/* get carrier id */
	if ((avp_val.n = load_user_carrier(user, domain)) < 0) {
		LM_ERR("error in load user carrier\n");
		return -1;
	}
	else {
		/* set avp ! */
		if(pv_get_avp_name(_msg, &(dstavp->pvp), &avp_name, &name_type)!=0) {
			LM_ERR("Invalid AVP definition\n");
			return -1;
		}

		if (add_avp(name_type, avp_name, avp_val)<0) {
			LM_ERR("add AVP failed\n");
			return -1;
		}
	}
	return 1;
}


/**
 * Try to match the reply code rc to the reply code with wildcards.
 *
 * @param rcw reply code specifier with wildcards
 * @param rc the current reply code
 *
 * @return 0 on match, -1 otherwise
 */
static inline int reply_code_matcher(const str *rcw, const str *rc) {
	int i;

	if (rcw->len==0) return 0;

	if (rcw->len != rc->len) return -1;

	for (i=0; i<rc->len; i++) {
		if (rcw->s[i]!='.' && rcw->s[i]!=rc->s[i]) return -1;
	}

	return 0;
}


/**
 * writes the next_domain avp using the rule list of route_tree
 *
 * @param failure_tree the current failure routing tree node
 * @param host last tried host
 * @param reply_code the last reply code
 * @param flags flags for the failure route rule
 * @param dstavp the name of the AVP where to store the next domain
 *
 * @return 0 on success, -1 on failure
 */
static int set_next_domain_on_rule(struct sip_msg * _msg,
		const struct failure_route_tree_item *failure_tree,
		const str *host, const str *reply_code, const flag_t flags,
		const pv_spec_t *dstavp) {
	struct failure_route_rule * rr;
	int_str avp_val;
	int avp_name;
	unsigned short name_type;

	assert(failure_tree != NULL);

	LM_DBG("searching for matching routing rules\n");
	for (rr = failure_tree->rule_list; rr != NULL; rr = rr->next) {
		/*
		LM_DBG("rr.flags=%d rr.mask=%d flags=%d\n", rr->flags, rr->mask, flags);
		LM_DBG("rr.host.len=%d host.len=%d\n", rr->host.len, host->len);
		LM_DBG("rr.host.s='%.*s' host.s='%.*s'\n", rr->host.len, rr->host.s, host->len, host->s);
		LM_DBG("rr.reply_code.len=%d reply_code.len=%d\n", rr->reply_code.len, reply_code->len);
		LM_DBG("rr.reply_code.s='%.*s' reply_code.s='%.*s'\n", rr->reply_code.len, rr->reply_code.s, reply_code->len, reply_code->s);
		*/
		if (((rr->mask & flags) == rr->flags) &&
				((rr->host.len == 0) || (str_strcmp(host, &rr->host)==0)) &&
				(reply_code_matcher(&(rr->reply_code), reply_code)==0)) {
			avp_val.n = rr->next_domain;

			if(pv_get_avp_name(_msg, (pv_param_p)&dstavp->pvp, &avp_name, &name_type)!=0) {
				LM_ERR("Invalid AVP definition\n");
				return -1;
			}

			if (add_avp(name_type, avp_name, avp_val)<0) {
				LM_ERR("set AVP failed\n");
				return -1;
			}

			LM_INFO("next_domain is %d.\n", rr->next_domain);
			return 0;
		}
	}

	return -1;
}


/**
 * traverses the failure routing tree until a matching rule is found.
 * The longest match is taken, so it is possible to define
 * failure route rules for a single number
 *
 * @param failure_tree the current routing tree node
 * @param uri the uri to be rewritten at the current position
 * @param host last tried host
 * @param reply_code the last reply code
 * @param flags flags for the failure route rule
 * @param dstavp the name of the AVP where to store the next domain
 *
 * @return 0 on success, -1 on failure, 1 on no more matching child node and no rule list
 */
static int set_next_domain_recursor(struct sip_msg * _msg,
		const struct failure_route_tree_item *failure_tree,
		const str *uri, const str *host, const str *reply_code, const flag_t flags,
		const pv_spec_t *dstavp) {
	int ret;
	struct failure_route_tree_item *re_tree;
	str re_uri = *uri;

	/* Skip over non-digits.  */
	while (re_uri.len > 0 && !isdigit(*re_uri.s)) {
		++re_uri.s;
		--re_uri.len;
	}
	if (re_uri.len == 0 || failure_tree->nodes[*re_uri.s - '0'] == NULL) {
		if (failure_tree->rule_list == NULL) {
			LM_INFO("URI or route tree nodes empty, empty rule list\n");
			return 1;
		} else {
			return set_next_domain_on_rule(_msg, failure_tree, host, reply_code, flags, dstavp);
		}
	} else {
		/* match, goto the next digit of the uri and try again */
		re_tree = failure_tree->nodes[*re_uri.s - '0'];
		re_uri.s++;
		re_uri.len--;
		ret = set_next_domain_recursor(_msg, re_tree, &re_uri, host, reply_code, flags, dstavp);
		switch (ret) {
		case 0:
			return 0;
		case 1:
			if (failure_tree->rule_list != NULL) {
				return set_next_domain_on_rule(_msg, failure_tree, host, reply_code, flags, dstavp);
			} else {
					LM_INFO("empty rule list for host [%.*s]%.*s\n", re_uri.len, re_uri.s,
						host->len, host->s);
				return 1;
			}
		default:
			return -1;
		}
	}
}


/**
 * searches for a rule int rt with hash_index prob - 1
 * If the rule with the desired hash index is deactivated,
 * the next working rule is used.
 *
 * @param rf the route_flags node to search for rule
 * @param prob the hash index
 *
 * @return pointer to route rule on success, NULL on failure
 */
static struct route_rule * get_rule_by_hash(const struct route_flags * rf,
		const int prob) {
	struct route_rule * act_hash = NULL;

	if (prob > rf->rule_num) {
		LM_WARN("too large desired hash, taking highest\n");
		act_hash = rf->rules[rf->rule_num - 1];
	}
	act_hash = rf->rules[prob - 1];

	if (!act_hash->status) {
		if (act_hash->backup && act_hash->backup->rr) {
			act_hash = act_hash->backup->rr;
		} else {
			act_hash = NULL;
		}
	}
	LM_INFO("desired hash was %i, return %i\n", prob, act_hash ? act_hash->hash_index : -1);
	return act_hash;
}


/**
 * does the work for rewrite_on_rule, writes the new URI into dest
 *
 * @param rs the route rule used for rewriting
 * @param dest the returned new destination URI
 * @param msg the sip message
 * @param user the localpart of the uri to be rewritten
 * @param dstavp the name of the destination AVP where the used host name is stored
 *
 * @return 0 on success, -1 on failure
 *
 * @see rewrite_on_rule()
 */
static int actually_rewrite(const struct route_rule *rs, str *dest,
		struct sip_msg *msg, const str * user, const pv_spec_t *dstavp) {
	size_t len;
	char *p;
  int_str avp_val;
	int strip = 0;
	int avp_name;
	unsigned short name_type;

	strip = (rs->strip > user->len ? user->len : rs->strip);
	strip = (strip < 0 ? 0 : strip);

	len = rs->local_prefix.len + user->len + rs->local_suffix.len +
	      AT_SIGN_LEN + rs->host.len - strip;
	if (msg->parsed_uri.type == SIPS_URI_T) {
		len += SIPS_URI_LEN;
	} else {
		len += SIP_URI_LEN;
	}
	dest->s = (char *)pkg_malloc(len + 1);
	if (dest->s == NULL) {
		LM_ERR("out of private memory.\n");
		return -1;
	}
	dest->len = len;
	p = dest->s;
	if (msg->parsed_uri.type == SIPS_URI_T) {
		memcpy(p, SIPS_URI, SIPS_URI_LEN);
		p += SIPS_URI_LEN;
	} else {
		memcpy(p, SIP_URI, SIP_URI_LEN);
		p += SIP_URI_LEN;
	}
	if (user->len) {
		memcpy(p, rs->local_prefix.s, rs->local_prefix.len);
		p += rs->local_prefix.len;
		memcpy(p, user->s + strip, user->len - strip);
		p += user->len - strip;
		memcpy(p, rs->local_suffix.s, rs->local_suffix.len);
		p += rs->local_suffix.len;
		memcpy(p, AT_SIGN, AT_SIGN_LEN);
		p += AT_SIGN_LEN;
	}
	/* this could be an error, or a blacklisted destination */
	if (rs->host.len == 0) {
		*p = '\0';
		pkg_free(dest->s);
		return -1;
	}
	memcpy(p, rs->host.s, rs->host.len);
	p += rs->host.len;
	*p = '\0';

	if (dstavp) {
		if(pv_get_avp_name(msg, (pv_param_p)&dstavp->pvp, &avp_name, &name_type)!=0) {
			LM_ERR("Invalid AVP definition\n");
			return -1;
		}

		avp_val.s = rs->host;
		if (add_avp(AVP_VAL_STR | name_type, avp_name, avp_val)<0) {
			LM_ERR("set AVP failed\n");
			pkg_free(dest->s);
			return -1;
		}
	}

	return 0;
}


/**
 * writes the uri dest using the rule list of route_tree
 *
 * @param route_tree the current routing tree node
 * @param flags user defined flags
 * @param dest the returned new destination URI
 * @param msg the sip message
 * @param user the localpart of the uri to be rewritten
 * @param hash_source the SIP header used for hashing
 * @param alg the algorithm used for hashing
 * @param dstavp the name of the destination AVP where the used host name is stored
 *
 * @return 0 on success, -1 on failure, 1 on empty rule list
 */
static int rewrite_on_rule(const struct route_tree_item * route_tree, flag_t flags, str * dest,
		struct sip_msg * msg, const str * user, const enum hash_source hash_source,
		const enum hash_algorithm alg, pv_spec_t *dstavp) {
	struct route_flags * rf;
	struct route_rule * rr;
	int prob;

	assert(route_tree != NULL);
	assert(route_tree->flag_list != NULL);

	LM_DBG("searching for matching routing rules\n");
	for (rf = route_tree->flag_list; rf != NULL; rf = rf->next) {
		/* LM_DBG("actual flags %i, searched flags %i, mask %i and match %i\n", rf->flags, flags, rf->mask, flags&rf->mask); */
		if ((flags&rf->mask) == rf->flags) break;
	}

	if (rf==NULL) {
		LM_INFO("did not find a match for flags %d\n", flags);
		return -1;
	}

	if (rf->rule_list == NULL) {
		LM_INFO("empty rule list\n");
		return 1;
	}

	switch (alg) {
		case alg_prime:
			if ((prob = prime_hash_func(msg, hash_source, rf->max_targets)) < 0) {
				LM_ERR("could not hash message with prime algorithm\n");
				return -1;
			}
			if ((rr = get_rule_by_hash(rf, prob)) == NULL) {
				LM_CRIT("no route found\n");
				return -1;
			}
			break;
		case alg_crc32:
			if(rf->dice_max == 0) {
				LM_ERR("invalid dice_max value\n");
				return -1;
			}
			if ((prob = hash_func(msg, hash_source, rf->dice_max)) < 0) {
				LM_ERR("could not hash message with CRC32\n");
				return -1;
			}
			/* This auto-magically takes the last rule if anything is broken.
			 * Sometimes the hash result is zero. If the first rule is off
			 * (has a probablility of zero) then it has also a dice_to of
			 * zero and the message could not be routed at all if we use
			 * '<' here. Thus the '<=' is necessary.
			 */
			for (rr = rf->rule_list;
			        rr->next != NULL && rr->dice_to <= prob;
		        rr = rr->next) {}
			if (!rr->status) {
				if (!rr->backup) {
					LM_ERR("all routes are off\n");
					return -1;
				} else {
					if (!rr->backup->rr) {
						LM_ERR("all routes are off\n");
						return -1;
					}
					rr = rr->backup->rr;
				}
			}
			break;
		default:
			LM_ERR("invalid hash algorithm\n");
			return -1;
	}
	return actually_rewrite(rr, dest, msg, user, dstavp);
}


/**
 * traverses the routing tree until a matching rule is found
 * The longest match is taken, so it is possible to define
 * route rules for a single number
 *
 * @param route_tree the current routing tree node
 * @param pm the user to be used for prefix matching
 * @param flags user defined flags
 * @param dest the returned new destination URI
 * @param msg the sip message
 * @param user the localpart of the uri to be rewritten
 * @param hash_source the SIP header used for hashing
 * @param alg the algorithm used for hashing
 * @param dstavp the name of the destination AVP where the used host name is stored
 *
 * @return 0 on success, -1 on failure, 1 on no more matching child node and no rule list
 */
static int rewrite_uri_recursor(const struct route_tree_item * route_tree,
		const str * pm, flag_t flags, str * dest, struct sip_msg * msg, const str * user,
		const enum hash_source hash_source, const enum hash_algorithm alg,
		pv_spec_t *dstavp) {
	struct route_tree_item *re_tree;
	str re_pm;

	re_pm=*pm;
	/* Skip over non-digits.  */
	while (re_pm.len > 0 && !isdigit(*re_pm.s)) {
		++re_pm.s;
		--re_pm.len;
	}
	if (re_pm.len == 0 || route_tree->nodes[*re_pm.s - '0'] == NULL) {
		if (route_tree->flag_list == NULL) {
			LM_INFO("URI or route tree nodes empty, empty flag list\n");
			return 1;
		} else {
			return rewrite_on_rule(route_tree, flags, dest, msg, user, hash_source, alg, dstavp);
		}
	} else {
		/* match, goto the next digit of the uri and try again */
		re_tree = route_tree->nodes[*re_pm.s - '0'];
		re_pm.s = re_pm.s + 1;
		re_pm.len = re_pm.len - 1;
		switch (rewrite_uri_recursor(re_tree, &re_pm, flags, dest, msg, user, hash_source, alg, dstavp)) {
			case 0:
				return 0;
			case 1:
				if (route_tree->flag_list != NULL) {
					return rewrite_on_rule(route_tree, flags, dest, msg, user, hash_source, alg, dstavp);
				} else {
					LM_INFO("empty flag list for prefix [%.*s]%.*s\n", user->len - re_pm.len,
						user->s, re_pm.len, re_pm.s);
					return 1;
				}
			default:
				return -1;
		}
	}
}


/**
 * rewrites the request URI of msg after determining the
 * new destination URI
 *
 * @param _msg the current SIP message
 * @param _carrier the requested carrier
 * @param _domain the requested routing domain
 * @param _prefix_matching the user to be used for prefix matching
 * @param _rewrite_user the localpart of the URI to be rewritten
 * @param _hsrc the SIP header used for hashing
 * @param _halg the hash algorithm used for hashing
 * @param _dstavp the name of the destination AVP where the used host name is stored
 *
 * @return 1 on success, -1 on failure
 */
int cr_do_route(struct sip_msg * _msg, void *_carrier,
		void *_domain, str *prefix_matching,
		str *rewrite_user, void *_hsrc,
		enum hash_algorithm _halg, pv_spec_t *_dstavp) {
	int carrier_id;
	int domain_id;
	flag_t flags;
	struct rewrite_data * rd;
	struct carrier_tree * ct;
	struct route_tree * rt;
	str dest;
	int ret;

	ret = -1;

	carrier_id = (int)(unsigned long)_carrier;
	domain_id = (int)(unsigned long)_domain;
	if (domain_id < 0) {
		LM_ERR("invalid domain id %d\n", domain_id);
		return -1;
	}

	flags = _msg->flags;

	do {
		rd = get_data();
	} while (rd == NULL);

	ct=NULL;
	if (carrier_id < 0) {
		if (fallback_default) {
			LM_NOTICE("invalid tree id %i specified, using default tree\n", carrier_id);
			ct = rd->carriers[rd->default_carrier_index];
		}
	} else if (carrier_id == 0) {
		ct = rd->carriers[rd->default_carrier_index];
	} else {
		ct = get_carrier_tree(carrier_id, rd);
		if (ct == NULL) {
			if (fallback_default) {
				LM_NOTICE("invalid tree id %i specified, using default tree\n", carrier_id);
				ct = rd->carriers[rd->default_carrier_index];
			}
		}
	}
	if (ct == NULL) {
		LM_ERR("cannot get carrier tree\n");
		goto unlock_and_out;
	}

	rt = get_route_tree_by_id(ct, domain_id);
	if (rt == NULL) {
		LM_ERR("desired routing domain doesn't exist, prefix %.*s, carrier %d, domain %d\n",
			prefix_matching->len, prefix_matching->s, carrier_id, domain_id);
		goto unlock_and_out;
	}

	if (rewrite_uri_recursor(rt->tree, prefix_matching, flags, &dest, _msg, rewrite_user, (enum hash_source)_hsrc, _halg, _dstavp) != 0) {
		/* this is not necessarily an error, rewrite_recursor does already some error logging */
		LM_INFO("rewrite_uri_recursor doesn't complete, uri %.*s, carrier %d, domain %d\n", prefix_matching->len,
			prefix_matching->s, carrier_id, domain_id);
		goto unlock_and_out;
	}

	LM_INFO("uri %.*s was rewritten to %.*s\n",
		rewrite_user->len, rewrite_user->s, dest.len, dest.s);

	if (set_ruri(_msg, &dest) < 0) {
		LM_ERR("Error setting RURI\n");
		ret = -1;
	} else {
		ret = 1;
	}

	pkg_free(dest.s);

unlock_and_out:
	release_data(rd);
	return ret;
}

/**
 * rewrites the request URI of msg after determining the
 * new destination URI with the crc32 hash algorithm.
 *
 * @param _msg the current SIP message
 * @param _carrier the requested carrier
 * @param _domain the requested routing domain
 * @param _prefix_matching the user to be used for prefix matching
 * @param _rewrite_user the localpart of the URI to be rewritten
 * @param _hsrc the SIP header used for hashing
 * @param _dstavp the name of the destination AVP where the used host name is stored
 *
 * @return 1 on success, -1 on failure
 */
int cr_route(struct sip_msg * _msg, void *_carrier,
		void *_domain, str *_prefix_matching,
		str *_rewrite_user, void *_hsrc,
		pv_spec_t *_dstavp)
{
	return cr_do_route(_msg, _carrier, _domain, _prefix_matching,
		_rewrite_user, _hsrc, alg_crc32, _dstavp);
}


/**
 * rewrites the request URI of msg after determining the
 * new destination URI with the prime hash algorithm.
 *
 * @param _msg the current SIP message
 * @param _carrier the requested carrier
 * @param _domain the requested routing domain
 * @param _prefix_matching the user to be used for prefix matching
 * @param _rewrite_user the localpart of the URI to be rewritten
 * @param _hsrc the SIP header used for hashing
 * @param _dstavp the name of the destination AVP where the used host name is stored
 *
 * @return 1 on success, -1 on failure
 */
int cr_prime_route(struct sip_msg * _msg, void *_carrier,
		str *_domain, str *_prefix_matching,
		str *_rewrite_user, void *_hsrc,
		pv_spec_t *_dstavp)
{
	return cr_do_route(_msg, _carrier, _domain, _prefix_matching,
		_rewrite_user, _hsrc, alg_prime, _dstavp);
}




/**
 * Loads next domain from failure routing table and stores it in an AVP.
 *
 * @param _msg the current SIP message
 * @param _carrier the requested carrier
 * @param _domain the requested routing domain
 * @param _prefix_matching the user to be used for prefix matching
 * @param _host the host name to be used for rule matching
 * @param _reply_code the reply code to be used for rule matching
 * @param _dstavp the name of the destination AVP
 *
 * @return 1 on success, -1 on failure
 */
int cr_load_next_domain(struct sip_msg * _msg, void *_carrier,
		void *_domain, str *prefix_matching,
		str *host, str *reply_code, pv_spec_t *_dstavp) {
	int carrier_id;
	int domain_id;
	flag_t flags;
	struct rewrite_data * rd;
	struct carrier_tree * ct;
	struct route_tree * rt;
	int ret;

	ret = -1;

	carrier_id = (int)(unsigned long)_carrier;
	domain_id = (int)(unsigned long)_domain;
	if (domain_id < 0) {
		LM_ERR("invalid domain id %d\n", domain_id);
		return -1;
	}

	flags = _msg->flags;

	do {
		rd = get_data();
	} while (rd == NULL);

	ct=NULL;
	if (carrier_id < 0) {
		if (fallback_default) {
			LM_NOTICE("invalid tree id %i specified, using default tree\n", carrier_id);
			ct = rd->carriers[rd->default_carrier_index];
		}
	} else if (carrier_id == 0) {
		ct = rd->carriers[rd->default_carrier_index];
	} else {
		ct = get_carrier_tree(carrier_id, rd);
		if (ct == NULL) {
			if (fallback_default) {
				LM_NOTICE("invalid tree id %i specified, using default tree\n", carrier_id);
				ct = rd->carriers[rd->default_carrier_index];
			}
		}
	}
	if (ct == NULL) {
		LM_ERR("cannot get carrier tree\n");
		goto unlock_and_out;
	}

	rt = get_route_tree_by_id(ct, domain_id);
	if (rt == NULL) {
		LM_ERR("desired routing domain doesn't exist, prefix %.*s, carrier %d, domain %d\n",
			prefix_matching->len, prefix_matching->s, carrier_id, domain_id);
		goto unlock_and_out;
	}

	if (set_next_domain_recursor(_msg, rt->failure_tree, prefix_matching, host, reply_code, flags, _dstavp) != 0) {
		LM_ERR("during set_next_domain_recursor, prefix '%.*s', carrier %d, domain %d\n", prefix_matching->len,
			prefix_matching->s, carrier_id, domain_id);
		goto unlock_and_out;
	}

	ret = 1;

unlock_and_out:
	release_data(rd);
	return ret;
}
