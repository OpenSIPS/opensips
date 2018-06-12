#include "checks.h"
#include "../../str.h"
#include "../../dprint.h"
#include <string.h>
#include "utils.h"
#include "auth.h"


static inline void get_username(str* _s)
{
	char* at, *dcolon, *dc;
	dcolon = find_not_quoted(_s->s, ':');

	if (!dcolon) {
		_s->len = 0;
		return;
	}
	_s->s = dcolon + 1;

	at = strchr(_s->s, '@');
	dc = strchr(_s->s, ':');
	if (at) {
		if ((dc) && (dc < at)) {
			_s->len = dc - dcolon - 1;
			return;
		}
		
		_s->len = at - dcolon - 1;
		/*	_s->s[_s->len] = '\0'; */
	} else {
		_s->len = 0;
	} 
}



int check_to(struct sip_msg* _msg, char* _str1, char* _str2)
{
	str user;

	if (!_msg->to) {
		LOG(L_ERR, "check_to(): To HF not found\n");
		return -1;
	}

	user.s = _msg->to->body.s;
	user.len = _msg->to->body.len;

	get_username(&user);

	if (!user.len) return -1;

	/* FIXME !! */
	if (!strncasecmp(user.s, state.cred.username.s,
			 (user.len < state.cred.username.len) ? (state.cred.username.len) : (user.len))) {
		DBG("check_to(): auth id and To username are equal\n");
		return 1;
	} else {
		DBG("check_to(): auth id and To username differ\n");
		return -1;
	}
}


int check_from(struct sip_msg* _msg, char* _str1, char* _str2)
{
	str user;

	if (!_msg->from) {
		LOG(L_ERR, "check_from(): From HF not found\n");
		return -1;
	}

	user.s = _msg->from->body.s;
	user.len = _msg->from->body.len;

	get_username(&user);

	if (!user.len) return -1;

	/* FIXME !! */
	if (!strncasecmp(user.s, state.cred.username.s,
			(user.len < state.cred.username.len) ? (state.cred.username.len) : (user.len))) {
		DBG("check_from(): auth id and From username are equal\n");
		return 1;
	} else {
		DBG("check_from(): auth id and From username differ\n");
		return -1;
	}
}
