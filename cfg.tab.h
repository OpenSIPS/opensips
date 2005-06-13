#ifndef BISON_CFG_TAB_H
# define BISON_CFG_TAB_H

#ifndef YYSTYPE
typedef union {
	long intval;
	unsigned long uval;
	char* strval;
	struct expr* expr;
	struct action* action;
	struct net* ipnet;
	struct ip_addr* ipaddr;
	struct socket_id* sockid;
} yystype;
# define YYSTYPE yystype
# define YYSTYPE_IS_TRIVIAL 1
#endif
# define	FORWARD	257
# define	FORWARD_TCP	258
# define	FORWARD_TLS	259
# define	FORWARD_UDP	260
# define	SEND	261
# define	SEND_TCP	262
# define	DROP	263
# define	EXIT	264
# define	RETURN	265
# define	LOG_TOK	266
# define	ERROR	267
# define	ROUTE	268
# define	ROUTE_FAILURE	269
# define	ROUTE_ONREPLY	270
# define	EXEC	271
# define	SET_HOST	272
# define	SET_HOSTPORT	273
# define	PREFIX	274
# define	STRIP	275
# define	STRIP_TAIL	276
# define	APPEND_BRANCH	277
# define	SET_USER	278
# define	SET_USERPASS	279
# define	SET_PORT	280
# define	SET_URI	281
# define	REVERT_URI	282
# define	FORCE_RPORT	283
# define	FORCE_TCP_ALIAS	284
# define	IF	285
# define	ELSE	286
# define	SET_ADV_ADDRESS	287
# define	SET_ADV_PORT	288
# define	FORCE_SEND_SOCKET	289
# define	URIHOST	290
# define	URIPORT	291
# define	MAX_LEN	292
# define	SETFLAG	293
# define	RESETFLAG	294
# define	ISFLAGSET	295
# define	METHOD	296
# define	URI	297
# define	FROM_URI	298
# define	TO_URI	299
# define	SRCIP	300
# define	SRCPORT	301
# define	DSTIP	302
# define	DSTPORT	303
# define	PROTO	304
# define	AF	305
# define	MYSELF	306
# define	MSGLEN	307
# define	UDP	308
# define	TCP	309
# define	TLS	310
# define	DEBUG	311
# define	FORK	312
# define	LOGSTDERROR	313
# define	LOGFACILITY	314
# define	LISTEN	315
# define	ALIAS	316
# define	DNS	317
# define	REV_DNS	318
# define	PORT	319
# define	STAT	320
# define	CHILDREN	321
# define	CHECK_VIA	322
# define	SYN_BRANCH	323
# define	MEMLOG	324
# define	SIP_WARNING	325
# define	FIFO	326
# define	FIFO_DIR	327
# define	SOCK_MODE	328
# define	SOCK_USER	329
# define	SOCK_GROUP	330
# define	FIFO_DB_URL	331
# define	UNIX_SOCK	332
# define	UNIX_SOCK_CHILDREN	333
# define	UNIX_TX_TIMEOUT	334
# define	SERVER_SIGNATURE	335
# define	REPLY_TO_VIA	336
# define	LOADMODULE	337
# define	MODPARAM	338
# define	MAXBUFFER	339
# define	USER	340
# define	GROUP	341
# define	CHROOT	342
# define	WDIR	343
# define	MHOMED	344
# define	DISABLE_TCP	345
# define	TCP_ACCEPT_ALIASES	346
# define	TCP_CHILDREN	347
# define	TCP_CONNECT_TIMEOUT	348
# define	TCP_SEND_TIMEOUT	349
# define	DISABLE_TLS	350
# define	TLSLOG	351
# define	TLS_PORT_NO	352
# define	TLS_METHOD	353
# define	TLS_HANDSHAKE_TIMEOUT	354
# define	TLS_SEND_TIMEOUT	355
# define	SSLv23	356
# define	SSLv2	357
# define	SSLv3	358
# define	TLSv1	359
# define	TLS_VERIFY	360
# define	TLS_REQUIRE_CERTIFICATE	361
# define	TLS_CERTIFICATE	362
# define	TLS_PRIVATE_KEY	363
# define	TLS_CA_LIST	364
# define	ADVERTISED_ADDRESS	365
# define	ADVERTISED_PORT	366
# define	DISABLE_CORE	367
# define	OPEN_FD_LIMIT	368
# define	MCAST_LOOPBACK	369
# define	MCAST_TTL	370
# define	EQUAL	371
# define	EQUAL_T	372
# define	GT	373
# define	LT	374
# define	GTE	375
# define	LTE	376
# define	DIFF	377
# define	MATCH	378
# define	OR	379
# define	AND	380
# define	NOT	381
# define	PLUS	382
# define	MINUS	383
# define	NUMBER	384
# define	ID	385
# define	STRING	386
# define	IPV6ADDR	387
# define	COMMA	388
# define	SEMICOLON	389
# define	RPAREN	390
# define	LPAREN	391
# define	LBRACE	392
# define	RBRACE	393
# define	LBRACK	394
# define	RBRACK	395
# define	SLASH	396
# define	DOT	397
# define	CR	398
# define	COLON	399
# define	STAR	400


extern YYSTYPE yylval;

#endif /* not BISON_CFG_TAB_H */
