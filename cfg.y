/*
 * $Id$
 *
 *  cfg grammar
 */

%{

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "route_struct.h"
#include "globals.h"
#include "route.h"
#include "dprint.h"

void yyerror(char* s);
char* tmp;

%}

%union {
	int intval;
	unsigned uval;
	char* strval;
	struct expr* expr;
	struct action* action;
	struct net* net;
	struct route_elem* route_el;
}

/* terminals */


/* keywords */
%token FORWARD
%token SEND
%token DROP
%token LOG_TOK
%token ERROR
%token ROUTE
%token EXEC
%token SET_HOST
%token SET_HOSTPORT
%token SET_USER
%token SET_USERPASS
%token SET_PORT
%token SET_URI

%token METHOD
%token URI
%token SRCIP
%token DSTIP

/* config vars. */
%token DEBUG
%token FORK
%token LOGSTDERROR
%token LISTEN
%token DNS
%token REV_DNS
%token PORT
%token CHILDREN
%token CHECK_VIA



/* operators */
%nonassoc EQUAL
%nonassoc EQUAL_T
%nonassoc MATCH
%left OR
%left AND
%left NOT

/* values */
%token <intval> NUMBER
%token <strval> ID
%token <strval> STRING

/* other */
%token COMMA
%token SEMICOLON
%token RPAREN
%token LPAREN
%token LBRACE
%token RBRACE
%token LBRACK
%token RBRACK
%token SLASH
%token DOT
%token CR


/*non-terminals */
%type <expr> exp, condition,  exp_elem
%type <action> action, actions, cmd
%type <uval> ipv4
%type <net> net4
%type <strval> host
%type <route_el> rules;
%type <route_el> rule;



%%


cfg:	statements
	;

statements:	statements statement {}
		| statement {}
		| statements error { yyerror(""); YYABORT;}
	;

statement:	assign_stm 
		| route_stm 
		| CR	/* null statement*/
	;

assign_stm:	DEBUG EQUAL NUMBER { debug=$3; }
		| DEBUG EQUAL error  { yyerror("number  expected"); }
		| FORK  EQUAL NUMBER { dont_fork= ! $3; }
		| FORK  EQUAL error  { yyerror("boolean value expected"); }
		| LOGSTDERROR EQUAL NUMBER { log_stderr=$3; }
		| LOGSTDERROR EQUAL error { yyerror("boolean value expected"); }
		| DNS EQUAL NUMBER   { received_dns|= ($3)?DO_DNS:0; }
		| DNS EQUAL error { yyerror("boolean value expected"); }
		| REV_DNS EQUAL NUMBER { received_dns|= ($3)?DO_REV_DNS:0; }
		| REV_DNS EQUAL error { yyerror("boolean value expected"); }
		| PORT EQUAL NUMBER   { port_no=$3; }
		| PORT EQUAL error    { yyerror("number expected"); } 
		| CHILDREN EQUAL NUMBER { children_no=$3; }
		| CHILDREN EQUAL error { yyerror("number expected"); } 
		| CHECK_VIA EQUAL NUMBER { check_via=$3; }
		| CHECK_VIA EQUAL error { yyerror("boolean value expected"); }
		| LISTEN EQUAL ipv4  {
								if (addresses_no < MAX_LISTEN){
									tmp=inet_ntoa(*(struct in_addr*)&$3);
									names[addresses_no]=(char*)malloc(strlen(tmp)+1);
									if (names[addresses_no]==0){
										LOG(L_CRIT, "ERROR: cfg. parser: out of memory.\n");
									}else{
										strncpy(names[addresses_no], tmp, strlen(tmp)+1);
										addresses_no++;
									}
								}else{
									LOG(L_CRIT, "ERROR: cfg. parser: too many listen addresses"
												"(max. %d).\n", MAX_LISTEN);
								}
							  }
		| LISTEN EQUAL ID	 {
								if (addresses_no < MAX_LISTEN){
									names[addresses_no]=(char*)malloc(strlen($3)+1);
									if (names[addresses_no]==0){
										LOG(L_CRIT, "ERROR: cfg. parser: out of memory.\n");
									}else{
										strncpy(names[addresses_no], $3, strlen($3)+1);
										addresses_no++;
									}
								}else{
									LOG(L_CRIT, "ERROR: cfg. parser: too many listen addresses"
												"(max. %d).\n", MAX_LISTEN);
								}
							  }
		| LISTEN EQUAL STRING {
								if (addresses_no < MAX_LISTEN){
									names[addresses_no]=(char*)malloc(strlen($3)+1);
									if (names[addresses_no]==0){
										LOG(L_CRIT, "ERROR: cfg. parser: out of memory.\n");
									}else{
										strncpy(names[addresses_no], $3, strlen($3)+1);
										addresses_no++;
									}
								}else{
									LOG(L_CRIT, "ERROR: cfg. parser: too many listen addresses"
												"(max. %d).\n", MAX_LISTEN);
								}
							  }
		| LISTEN EQUAL  error { yyerror("ip address or hostname"
						"expected"); }
		| error EQUAL { yyerror("unknown config variable"); }
	;


ipv4:	NUMBER DOT NUMBER DOT NUMBER DOT NUMBER { 
											if (($1>255) || ($1<0) ||
												($3>255) || ($3<0) ||
												($5>255) || ($5<0) ||
												($7>255) || ($7<0)){
												yyerror("invalid ipv4"
														"address");
												$$=0;
											}else{
												$$=htonl( ($1<<24)|
													($3<<16)| ($5<<8)|$7 );
											}
												}
	;

route_stm:	ROUTE LBRACE rules RBRACE { push($3, &rlist[DEFAULT_RT]); }

		| ROUTE LBRACK NUMBER RBRACK LBRACE rules RBRACE { 
										if (($3<RT_NO) && ($3>=0)){
											push($6, &rlist[$3]);
										}else{
											yyerror("invalid routing"
													"table number");
											YYABORT; }
										}
		| ROUTE error { yyerror("invalid  route  statement"); }
	;

rules:	rules rule { push($2, &$1); $$=$1; }
	| rule {$$=$1; }
	| rules error { $$=0; yyerror("invalid rule"); }
	 ;

rule:	condition	actions CR {
								$$=0;
								if (add_rule($1, $2, &$$)<0) {
									yyerror("error calling add_rule");
									YYABORT;
								}
							  }
	| CR  /* null rule */		{ $$=0;}
	| condition error { $$=0; yyerror("bad actions in rule"); }
	;

condition:	exp {$$=$1;}
	;

exp:	exp AND exp 	{ $$=mk_exp(AND_OP, $1, $3); }
	| exp OR  exp		{ $$=mk_exp(OR_OP, $1, $3);  }
	| NOT exp 			{ $$=mk_exp(NOT_OP, $2, 0);  }
	| LPAREN exp RPAREN	{ $$=$2; }
	| exp_elem			{ $$=$1; }
	;

exp_elem:	METHOD EQUAL_T STRING	{$$= mk_elem(	EQUAL_OP, STRING_ST, 
													METHOD_O, $3);
									}
		| METHOD EQUAL_T ID	{$$ = mk_elem(	EQUAL_OP, STRING_ST,
											METHOD_O, $3); 
				 			}
		| METHOD EQUAL_T error { $$=0; yyerror("string expected"); }
		| METHOD MATCH STRING	{$$ = mk_elem(	MATCH_OP, STRING_ST,
												METHOD_O, $3); 
				 				}
		| METHOD MATCH ID	{$$ = mk_elem(	MATCH_OP, STRING_ST,
											METHOD_O, $3); 
				 			}
		| METHOD MATCH error { $$=0; yyerror("string expected"); }
		| METHOD error	{ $$=0; yyerror("invalid operator,"
										"== or =~ expected");
						}
		| URI EQUAL_T STRING 	{$$ = mk_elem(	EQUAL_OP, STRING_ST,
												URI_O, $3); 
				 				}
		| URI EQUAL_T ID 	{$$ = mk_elem(	EQUAL_OP, STRING_ST,
											URI_O, $3); 
				 			}
		| URI EQUAL_T error { $$=0; yyerror("string expected"); }
		| URI MATCH STRING	{ $$=mk_elem(	MATCH_OP, STRING_ST,
											URI_O, $3);
							}
		| URI MATCH ID		{ $$=mk_elem(	MATCH_OP, STRING_ST,
											URI_O, $3);
							}
		| URI MATCH error {  $$=0; yyerror("string expected"); }
		| URI error	{ $$=0; yyerror("invalid operator,"
				  					" == or =~ expected");
					}
		| SRCIP EQUAL_T net4	{ $$=mk_elem(	EQUAL_OP, NET_ST,
												SRCIP_O, $3);
								}
		| SRCIP EQUAL_T STRING	{ $$=mk_elem(	EQUAL_OP, STRING_ST,
												SRCIP_O, $3);
								}
		| SRCIP EQUAL_T host	{ $$=mk_elem(	EQUAL_OP, STRING_ST,
												SRCIP_O, $3);
								}
		| SRCIP EQUAL_T error { $$=0; yyerror( "ip address or hostname"
						 "expected" ); }
		| SRCIP MATCH STRING	{ $$=mk_elem(	MATCH_OP, STRING_ST,
												SRCIP_O, $3);
								}
		| SRCIP MATCH ID		{ $$=mk_elem(	MATCH_OP, STRING_ST,
												SRCIP_O, $3);
								}
		| SRCIP MATCH error  { $$=0; yyerror( "hostname expected"); }
		| SRCIP error  { $$=0; 
						 yyerror("invalid operator, == or =~ expected");}
		| DSTIP EQUAL_T net4	{ $$=mk_elem(	EQUAL_OP, NET_ST,
												DSTIP_O, $3);
								}
		| DSTIP EQUAL_T STRING	{ $$=mk_elem(	EQUAL_OP, STRING_ST,
												DSTIP_O, $3);
								}
		| DSTIP EQUAL_T host	{ $$=mk_elem(	EQUAL_OP, STRING_ST,
												DSTIP_O, $3);
								}
		| DSTIP EQUAL_T error { $$=0; yyerror( "ip address or hostname"
						 			"expected" ); }
		| DSTIP MATCH STRING	{ $$=mk_elem(	MATCH_OP, STRING_ST,
												DSTIP_O, $3);
								}
		| DSTIP MATCH ID	{ $$=mk_elem(	MATCH_OP, STRING_ST,
											DSTIP_O, $3);
							}
		| DSTIP MATCH error  { $$=0; yyerror ( "hostname  expected" ); }
		| DSTIP error { $$=0; 
						yyerror("invalid operator, == or =~ expected");}
	;

net4:	ipv4 SLASH ipv4	{ $$=mk_net($1, $3); } 
	| ipv4 SLASH NUMBER {	if (($3>32)|($3<0)){
								yyerror("invalid bit number in netmask");
								$$=0;
							}else{
								$$=mk_net($1, htonl( ($3)?~( (1<<32-$3)-1 ):0 ) );
							}
						}
	| ipv4				{ $$=mk_net($1, 0xffffffff); }
	| ipv4 SLASH error { $$=0;
						 yyerror("netmask (eg:255.0.0.0 or 8) expected");}
	;

host:	ID				{ $$=$1; }
	| host DOT ID		{ $$=(char*)malloc(strlen($1)+1+strlen($3)+1);
						  if ($$==0){
						  	LOG(L_CRIT, "ERROR: cfg. parser: memory allocation failure"
						 				" while parsing host\n");
						  }else{
						  	memcpy($$, $1, strlen($1));
						  	$$[strlen($1)]='.';
						  	memcpy($$+strlen($1)+1, $3, strlen($3));
						  	$$[strlen($1)+1+strlen($3)]=0;
						  }
						  free($1); free($3);
						};
	| host DOT error { $$=0; free($1); yyerror("invalid hostname"); }
	;


actions:	actions action	{$$=append_action($1, $2); }
		| action			{$$=$1;}
		| actions error { $$=0; yyerror("bad command"); }
	;

action:		cmd SEMICOLON {$$=$1;}
		| SEMICOLON /* null action */ {$$=0;}
		| cmd error { $$=0; yyerror("bad command: missing ';'?"); }
	;

cmd:		FORWARD LPAREN host RPAREN	{ $$=mk_action(	FORWARD_T,
														STRING_ST,
														NUMBER_ST,
														$3,
														0);
										}
		| FORWARD LPAREN STRING RPAREN	{ $$=mk_action(	FORWARD_T,
														STRING_ST,
														NUMBER_ST,
														$3,
														0);
										}
		| FORWARD LPAREN ipv4 RPAREN	{ $$=mk_action(	FORWARD_T,
														IP_ST,
														NUMBER_ST,
														(void*)$3,
														0);
										}
		| FORWARD LPAREN host COMMA NUMBER RPAREN { $$=mk_action(FORWARD_T,
																 STRING_ST,
																 NUMBER_ST,
																$3,
																(void*)$5);
												 }
		| FORWARD LPAREN STRING COMMA NUMBER RPAREN {$$=mk_action(FORWARD_T,
																 STRING_ST,
																 NUMBER_ST,
																$3,
																(void*)$5);
													}
		| FORWARD LPAREN ipv4 COMMA NUMBER RPAREN { $$=mk_action(FORWARD_T,
																 IP_ST,
																 NUMBER_ST,
																 (void*)$3,
																(void*)$5);
												  }
		| FORWARD error { $$=0; yyerror("missing '(' or ')' ?"); }
		| FORWARD LPAREN error RPAREN { $$=0; yyerror("bad forward"
										"argument"); }
		| SEND LPAREN host RPAREN	{ $$=mk_action(	SEND_T,
													STRING_ST,
													NUMBER_ST,
													$3,
													0);
									}
		| SEND LPAREN STRING RPAREN { $$=mk_action(	SEND_T,
													STRING_ST,
													NUMBER_ST,
													$3,
													0);
									}
		| SEND LPAREN ipv4 RPAREN	{ $$=mk_action(	SEND_T,
													IP_ST,
													NUMBER_ST,
													(void*)$3,
													0);
									}
		| SEND LPAREN host COMMA NUMBER RPAREN	{ $$=mk_action(	SEND_T,
																STRING_ST,
																NUMBER_ST,
																$3,
																(void*)$5);
												}
		| SEND LPAREN STRING COMMA NUMBER RPAREN {$$=mk_action(	SEND_T,
																STRING_ST,
																NUMBER_ST,
																$3,
																(void*)$5);
												}
		| SEND LPAREN ipv4 COMMA NUMBER RPAREN { $$=mk_action(	SEND_T,
																IP_ST,
																NUMBER_ST,
																(void*)$3,
																(void*)$5);
											   }
		| SEND error { $$=0; yyerror("missing '(' or ')' ?"); }
		| SEND LPAREN error RPAREN { $$=0; yyerror("bad send"
													"argument"); }
		| DROP LPAREN RPAREN	{$$=mk_action(DROP_T,0, 0, 0, 0); }
		| DROP					{$$=mk_action(DROP_T,0, 0, 0, 0); }
		| LOG_TOK LPAREN STRING RPAREN	{$$=mk_action(	LOG_T, NUMBER_ST, 
													STRING_ST,(void*)4,$3);
									}
		| LOG_TOK LPAREN NUMBER COMMA STRING RPAREN	{$$=mk_action(	LOG_T,
																NUMBER_ST, 
																STRING_ST,
																(void*)$3,
																$5);
												}
		| LOG_TOK error { $$=0; yyerror("missing '(' or ')' ?"); }
		| LOG_TOK LPAREN error RPAREN { $$=0; yyerror("bad log"
									"argument"); }
		| ERROR LPAREN STRING COMMA STRING RPAREN {$$=mk_action(ERROR_T,
																STRING_ST, 
																STRING_ST,
																$3,
																$5);
												  }
												
		| ERROR error { $$=0; yyerror("missing '(' or ')' ?"); }
		| ERROR LPAREN error RPAREN { $$=0; yyerror("bad error"
														"argument"); }
		| ROUTE LPAREN NUMBER RPAREN	{ $$=mk_action(ROUTE_T, NUMBER_ST,
														0, (void*)$3, 0);
										}
		| ROUTE error { $$=0; yyerror("missing '(' or ')' ?"); }
		| ROUTE LPAREN error RPAREN { $$=0; yyerror("bad route"
						"argument"); }
		| EXEC LPAREN STRING RPAREN	{ $$=mk_action(	EXEC_T, STRING_ST, 0,
													$3, 0);
									}
		| SET_HOST LPAREN STRING RPAREN { $$=mk_action( SET_HOST_T, STRING_ST, 0, $3, 0); }
		| SET_HOST error { $$=0; yyerror("missing '(' or ')' ?"); }
		| SET_HOST LPAREN error RPAREN { $$=0; yyerror("bad argument, string expected"); }
		| SET_HOSTPORT LPAREN STRING RPAREN { $$=mk_action( SET_HOSTPORT_T, STRING_ST, 0, $3, 0); }
		| SET_HOSTPORT error { $$=0; yyerror("missing '(' or ')' ?"); }
		| SET_HOSTPORT LPAREN error RPAREN { $$=0; yyerror("bad argument, string expected"); }
		| SET_PORT LPAREN STRING RPAREN { $$=mk_action( SET_PORT_T, STRING_ST, 0, $3, 0); }
		| SET_PORT error { $$=0; yyerror("missing '(' or ')' ?"); }
		| SET_PORT LPAREN error RPAREN { $$=0; yyerror("bad argument, string expected"); }
		| SET_USER LPAREN STRING RPAREN { $$=mk_action( SET_USER_T, STRING_ST, 0, $3, 0); }
		| SET_USER error { $$=0; yyerror("missing '(' or ')' ?"); }
		| SET_USER LPAREN error RPAREN { $$=0; yyerror("bad argument, string expected"); }
		| SET_USERPASS LPAREN STRING RPAREN { $$=mk_action( SET_USERPASS_T, STRING_ST, 0, $3, 0); }
		| SET_USERPASS error { $$=0; yyerror("missing '(' or ')' ?"); }
		| SET_USERPASS LPAREN error RPAREN { $$=0; yyerror("bad argument, string expected"); }
		| SET_URI LPAREN STRING RPAREN { $$=mk_action( SET_URI_T, STRING_ST, 0, $3, 0); }
		| SET_URI error { $$=0; yyerror("missing '(' or ')' ?"); }
		| SET_URI LPAREN error RPAREN { $$=0; yyerror("bad argument, string expected"); }
	;


%%

extern int line;
extern int column;
extern int startcolumn;
void yyerror(char* s)
{
	LOG(L_CRIT, "parse error (%d,%d-%d): %s\n", line, startcolumn, 
			column, s);
	cfg_errors++;
}

/*
int main(int argc, char ** argv)
{
	if (yyparse()!=0)
		fprintf(stderr, "parsing error\n");
}
*/
