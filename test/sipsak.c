/* sipsak written by nils ohlmeier (ohlmeier@fokus.gmd.de).
based up on a modifyed version of shoot.
set DEBUG on compile will produce much more output, primary
it will print out the sended and received messages before or after
every network action.
*/

/*
shot written by ashhar farhan, is not bound by any licensing at all.
you are free to use this code as you deem fit. just dont blame the author
for any problems you may have using it.
bouquets and brickbats to farhan@hotfoon.com
*/

/* changes by jiri@iptel.org; now messages can be really received;
   status code returned is 2 for some local errors , 0 for success
   and 1 for remote error -- ICMP/timeout; can be used to test if
   a server is alive; 1xx messages are now ignored; windows support
   dropped
*/

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/utsname.h>

#include <regex.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>

#define SIPSAK_VERSION "v0.1"
#define RESIZE		1024
#define BUFSIZE		1500
#define FQDN_SIZE   200
#define REQ_INV 1
#define REQ_REG 2
#define REQ_OPT 3
#define VIA_STR "Via: SIP/2.0/UDP "
#define VIA_STR_LEN 17
#define MAX_FRW_STR "Max-Forwards: "
#define MAX_FRW_STR_LEN 14
#define SIP20_STR " SIP/2.0\r\n"
#define SIP20_STR_LEN 10
#define SIP200_STR "SIP/2.0 200 OK\r\n"
#define SIP200_STR_LEN 16
#define REG_STR "REGISTER"
#define REG_STR_LEN 8
#define OPT_STR "OPTIONS"
#define OPT_STR_LEN 7
#define MES_STR "MESSAGE"
#define MES_STR_LEN 7
#define FROM_STR "From: "
#define FROM_STR_LEN 6
#define TO_STR "To: "
#define TO_STR_LEN 4
#define CALL_STR "Call-ID: "
#define CALL_STR_LEN 9
#define CSEQ_STR "CSeq: "
#define CSEQ_STR_LEN 6
#define CONT_STR "Contact: "
#define CONT_STR_LEN 9
#define CON_TXT_STR "Content-Type: text/plain\r\n"
#define CON_TXT_STR_LEN 26
#define CON_LEN_STR "Content-Length: "
#define CON_LEN_STR_LEN 16
#define SIPSAK_MES_STR "USRLOC test message from SIPsak for user "
#define SIPSAK_MES_STR_LEN 41
#define EXP_STR "Expires: "
#define EXP_STR_LEN 9
#define USRLOC_EXP_DEF 16

int verbose, nameend, namebeg;
char *username, *domainname;
char fqdn[FQDN_SIZE];
char message[BUFSIZE], mes_reply[BUFSIZE];

/* take either a dot.decimal string of ip address or a 
domain name and returns a NETWORK ordered long int containing
the address. i chose to internally represent the address as long for speedier
comparisions.

any changes to getaddress have to be patched back to the net library.
contact: farhan@hotfoon.com

  returns zero if there is an error.
  this is convenient as 0 means 'this' host and the traffic of
  a badly behaving dns system remains inside (you send to 0.0.0.0)
*/

long getaddress(char *host)
{
	int i, dotcount=0;
	char *p = host;
	struct hostent* pent;
	long l, *lp;

	/*try understanding if this is a valid ip address
	we are skipping the values of the octets specified here.
	for instance, this code will allow 952.0.320.567 through*/
	while (*p)
	{
		for (i = 0; i < 3; i++, p++)
			if (!isdigit(*p))
				break;
		if (*p != '.')
			break;
		p++;
		dotcount++;
	}

	/* three dots with upto three digits in before, between and after ? */
	if (dotcount == 3 && i > 0 && i <= 3)
		return inet_addr(host);

	/* try the system's own resolution mechanism for dns lookup:
	 required only for domain names.
	 inspite of what the rfc2543 :D Using SRV DNS Records recommends,
	 we are leaving it to the operating system to do the name caching.

	 this is an important implementational issue especially in the light
	 dynamic dns servers like dynip.com or dyndns.com where a dial
	 ip address is dynamically assigned a sub domain like farhan.dynip.com

	 although expensive, this is a must to allow OS to take
	 the decision to expire the DNS records as it deems fit.
	*/
	pent = gethostbyname(host);
	if (!pent) {
		perror("no gethostbyname");
		exit(2);
	}
	lp = (long *) (pent->h_addr);
	l = *lp;
	return l;
}

/* because the full qualified domain name is needed by many other
   functions it will be determined by this function.*/
void get_fqdn(){
	char hname[100], dname[100];
	size_t namelen=100;

	if (gethostname(&hname[0], namelen) < 0) {
		printf("error: cannot determine domainname\n");
		exit(2);
	}
	/* a hostname with dots should be a domainname */
	if ((strchr(hname, '.'))==NULL) {
#ifdef DEBUG
		printf("hostname without dots. determine domainname...\n");
#endif
		if (getdomainname(&dname[0], namelen) < 0) {
			printf("error: cannot determine domainname\n");
			exit(2);
		}
		sprintf(fqdn, "%s.%s", hname, dname);
	}
	else {
		strcpy(fqdn, hname);
	}

#ifdef DEBUG
	printf("fqdnhostname: %s\n", fqdn);
#endif
}

/* add a Via Header Field in the message.
*/
void add_via(char *mes, int port)
{
	char *via_line, *via, *backup; 

	/* first build our own Via-header-line */
	via_line = malloc(VIA_STR_LEN+strlen(fqdn)+9);
	sprintf(via_line, "%s%s:%i\r\n", VIA_STR, fqdn, port);
#ifdef DEBUG
	printf("our Via-Line: %s\n", via_line);
#endif

	if (strlen(mes)+strlen(via_line)>= BUFSIZE){
		printf("can't add our Via Header Line because file is too big\n");
		exit(2);
	}
	if ((via=strstr(mes,"Via:"))==NULL){
		/* We doesn't find a Via so we insert our via
		   direct after the first line. */
		via=strchr(mes,'\n');
		via++;
	}
	/* finnaly make a backup, insert our via and append the backup */
	backup=malloc(strlen(via)+1);
	strncpy(backup, via, strlen(via)+1);
	strncpy(via, via_line, strlen(via_line));
	strncpy(via+strlen(via_line), backup, strlen(backup)+1);
	free(via_line);
	free(backup);
	if (verbose)
		printf("New message with Via-Line:\n%s\n", mes);
}

/* copy the via lines from the message to the message 
   reply for correct routing of our reply.*/
void cpy_vias(char *reply){
	char *first_via, *middle_via, *last_via, *backup;

	/* lets see if we find any via */
	if ((first_via=strstr(reply, "Via:"))==NULL){
		printf("error: the received message doesn't contain a Via header\n");
		exit(1);
	}
	last_via=first_via+4;
	middle_via=last_via;
	/* proceed additional via lines */
	while ((middle_via=strstr(last_via, "Via:"))!=NULL)
		last_via=middle_via+4;
	last_via=strchr(last_via, '\n');
	middle_via=strchr(mes_reply, '\n')+1;
	/* make a backup, insert the vias after the first line and append 
	backup */
	backup=malloc(strlen(middle_via)+1);
	strcpy(backup, middle_via);
	strncpy(middle_via, first_via, last_via-first_via+1);
	strcpy(middle_via+(last_via-first_via+1), backup);
	free(backup);
#ifdef DEBUG
	printf("message reply with vias included:\n%s\n", mes_reply);
#endif
}

/* create a valid sip header out of the given parameters */
void create_msg(char *buff, int action, int lport){
	unsigned int c;
	char *usern;

	/* this is not a cryptographic random number generator,
	   but hey this is only a test-tool => should be satisfying*/
	srand(time(0));
	c=rand();
	switch (action){
		case REQ_REG:
#ifdef DEBUG
			printf("username: %s\ndomainname: %s\n", username, domainname);
#endif
			usern=malloc(strlen(username)+6);
			sprintf(usern, "%s%i", username, namebeg);
			/* build the register, message and the 200 we need in for 
			   USRLOC on one function call*/
			sprintf(buff, "%s sip:%s:%i%s%s%s:%i\r\n%s<sip:%s@%s>\r\n%s<sip:%s@%s>\r\n%s%u@%s\r\n%s%i %s\r\n%s<sip:%s@%s:%i>\r\n%s%i\r\n\r\n", REG_STR, fqdn, lport, SIP20_STR, VIA_STR, fqdn, lport, FROM_STR, usern, domainname, TO_STR, usern, domainname, CALL_STR, c, fqdn, CSEQ_STR, 3*namebeg, REG_STR, CONT_STR, usern, fqdn, lport, EXP_STR, USRLOC_EXP_DEF);
			c=rand();
			sprintf(message, "%s im:%s@%s%s%s%s:%i\r\n%s<sip:sipsak@%s:%i>\r\n%s<sip:%s@%s>\r\n%s%u@%s\r\n%s%i %s\r\n%s%s%i\r\n\r\n%s%s%i.", MES_STR, usern, domainname, SIP20_STR, VIA_STR, fqdn, lport, FROM_STR, fqdn, lport, TO_STR, usern, domainname, CALL_STR, c, fqdn, CSEQ_STR, 3*namebeg+1, MES_STR, CON_TXT_STR, CON_LEN_STR, SIPSAK_MES_STR_LEN+strlen(usern), SIPSAK_MES_STR, username, namebeg);
			sprintf(mes_reply, "%s%s<sip:sipsak@%s:%i>\r\n%s<sip:%s@%s>\r\n%s%u@%s\r\n%s%i %s\r\n%s 0\r\n\r\n", SIP200_STR, FROM_STR, fqdn, lport, TO_STR, usern, domainname, CALL_STR, c, fqdn, CSEQ_STR, 3*namebeg+1, MES_STR, CON_LEN_STR);
#ifdef DEBUG
			printf("message:\n%s\n", message);
			printf("message reply:\n%s\n", mes_reply);
#endif
			free(usern);
			break;
		case REQ_OPT:
			sprintf(buff, "%s sip:%s@%s%s%s<sip:sipsak@%s:%i>\r\n%s<sip:%s@%s>\r\n%s%u@%s\r\n%s%i %s\r\n%s<sip:sipsak@%s:%i>\r\n\r\n", OPT_STR, username, domainname, SIP20_STR, FROM_STR, fqdn, lport, TO_STR, username, domainname, CALL_STR, c, fqdn, CSEQ_STR, namebeg, OPT_STR, CONT_STR, fqdn, lport);
			break;
		default:
			printf("error: unknown request type to create\n");
			exit(2);
			break;
	}
#ifdef DEBUG
	printf("request:\n%s", buff);
#endif
}

/* check for the existence of a Max-Forwards header field. if its 
   present it sets it to the given value, if not it will be inserted.*/
void set_maxforw(char *mes, int maxfw){
	char *max, *backup, *crlf;

	if ((max=strstr(mes,"Max-Forwards"))==NULL){
		/* no max-forwards found so insert it after the first line*/
		max=strchr(mes,'\n');
		max++;
		backup=malloc(strlen(max)+1);
		strncpy(backup, max, strlen(max)+1);
		sprintf(max, "%s%i\r\n", MAX_FRW_STR, maxfw);
		max=strchr(max,'\n');
		max++;
		strncpy(max, backup, strlen(backup)+1);
		free(backup);
		if (verbose)
			printf("Max-Forwards %i inserted into header\n", maxfw);
#ifdef DEBUG
		printf("New message with inserted Max-Forwards:\n%s\n", mes);
#endif
	}
	else{
		/* found max-forwards => overwrite the value with maxfw*/
		crlf=strchr(max,'\n');
		crlf++;
		backup=malloc(strlen(crlf)+1);
		strncpy(backup, crlf, strlen(crlf)+1);
		crlf=max + MAX_FRW_STR_LEN;
		sprintf(crlf, "%i\r\n", maxfw);
		crlf=strchr(max,'\n');
		crlf++;
		strncpy(crlf, backup, strlen(backup)+1);
		crlf=crlf+strlen(backup);
		free(backup);
		if (verbose)
			printf("Max-Forwards set to %i\n", maxfw);
#ifdef DEBUG
		printf("New message with changed Max-Forwards:\n%s\n", mes);
#endif
	}
}



/* replaces the uri in first line of mes with the other uri */
void uri_replace(char *mes, char *uri)
{
	char *foo, *backup;

	foo=strchr(mes, '\n');
	foo++;
	backup=malloc(strlen(foo)+1);
	strncpy(backup, foo, strlen(foo)+1);
	foo=strstr(mes, "sip");
	strncpy(foo, uri, strlen(uri));
	strncpy(foo+strlen(uri), SIP20_STR, SIP20_STR_LEN);
	strncpy(foo+strlen(uri)+SIP20_STR_LEN, backup, strlen(backup)+1);
	free(backup);
#ifdef DEBUG
	printf("Message with modified uri:\n%s\n", mes);
#endif
}

/*
shoot:
takes:
	1. the text message of buff to 
	2. the address (network orderd byte order)
	3. local- and remote-port (not network byte ordered).
	4. and lots of boolean for the different modi

starting from half a second, times-out on replies and
keeps retrying with exponential back-off that flattens out
at 5 seconds (5000 milliseconds).
*/
void shoot(char *buff, long address, int lport, int rport, int maxforw, int trace, int vbool, int fbool, int usrloc, int redirects)
{
	struct sockaddr_in	addr, sockname;
	struct timeval	tv;
	struct pollfd sockerr;
	int ssock, redirected, retryAfter, nretries;
	int sock, i, len, ret, usrlocstep;
	char	*contact, *crlf, *foo, *bar;
	char	reply[1600];
	fd_set	fd;
	socklen_t slen;
	regex_t* regexp;
	regex_t* redexp;

	redirected = 1;
	nretries = 5;
	retryAfter = 500;
	usrlocstep = 0;

	/* create a sending socket */
	sock = (int)socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock==-1) {
		perror("no client socket");
		exit(2);
	}

	/* create a listening socket */
	ssock = (int)socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ssock==-1) {
		perror("no server socket");
		exit(2);
	}

	sockname.sin_family=AF_INET;
	sockname.sin_addr.s_addr = htonl( INADDR_ANY );
	sockname.sin_port = htons((short)lport);
	if (bind( ssock, (struct sockaddr *) &sockname, sizeof(sockname) )==-1) {
		perror("no bind");
		exit(2);
	}

	/* for the via line we need our listening port number */
	if ((vbool||usrloc) && lport==0){
		memset(&sockname, 0, sizeof(sockname));
		slen=sizeof(sockname);
		getsockname(ssock, (struct sockaddr *)&sockname, &slen);
		lport=ntohs(sockname.sin_port);
	}

	/* set a regular expression according to the modus */
	regexp=(regex_t*)malloc(sizeof(regex_t));
	if (trace)
		regcomp(regexp, "^SIP/[0-9]\\.[0-9] 483 ", REG_EXTENDED|REG_NOSUB|REG_ICASE); 
	else if (usrloc)
		regcomp(regexp, "^SIP/[0-9]\\.[0-9] 200 ", REG_EXTENDED|REG_NOSUB|REG_ICASE); 
	else
		regcomp(regexp, "^SIP/[0-9]\\.[0-9] 1[0-9][0-9] ", REG_EXTENDED|REG_NOSUB|REG_ICASE); 
	/* catching redirects */
	redexp=(regex_t*)malloc(sizeof(regex_t));
	regcomp(redexp, "^SIP/[0-9]\\.[0-9] 3[0-9][0-9] ", REG_EXTENDED|REG_NOSUB|REG_ICASE); 

	/* determine our hostname */
	get_fqdn();

	if (usrloc){
		nretries=3*(nameend-namebeg)+3;
		create_msg(buff, REQ_REG, lport);
		retryAfter = 5000;
	}
	if (trace & !fbool)
		create_msg(buff, REQ_OPT, lport);
	if(maxforw)
		set_maxforw(buff, maxforw);
	if(vbool)
		add_via(buff, lport);
	
	if (trace) {
		if (maxforw)
			nretries=maxforw;
		else
			nretries=255;
	}

	/* if we got a redirect this loop ensures sending to the 
	   redirected server*/
	while (redirected) {

		redirected=0;

		addr.sin_addr.s_addr = address;
		addr.sin_port = htons((short)rport);
		addr.sin_family = AF_INET;
	
		/* we connect as per the RFC 2543 recommendations
		modified from sendto/recvfrom */
		ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
		if (ret==-1) {
			perror("no connect");
			exit(2);
		}

		for (i = 0; i < nretries; i++)
		{
			if (trace) {
				set_maxforw(buff, i+1);
			}
			else if (usrloc && verbose) {
				switch (usrlocstep) {
					case 0:
						printf("registering user %s%i... ", username, namebeg);
						break;
					case 1:
						printf("sending message... ");
						break;
					case 2:
						printf("sending message reply... ");
						break;
				}
			}
			else if (!trace && !usrloc){
				printf("** request **\n%s\n", buff);
			}

			ret = send(sock, buff, strlen(buff), 0);
			if (ret==-1) {
				perror("send failure");
				exit( 1 );
			}
		

			tv.tv_sec = retryAfter/1000;
			tv.tv_usec = (retryAfter % 1000) * 1000;

			FD_ZERO(&fd);
			FD_SET(ssock, &fd); 

			//ret = select(6, &fd, NULL, NULL, &tv);
			ret = select(FD_SETSIZE, &fd, NULL, NULL, &tv);
			if (ret == 0)
			{
				sockerr.fd=sock;
				sockerr.events=POLLERR;
				if ((poll(&sockerr, 1, 10))==1) {
					if (sockerr.revents && POLLERR) {
						printf("send failure:\n");
						recv(sock, reply, strlen(reply), 0);
						perror("");
						exit(1);
					}
				}
				printf("** timeout **\n");
				retryAfter = retryAfter * 2;
				if (retryAfter > 5000)
					retryAfter = 5000;
				/* we should have retrieved the error code and displayed
				we are not doing that because there is a great variation
				in the process of retrieveing error codes between
				micro$oft and *nix world*/
				continue;
			} else if ( ret == -1 ) {
				perror("select error");
				exit(2);
			} /* no timeout, no error ... something has happened :-) */
			else if (FD_ISSET(ssock, &fd)) {
			 	if (!trace && !usrloc)
					puts ("\nmessage received");
			} else {
				puts("\nselect returned succesfuly, nothing received\n");
				continue;
			}

			/* we are retrieving only the extend of a decent MSS = 1500 bytes */
			len = sizeof(addr);
			ret = recv(ssock, reply, 1500, 0);
			if(ret > 0)
			{
				reply[ret] = 0;
				if (redirects && regexec((regex_t*)redexp, reply, 0, 0, 0)==0) {
					printf("** received redirect **\n");
					/* we'll try to handle 301 and 302 here, other 3xx are to complex */
					regcomp(redexp, "^SIP/[0-9]\\.[0-9] 30[1-2] ", REG_EXTENDED|REG_NOSUB|REG_ICASE);
					if (regexec((regex_t*)redexp, reply, 0, 0, 0)==0) {
						/* try to find the contact in the redirect */
						if ((foo=strstr(reply, "Contact"))==NULL) {
							printf("error: cannot find Contact in this redirect:\n%s\n", reply);
							exit(2);
						}
						crlf=strchr(foo, '\n');
						if ((contact=strchr(foo, '\r'))!=NULL && contact<crlf)
							crlf=contact;
						bar=malloc(crlf-foo+1);
						strncpy(bar, foo, crlf-foo);
						sprintf(bar+(crlf-foo), "\0");
						if ((contact=strstr(bar, "sip"))==NULL) {
							printf("error: cannot find sip in the Contact of this redirect:\n%s\n", reply);
							exit(2);
						}
						if ((foo=strchr(contact, ';'))!=NULL)
							*foo='\0';
						if ((foo=strchr(contact, '>'))!=NULL)
							*foo='\0';
						if ((crlf=strchr(contact,':'))!=NULL){
							crlf++;
							/* extract the needed information*/
							if ((foo=strchr(crlf,':'))!=NULL){
								*foo='\0';
								foo++;
								rport = atoi(foo);
								if (!rport) {
									printf("error: cannot handle the port in the uri in Contact:\n%s\n", reply);
									exit(2);
								}
							}
							/* correct our request */
							uri_replace(buff, contact);
							if ((foo=strchr(contact,'@'))!=NULL){
								foo++;
								crlf=foo;
							}
							/* get the new destination IP*/
							address = getaddress(crlf);
							if (!address){
								printf("error: cannot determine host address from Contact of redirect:\%s\n", reply);
								exit(2);
							}
						}
						else{
							printf("error: missing : in Contact of this redirect:\n%s\n", reply);
							exit(2);
						}
						free(bar);
						memset(&addr, 0, sizeof(addr));
						redirected=1;
						i=nretries;
					}
					else {
						printf("error: cannot handle this redirect:\n%s\n", reply);
						exit(2);
					}
				}
				else if (trace) {
					/* in trace we only look for 483, anything else is 
					   treated as the final reply*/
					printf("%i: ", i+1);
					if (regexec((regex_t*)regexp, reply, 0, 0, 0)==0) {
						printf("* (483) \n");
#ifdef DEBUG
						printf("%s\n", reply);
#endif
						continue;
					}
					else {
						crlf=strchr(reply,'\n');
						sprintf(crlf, "\0");
						printf("%s\n", reply);
						crlf++;
						contact=strstr(crlf, "Contact");
						if (contact){
						crlf=strchr(contact,'\n');
						sprintf(crlf, "\0");
						printf("   %s\n", contact);
						}
						else {
							printf("received reply without contact:\n%s\n"
								, reply);
						}
						exit(0);
					}
				}
				else if (usrloc) {
					switch (usrlocstep) {
						case 0:
							/* at first we have sended a register a look at the 
							   response now*/
							if (regexec((regex_t*)regexp, reply, 0, 0, 0)==0) {
								if (verbose)
									printf ("  OK\n");
#ifdef DEBUG
								printf("\n%s\n", reply);
#endif
								strcpy(buff, message);
								usrlocstep=1;
							}
							else {
								if (verbose)
									printf("received:\n%s\n", reply);
								printf("error: didn't received '200 OK' on regsiter. aborting\n");
								exit(1);
							}
							break;
						case 1:
							/* now we sended the message and look if its 
							   forwarded to us*/
							if (!strncmp(reply, MES_STR, MES_STR_LEN)) {
								if (verbose) {
									crlf=strstr(reply, "\r\n\r\n");
									crlf=crlf+4;
									printf("         received message\n  '%s'\n", crlf);
								}
#ifdef DEBUG
								printf("\n%s\n", reply);
#endif
								cpy_vias(reply);
								strcpy(buff, mes_reply);
								usrlocstep=2;
							}
							else {
								if (verbose)
									printf("received:\n%s", reply);
								printf("error: didn't received the 'MESSAGE' we sended. aborting\n");
								exit(1);
							}
							break;
						case 2:
							/* finnaly we sended our reply on the message and 
							   look if this is also forwarded to us*/
							if (regexec((regex_t*)regexp, reply, 0, 0, 0)==0) {
								if (verbose)
									printf("   reply received\n\n");
								else
									printf("USRLOC for %s%i completed successful\n", username, namebeg);
								if (namebeg==nameend) {
									printf("All USRLOC tests completed successful.\n");
									exit(0);
								}
								namebeg++;
								create_msg(buff, REQ_REG, lport);
								usrlocstep=0;
							}
							else {
								if (verbose)
									printf("received:\n%s\n", reply);
								printf("error: didn't received the '200 OK' that we sended as the reply on the message\n");
								exit(1);
							}
							break;
					}
				}
				else {
					/* in the normal send and reply case anything other then 
					   1xx will be treated as final response*/
					printf("** reply **\n%s\n", reply);
					if (regexec((regex_t*)regexp, reply, 0, 0, 0)==0) {
						puts(" provisional received; still waiting for a final response\n ");
						continue;
					} else {
						puts(" final received; congratulations!\n ");
						exit(0);
					}
				}
		
			} 
			else {
				perror("recv error");
				exit(2);
			}
		}

	}
	/* after all the retries, nothing has come back :-( */
	puts("** I give up retransmission....");
	exit(1);
}

int main(int argc, char *argv[])
{
	long	address;
	FILE	*pf;
	char	buff[BUFSIZE];
	int		length, c, fbool, sbool, tbool, vbool, ubool, dbool;
	int		maxforw, lport, rport;
	char	*delim, *delim2;

	/* some initialisation to be shure */
	username=NULL;
	verbose=0;
	namebeg=nameend=-1;

	fbool=sbool=tbool=lport=maxforw=ubool=0;
	vbool=dbool=1;
    rport=5060;
	memset(buff, 0, BUFSIZE);
	memset(message, 0, BUFSIZE);
	memset(mes_reply, 0, BUFSIZE);
	memset(fqdn, 0, FQDN_SIZE);

	/* lots of command line switches to handle*/
	while ((c=getopt(argc,argv,"b:de:f:hil:m:r:s:tuv")) != EOF){
		switch(c){
			case 'b':
				namebeg=atoi(optarg);
				if (namebeg==-1) {
					puts("error: non-numerical appendix begin for the username");
					exit(2);
				}
				break;
			case 'd':
				dbool=0;
				break;
			case 'e':
				nameend=atoi(optarg);
				if (nameend==-1) {
					puts("error: non-numerical appendix end for the username");
					exit(2);
				}
				break;
			case 'f':
				/* file is opened in binary mode so that the cr-lf is preserved */
				pf = fopen(optarg, "rb");
				if (!pf){
					puts("unable to open the file.\n");
					exit(2);
				}
				length  = fread(buff, 1, sizeof(buff), pf);
				if (length >= sizeof(buff)){
					printf("error:the file is too big. try files of less than %i bytes.\n", BUFSIZE);
					puts("      or recompile the program with bigger BUFSIZE defined.");
					exit(2);
				}
				fclose(pf);
				buff[length] = '\0';
				fbool=1;
				break;
			case 'h':
				printf("sipsak %s ", SIPSAK_VERSION);
#ifdef DEBUG
				printf("(compiled with DEBUG) ");
#endif
				printf("modi:\n"
						" shoot : sipsak -f filename -s sip:uri\n"
						" trace : sipsak [-f filename] -s sip:uri -t\n"
						" USRLOC: sipsak [-b number] -e number -s sip:uri -u\n"
						" additional parameter in every modus:\n"
						"                [-d] [-i] [-l port] [-m number] [-r port] [-v]\n"
						"   -h           displays this help message\n"
						"   -f filename  the file which contains the SIP message to send\n"
						"   -s sip:uri   the destination server uri in form sip:[user@]servername[:port]\n"
						"   -t           activates the traceroute modus\n"
						"   -u           activates the USRLOC modus\n"
						"   -b number    the starting number appendix to the user name in USRLOC modus\n"
						"   -e number    the ending numer of the appendix to the user name in USRLOC modus\n"
						"   -l port      the local port to use\n"
						"   -r port      the remote port to use\n"
						"   -m number    the value for the max-forwards header field\n"
						"   -i           deactivate the insertion of a Via-Line\n"
						"   -d           ignore redirects\n"
						"   -v           be more verbose\n"
						"The manupulation function are only tested with nice RFC conform SIP-messages,\n"
						"so don't expect them to work with ugly or malformed messages.\n");
				exit(0);
				break;
			case 'i':
				vbool=0;
				break;
			case 'l':
				lport=atoi(optarg);
				if (!lport) {
					puts("error: non-numerical local port number");
					exit(2);
				}
				break;
			case 'm':
				maxforw=atoi(optarg);
				if (!maxforw) {
					puts("error: non-numerical number of max-forwards");
					exit(2);
				}
			case 'r':
				rport=atoi(optarg);
				if (!rport) {
					puts("error: non-numerical remote port number");
					exit(2);
				}
				break;
			case 's':
				if (!strncmp(optarg,"sip",3)){
					if ((delim=strchr(optarg,':'))!=NULL){
						delim++;
						if ((delim2=strchr(delim,'@'))!=NULL){
							username=malloc(delim2-delim+1);
							strncpy(username, delim, delim2-delim);
							delim2++;
							delim=delim2;
						}
						if ((delim2=strchr(delim,':'))!=NULL){
							*delim2 = '\0';
							delim2++;
							rport = atoi(delim2);
							if (!rport) {
								puts("error: non-numerical remote port number");
								exit(2);
							}
						}
						domainname=malloc(strlen(delim)+1);
						strncpy(domainname, delim, strlen(delim));
						address = getaddress(delim);
						if (!address){
							puts("error:unable to determine the remote host address.");
							exit(2);
						}
					}
					else{
						puts("error: sip:uri doesn't contain a : ?!");
						exit(2);
					}
				}
				else{
					puts("error: sip:uri doesn't not begin with sip");
					exit(2);
				}
				sbool=1;
				break;			break;
			case 't':
				tbool=1;
				break;
			case 'u':
				ubool=1;
				break;
			case 'v':
				verbose=1;
				break;
			default:
				printf("error: unknown parameter %c\n", c);
				exit(2);
				break;
		}
	}

	/* lots of conditions to check */
	if (tbool && ubool) {
		printf("error: tracing and usrloc together isn't possible\n");
		exit(2);
	}

	if (tbool) {
		if (!sbool) {
			printf("error: for trace modus a sip:uri is realy needed\n");
			exit(2);
		}
		if (fbool) {
			if (strncmp(buff, "OPTIONS", 7)){
				printf("error: tracerouting only possible with an OPTIONS request.\n"
					"       Give another request file or convert it to an OPTIONS request.\n");
				exit(2);
			}
		}
		else {
			if (!username) {
				printf("error: for trace modus without a file the sip:uir have to contain a username\n");
				exit(2);
			}
		}
		if (!vbool){
			printf("warning: Via-Line is needed for tracing. Ignoring -i\n");
			vbool=1;
		}
	}
	else if (ubool) {
		if (!username || !sbool || nameend==-1) {
			printf("error: for the USRLOC modus you have to give a sip:uri with a "
					"username and the\n       username appendix end at least\n");
			exit(2);
		}
		if (vbool) {
			vbool=0;
		}
		if (dbool) {
			printf("warning: redirects are not expected in USRLOC. Enableling -d\n");
			dbool=0;
		}
		if (namebeg==-1)
			namebeg=0;
	}
	else if (!fbool & !sbool)
		printf("error: you have to give the file to send and the sip:uri at least.\n"
			"       see 'sipsak -h' for more help.\n");
	/* here we go...*/
	shoot(buff, address, lport, rport, maxforw, tbool, vbool, fbool, ubool, dbool);

	/* normaly we won't come back here, but to satisfy the compiler */
	return 0;
}


/*
shoot will exercise the all types of sip servers.
it is not to be used to measure round-trips and general connectivity.
use ping for that. 
written by farhan on 10th august, 2000.
*/

