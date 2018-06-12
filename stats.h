#ifndef stats_h
#define stats_h

#include <ctype.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>



#ifdef STATS


struct stats_s {

	unsigned int	process_index;
	pid_t		pid;
	time_t		start_time;

	unsigned long 

	/* received packets */

	received_requests_inv, 		/* received_requests */
	received_requests_ack,
	received_requests_cnc,
	received_requests_bye,
	received_requests_other,

	received_responses_1, 		/* received_requests */
	received_responses_2,
	received_responses_3,
	received_responses_4,
	received_responses_5,
	received_responses_6,
	received_responses_other,

	received_drops, 		/* all messages we received and did not process
					   successfully; reasons include SIP sanity checks 
					   (missing Vias, neither request nor response, 
					   failed parsing), ser errors (malloc, action
					   failure)
					*/

	/* sent */

	/* sent_requests */
	sent_requests_inv,
	sent_requests_ack,
	sent_requests_cnc,
	sent_requests_bye,
	sent_requests_other,

	/* sent responses */
	sent_responses_1,
	sent_responses_2,
	sent_responses_3,
	sent_responses_4,
	sent_responses_5,
	sent_responses_6,

	failed_on_send;			
			  
};


extern struct stats_s *stats;

void setstats( int child_index );
void dump_statistic( FILE *fp, struct stats_s *istats );
int dump_all_statistic();
int init_stats( int nr_of_processes );

#define _update_request( method, dir )			\
	{ if (stat_file!=NULL) switch( method ) {	\
          	case METHOD_INVITE: stats->dir##_requests_inv++; break;	\
          	case METHOD_ACK: stats->dir##_requests_ack++; break;		\
          	case METHOD_CANCEL: stats->dir##_requests_cnc++; break;	\
          	case METHOD_BYE: stats->dir##_requests_bye++; break;		\
          	case METHOD_OTHER: stats->dir##_requests_other++; break;	\
          	default: LOG(L_ERR, "ERROR: unknown method in rq stats (%s)\n", #dir);	\
		}	\
        }

#define update_received_request( method ) _update_request( method, received )
#define update_sent_request( method ) _update_request( method, sent )

#define         _statusline(class, dir )       case class: stats->dir##_responses_##class++; break;
/*
#define		statusline( class )	_statusline( class, received )
#define		statusline2( class )	_statusline( class, sent )
*/

#define _update_response( statusclass, dir )		\
        { if (stat_file!=NULL)                          \
                switch( statusclass ) {                 \
                        _statusline(1, dir)                   \
                        _statusline(2, dir)                   \
                        _statusline(3, dir)                   \
                        _statusline(4, dir)                   \
                        _statusline(5, dir)                   \
                        _statusline(6, dir)                   \
                        default: LOG(L_INFO, "ERROR: unusual status code received in stats (%s)\n", #dir);    \
                }       \
        }

#define update_received_response( statusclass ) _update_response( statusclass, received )
#define update_sent_response( statusclass ) _update_response( statusclass, sent )

#define update_received_drops	{  stats->received_drops++; }
#define update_fail_on_send	{  stats->failed_on_send++; }


#endif
#endif
