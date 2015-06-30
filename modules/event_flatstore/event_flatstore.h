#ifndef _EV_FLAT_H_
#define _EV_FLAT_H_

#include "../../str.h"

#define FLAT_NAME	"flatstore"
#define FLAT_STR		{ FLAT_NAME, sizeof(FLAT_NAME) - 1}
#define FLAT_FLAG (1<<25)

#define INITIAL_CAPACITY 100

#define BUF_LEN 1024
#define IOV_LEN 1024

static struct iovec *flat_iov = 0;

struct flat_socket {
    str path;
    unsigned int file_index_process;
    unsigned int counter_open;
    unsigned int rotate_version;
    struct flat_socket *next;
    struct flat_socket *prev;

};

struct deleted {
    struct flat_socket *socket;
    struct deleted *next;
};


#endif