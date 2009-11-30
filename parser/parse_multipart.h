#ifndef _PARSE_MULITPART
#define _PARSE_MULITPART
struct part{

    /* MIME content type */
    int content_type;

    /* body of the current part */
    str body;

    /* the whole part ( body + headers) */
    str all_data;

    /* whatever information might be received from parsing the part */
    void * parsed_data;

    struct part * next;
};

struct multi_body {
    int from_multi_part;
    str boundary;

    int part_count;
    struct part * first;
};


/*
 * If the body of the message is multipart get all the parts,
 * otherwise get a multi_body cotaining one element of the initial body.
 * Should be used if someone thinks that the message could be multipart
 * and needs to be interpreted.
 *
 */

struct multi_body * get_all_bodies(struct sip_msg * msg);

void free_multi_body(struct multi_body *);

#endif

