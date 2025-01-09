#ifndef PERM_SUBNET_PREFIX_TREE_H
#define PERM_SUBNET_PREFIX_TREE_H

#include <stdarg.h>

typedef struct ppt_metadata_t ppt_metadata_t;
typedef struct ppt_trie_node_t ppt_trie_node_t;

typedef struct ppt_metadata_t {
    ppt_metadata_t *next;
    void *data;
} ppt_metadata_t;

typedef struct ppt_trie_node_t {
    ppt_trie_node_t *children[2];
    int is_subnet_end;
    ppt_metadata_t *metadata_list;
} ppt_trie_node_t;

typedef int (*ppt_match_callback)(void *data, va_list args);

ppt_trie_node_t *ppt_create_node(void);
int ppt_insert_subnet(ppt_trie_node_t *root, const unsigned char *ip, int prefix_length,
                      void *data);
void *ppt_match_subnet(ppt_trie_node_t *root, const unsigned char *ip, int ip_length,
                       ppt_match_callback match, ...);
void ppt_free_trie(ppt_trie_node_t *root);

#endif /* PERM_SUBNET_PREFIX_TREE_H */
