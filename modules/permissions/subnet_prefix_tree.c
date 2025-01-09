#include "subnet_prefix_tree.h"

#include "../../mem/shm_mem.h"

ppt_trie_node_t *ppt_create_node(void) {
    ppt_trie_node_t *node;

    node = shm_malloc(sizeof(ppt_trie_node_t));
    if (!node) return NULL;

    node->children[0] = NULL;
    node->children[1] = NULL;
    node->is_subnet_end = 0;
    node->metadata_list = NULL;

    return node;
}

ppt_metadata_t *ppt_create_metadata(void *data) {
    ppt_metadata_t *metadata;

    metadata = shm_malloc(sizeof(ppt_metadata_t));
    if (!metadata) return NULL;

    metadata->data = data;

    return metadata;
}

int get_bit_at_index(const unsigned char *ip, int index) {
    int byte_index, bit_index;

    byte_index = index / 8;
    bit_index = index % 8;
    return (ip[byte_index] >> (7 - bit_index)) & 1;
}

int ppt_insert_subnet(ppt_trie_node_t *root, const unsigned char *ip, int prefix_length,
                      void *data) {
    ppt_metadata_t *metadata;
    int i, bit;

    metadata = (ppt_metadata_t *)data;
    if (prefix_length == 0) {
        metadata = ppt_create_metadata(data);
        if (!metadata) return -1;
        root->is_subnet_end = 1;
        metadata->next = root->metadata_list;
        root->metadata_list = metadata;
        return 1;
    }

    ppt_trie_node_t *current = root;
    for (i = 0; i < prefix_length; ++i) {
        bit = get_bit_at_index(ip, i);
        if (current->children[bit] == NULL) {
            current->children[bit] = ppt_create_node();
            if (!current->children[bit]) return -1;
        }
        current = current->children[bit];
    }

    metadata = ppt_create_metadata(data);
    if (!metadata) return -1;
    current->is_subnet_end = 1;
    metadata->next = current->metadata_list;
    current->metadata_list = metadata;

    return 1;
}

void *ppt_match_subnet(ppt_trie_node_t *root, const unsigned char *ip, int ip_length,
                       ppt_match_callback match, ...) {
    va_list args, args_copy;
    int total_bits = ip_length * 8;

    va_start(args, match);

    ppt_trie_node_t *current = root;
    ppt_metadata_t *metadata;
    int i, bit;

    for (i = 0; i < total_bits; ++i) {
        if (current->is_subnet_end) {
            metadata = current->metadata_list;
            while (metadata) {
                va_copy(args_copy, args);
                if (match(metadata->data, args_copy)) {
                    va_end(args_copy);
                    va_end(args);
                    return metadata->data;
                }
                va_end(args_copy);
                metadata = metadata->next;
            }
        }

        bit = get_bit_at_index(ip, i);
        if (current->children[bit] == NULL) {
            va_end(args);
            return NULL;
        }
        current = current->children[bit];
    }

    if (current->is_subnet_end) {
        metadata = current->metadata_list;
        while (metadata) {
            va_copy(args_copy, args);
            if (match(metadata->data, args_copy)) {
                va_end(args_copy);
                va_end(args);
                return metadata->data;
            }
            va_end(args_copy);
            metadata = metadata->next;
        }
    }

    va_end(args);

    return NULL;
}

void ppt_free_metadata(ppt_metadata_t *metadata) {
    while (metadata != NULL) {
        ppt_metadata_t *next = metadata->next;
        shm_free(metadata);
        metadata = next;
    }
}

void ppt_free_trie(ppt_trie_node_t *root) {
    if (root == NULL) return;
    ppt_free_trie(root->children[0]);
    ppt_free_trie(root->children[1]);
    ppt_free_metadata(root->metadata_list);
    shm_free(root);
}
