/* 
 * File:   api.h
 * Author: cristi
 *
 * Created on September 1, 2015, 5:23 PM
 */

#ifndef API_H

typedef int (*get_client_domain_f) (void);
typedef struct tls_domain * (*tls_find_server_domain_f) (struct ip_addr *, unsigned short);
typedef struct tls_domain * (*tls_find_client_domain_f) (struct ip_addr *, unsigned short);
typedef struct tls_domain * (*tls_find_client_domain_name_f) (str);
typedef int (*get_send_timeout_f) (void);
typedef int (*get_handshake_timeout_f) (void);
typedef int (*tls_mod_init_f) (void);

struct tls_mgm_binds {
    get_client_domain_f get_client_domain;
    get_send_timeout_f get_send_timeout;
    get_handshake_timeout_f get_handshake_timeout;
    tls_find_server_domain_f find_server_domain;
    tls_find_client_domain_f find_client_domain;
    tls_find_client_domain_name_f find_client_domain_name;
    tls_mod_init_f mod_init;
};


typedef int(*load_tls_mgm_f)(struct tls_mgm_binds *binds);

int load_tls_mgm(struct tls_mgm_binds *binds);

static inline int load_tls_mgm_api(struct tls_mgm_binds *binds) {
    load_tls_mgm_f load_tls;

    /* import the DLG auto-loading function */
    if (!(load_tls = (load_tls_mgm_f) find_export("load_tls_mgm", 0, 0)))
        return -1;
 
    /* let the auto-loading function load all DLG stuff */
    if (load_tls(binds) == -1)
        return -1;

    return 0;
}

#endif	/* API_H */