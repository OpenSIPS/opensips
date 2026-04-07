#include <stdint.h>

#include "thinfo_codec.h"

#include "../../parser/msg_parser.h"
#include "../../socket_info.h"

#define SCHEME_MASK    0x0007
#define SCHEME_SIP     0x0000
#define SCHEME_SIPS    0x0001
#define SCHEME_TEL     0x0002
#define SCHEME_TELS    0x0003
#define SCHEME_URN_S   0x0004
#define SCHEME_URN_N   0x0005
#define SCHEME_M1      0x0006  // Magic bit 1 - must be 0 (invalid/garbage detection)
#define SCHEME_M2      0x0007  // Magic bit 2 - must be 0 (invalid/garbage detection)

#define TRANSPORT_MASK 0x0038
#define TRANSPORT_UDP  0x0000
#define TRANSPORT_TCP  0x0008
#define TRANSPORT_TLS  0x0010
#define TRANSPORT_SCTP 0x0018
#define TRANSPORT_WS   0x0020
#define TRANSPORT_WSS  0x0028
#define TRANSPORT_M1   0x0030  // Magic bit 1 - must be 0 (invalid/garbage detection)
#define TRANSPORT_M2   0x0038  // Magic bit 2 - must be 0 (invalid/garbage detection)

#define DOMAIN_MASK    0x00C0
#define DOMAIN_IPV4    0x0000
#define DOMAIN_IPV6    0x0040
#define DOMAIN_FQDN    0x0080
#define DOMAIN_M1      0x00C0  // Magic bit - must be 0 (invalid/garbage detection)

#define HAS_USERNAME   0x0100
#define HAS_PASSWORD   0x0200
#define HAS_PORT       0x0400
#define HAS_PARAMS     0x0800  // Now means "has OTHER params" (not lr/r2)
#define HAS_HEADERS    0x1000
#define HAS_LR         0x2000  // lr or lr=on present
#define IS_DUAL_URI    0x4000  // Dual URI encoding flag
#define RESERVED_BIT   0x8000  // Reserved for future use

#define SOCKET_PROTO_MASK  0x07  // 3 bits for protocol (bits 0-2)
#define SOCKET_IP_MASK     0x18  // 2 bits for IP type (bits 3-4)
#define SOCKET_IPV4        0x00
#define SOCKET_IPV6        0x08
#define SOCKET_HAS_PORT    0x20  // Bit 5: port is present


// URI2 properties byte (1 byte following URI1 data)
#define URI2_SCHEME_MASK    0x07    // Bits 0-2: scheme for URI2
#define URI2_TRANSPORT_MASK 0x38    // Bits 3-5: transport for URI2
#define URI2_TRANSPORT_SHIFT 3
#define URI2_HAS_PORT       0x40    // Bit 6: URI2 has port
#define URI2_HAS_R2         0x80    // Bit 7: r2 flag for both URIs in dual encoding

static str r2_on_uri_param     = str_init("r2=on");
static str lr_uri_param        = str_init("lr");
static str lr_on_uri_param     = str_init("lr=on");
static str transport_uri_param = str_init("transport");

#define MAX_THINFO_BUFFER_SIZE 4096

static const uint8_t SCHEMES[] = {
    [ERROR_URI_T]            = 0,
    [SIP_URI_T]              = SCHEME_SIP,
    [SIPS_URI_T]             = SCHEME_SIPS,
    [TEL_URI_T]              = SCHEME_TEL,
    [TELS_URI_T]             = SCHEME_TELS,
    [URN_SERVICE_URI_T]      = SCHEME_URN_N,
    [URN_NENA_SERVICE_URI_T] = SCHEME_URN_S
};

static const enum _uri_type SCHEME_TO_ENUM[] = {
    [SCHEME_SIP]   = SIP_URI_T,
    [SCHEME_SIPS]  = SIPS_URI_T,
    [SCHEME_TEL]   = TEL_URI_T,
    [SCHEME_TELS]  = TELS_URI_T,
    [SCHEME_URN_N] = URN_SERVICE_URI_T,
    [SCHEME_URN_S] = URN_NENA_SERVICE_URI_T
};

static const str SCHEME_STRINGS[] = {
    [SCHEME_SIP]   = str_init("sip"),
    [SCHEME_SIPS]  = str_init("sips"),
    [SCHEME_TEL]   = str_init("tel"),
    [SCHEME_TELS]  = str_init("tels"),
    [SCHEME_URN_N] = str_init("urn:service"),
    [SCHEME_URN_S] = str_init("urn:nena:service")
};

static const uint8_t TRANSPORTS[] = {
    [PROTO_NONE]    = 0,
    [PROTO_UDP]     = TRANSPORT_UDP,
    [PROTO_TCP]     = TRANSPORT_TCP,
    [PROTO_TLS]     = TRANSPORT_TLS,
    [PROTO_SCTP]    = TRANSPORT_SCTP,
    [PROTO_WS]      = TRANSPORT_WS,
    [PROTO_WSS]     = TRANSPORT_WSS
};

static const enum sip_protos TRANSPORT_TO_ENUM[] = {
    [TRANSPORT_UDP]  = PROTO_UDP,
    [TRANSPORT_TCP]  = PROTO_TCP,
    [TRANSPORT_TLS]  = PROTO_TLS,
    [TRANSPORT_SCTP] = PROTO_SCTP,
    [TRANSPORT_WS]   = PROTO_WS,
    [TRANSPORT_WSS]  = PROTO_WSS
};

static const char *TRANSPORT_STRINGS[] = {
    [TRANSPORT_UDP]  = "transport=udp",
    [TRANSPORT_TCP]  = "transport=tcp",
    [TRANSPORT_TLS]  = "transport=tls",
    [TRANSPORT_SCTP] = "transport=sctp",
    [TRANSPORT_WS]   = "transport=ws",
    [TRANSPORT_WSS]  = "transport=wss"
};

static str dual_uri_skip_params[] = {
    str_init("r2")
};

static int dual_uri_skip_params_count = sizeof(dual_uri_skip_params) / sizeof(dual_uri_skip_params[0]);

static uint8_t encode_params(unsigned char *p, uint16_t *uri_properties, str *params, int param_count, str params_to_skip[static param_count]) {
    char *src, *end;
    int remaining, param_len_current;
    uint8_t param_len = 0;
    int skip_encode = 0;
    
    if (!params || params->len == 0 || params->len > UINT8_MAX) {
        return 0;
    }
    
    src = params->s;
    remaining = params->len;
    
    if (remaining > 0 && *src == ';') {
        src++;
        remaining--;
    }
    
    while (remaining > 0) {
        if (*src == ';') {
            src++;
            remaining--;
            if (remaining == 0) break;
        }
        
        skip_encode = 0;
        end = memchr(src, ';', remaining);
        param_len_current = end ? (end - src) : remaining;

        for (int i = 0; i < param_count; i++) {
            LM_DBG("Checking param [%.*s]\n", params_to_skip[i].len, params_to_skip[i].s);
            if (param_len_current >= params_to_skip[i].len && strncmp(src, params_to_skip[i].s, params_to_skip[i].len) == 0) {
                if ((param_len_current == lr_uri_param.len && memcmp(src, lr_uri_param.s, lr_uri_param.len) == 0) ||
                         (param_len_current == lr_on_uri_param.len && memcmp(src, lr_on_uri_param.s, lr_on_uri_param.len) == 0)) {
                    *uri_properties |= HAS_LR;
                }
                
                src += param_len_current;
                remaining -= param_len_current;
                skip_encode = 1;
                break;
            }
        }

        if (skip_encode) {
            continue;
        }

        if (param_len > 0) {
            *p++ = ';';
            param_len++;
        }
        memcpy(p, src, param_len_current);
        p += param_len_current;
        param_len += param_len_current;
        
        src += param_len_current;
        remaining -= param_len_current;
    }
    
    return param_len;
}

#define ENCODE_URI_FIELD(_uri, _field, _flag_expr, _props, _p) \
    do { \
        if ((_uri)->_field.len > 0 && (_uri)->_field.len <= UINT8_MAX) { \
            (_props) = (_flag_expr); \
            *(_p)++ = (uint8_t)(_uri)->_field.len; \
            memcpy((_p), (_uri)->_field.s, (_uri)->_field.len); \
            (_p) += (_uri)->_field.len; \
        } else if ((_uri)->_field.len > UINT8_MAX) { \
            LM_WARN("URI " #_field " length '%d' larger than 255\n", (_uri)->_field.len); \
        } \
    } while(0)

static int encode_uris(thinfo_encoded_t *thinfo, struct sip_uri *uri1, struct sip_uri *uri2, int param_count, str *params_to_skip) {
    unsigned char *p, *props_ptr, *param_len_ptr, *uri2_props_ptr;
    uint16_t props = 0;
    uint8_t uri2_props;
    char tmp[256];
    uint8_t param_len;
    size_t start_pos;
    str extra_params[param_count + 2];
    int extra_param_count = param_count;
    
    if (thinfo->len + MAX_ENCODED_URI_SIZE * 2 > MAX_THINFO_BUFFER_SIZE) {
        return -1;
    }
    
    if (thinfo->len == 0) {
        p = thinfo->buf + 3;
        thinfo->len = 3;
        thinfo->pos = 0;
    } else {
        p = thinfo->buf + thinfo->len;
    }
    
    start_pos = p - thinfo->buf;
    
    if (uri2 != NULL) {
        props = IS_DUAL_URI;
    }

    props_ptr = p;
    p += 2;
    props |= SCHEMES[uri1->type];
    if (uri1->proto >= PROTO_UDP && uri1->proto <= PROTO_WSS) {
        props = (props & ~TRANSPORT_MASK) | TRANSPORTS[uri1->proto];
    } else {
        props = (props & ~TRANSPORT_MASK) | TRANSPORTS[PROTO_UDP];
    }

    ENCODE_URI_FIELD(uri1, user, props | HAS_USERNAME, props, p);
    
    ENCODE_URI_FIELD(uri1, passwd, props | HAS_PASSWORD, props, p);

    if (uri1->host.len > 0 && uri1->host.len < sizeof(tmp)) {
        memcpy(tmp, uri1->host.s, uri1->host.len);
        tmp[uri1->host.len] = '\0';
        
        if (inet_pton(AF_INET, tmp, p) == 1) {
            props = (props & ~DOMAIN_MASK) | DOMAIN_IPV4;
            p += 4;
        } else if (inet_pton(AF_INET6, tmp, p) == 1) {
            props = (props & ~DOMAIN_MASK) | DOMAIN_IPV6;
            p += 16;
        } else if (uri1->host.len <= UINT8_MAX) {
            ENCODE_URI_FIELD(uri1, host, (props & ~DOMAIN_MASK) | DOMAIN_FQDN, props, p);
        } else {
            return -1;
        }
    } else {
        return -1;
    }

    if (uri1->port_no > 0) {
        props |= HAS_PORT;
        *p++ = (uri1->port_no >> 8) & 0xFF;
        *p++ = uri1->port_no & 0xFF;
    }

    if (uri2 != NULL) {
        uri2_props = 0;
        uri2_props_ptr = p;
        p += 1;

        uri2_props |= SCHEMES[uri2->type] & URI2_SCHEME_MASK;
        if (uri2->proto >= PROTO_UDP && uri2->proto <= PROTO_WSS) {
            // TRANSPORTS values are already in bits 3-5 format (0x00, 0x08, 0x10, 0x18, 0x20, 0x28)
            // Just mask to fit in URI2 byte
            uri2_props |= TRANSPORTS[uri2->proto] & URI2_TRANSPORT_MASK;
        }

        if (uri2->port_no > 0) {
            uri2_props |= URI2_HAS_PORT;
            *p++ = (uri2->port_no >> 8) & 0xFF;
            *p++ = uri2->port_no & 0xFF;
        }
        uri2_props |= URI2_HAS_R2;
        *uri2_props_ptr = uri2_props;
    }

    if (uri1->params.len > 0 && uri1->params.len <= UINT8_MAX) {
        if (params_to_skip != NULL && param_count > 0) {
            memcpy(extra_params, params_to_skip, param_count * sizeof(params_to_skip[0]));
        } else if (params_to_skip == NULL && param_count > 0) {
            LM_WARN("params_to_skip is null but param_count is greater than 0\n");
            extra_param_count = 0;
        }

        extra_params[extra_param_count++] = transport_uri_param;
        extra_params[extra_param_count++] = lr_uri_param;

        param_len_ptr = p++;
        param_len = encode_params(p, &props, &uri1->params, extra_param_count, extra_params);

        if (param_len > 0) {
            *param_len_ptr = param_len;
            props |= HAS_PARAMS;
            p += param_len;
        } else {
            p = param_len_ptr;
        }
    }

    ENCODE_URI_FIELD(uri1, headers, props | HAS_HEADERS, props, p);

    props_ptr[0] = (props >> 8) & 0xFF;
    props_ptr[1] = props & 0xFF;
    
    thinfo->len = p - thinfo->buf;
    return p - (thinfo->buf + start_pos);
}

int thinfo_encode_dual_uri(thinfo_encoded_t *thinfo, struct sip_uri *uri1, struct sip_uri *uri2) {
    return encode_uris(thinfo, uri1, uri2, dual_uri_skip_params_count, dual_uri_skip_params);
}

int thinfo_encode_uri(thinfo_encoded_t *thinfo, struct sip_uri *uri, int param_count, str *params_to_skip) {
    return encode_uris(thinfo, uri, NULL, param_count, params_to_skip);
}

int thinfo_encode_socket(thinfo_encoded_t *thinfo, const struct socket_info *si) {
    unsigned char *p;
    uint8_t flags = 0;
    int has_port = 0;

    if (si == NULL) {
        LM_ERR("Socket is null\n");
        return -1;
    }
    
    if (thinfo->len + MAX_ENCODED_URI_SIZE > MAX_THINFO_BUFFER_SIZE) {
        return -1;
    }

    if (thinfo->len == 0) {
        thinfo->len = 3;
    }

    p = thinfo->buf + thinfo->len;

    if (si->proto >= PROTO_UDP && si->proto <= PROTO_WSS) {
        flags |= (TRANSPORTS[si->proto] >> 3) & SOCKET_PROTO_MASK;
    } else {
        return -1;
    }

    if (si->address.af == AF_INET) {
        flags |= SOCKET_IPV4;
    } else if (si->address.af == AF_INET6) {
        flags |= SOCKET_IPV6;
    } else {
        return -1;
    }

    has_port = (si->port_no > 0) ? 1 : 0;
    if (has_port) {
        flags |= SOCKET_HAS_PORT;
    }

    *p++ = flags;

    if (si->address.af == AF_INET) {
        memcpy(p, si->address.u.addr, 4);
        p += 4;
    } else if (si->address.af == AF_INET6) {
        memcpy(p, si->address.u.addr, 16);
        p += 16;
    }

    if (has_port) {
        *p++ = (si->port_no >> 8) & 0xFF;
        *p++ = si->port_no & 0xFF;
    }
    
    int bytes_written = p - (thinfo->buf + thinfo->len);
    thinfo->len = p - thinfo->buf;
    
    return bytes_written;
}

int thinfo_decode_socket(thinfo_encoded_t *thinfo, int *proto, str *ip, unsigned short *port) {
    static char ip_str[INET6_ADDRSTRLEN];
    unsigned char *p;
    uint8_t flags, proto_bits, ip_type;
    int remaining, has_port;
    
    if (!thinfo || thinfo->pos >= thinfo->len) return -1;

    if (thinfo->pos == 0) {
        thinfo->pos = 3;
    }
    
    p = thinfo->buf + thinfo->pos;
    remaining = thinfo->len - thinfo->pos;
    
    if (remaining < 5) return -1;  // Minimum: 1 byte flags + 4 bytes IPv4
    
    flags = *p++;
    remaining--;
    
    proto_bits = (flags & SOCKET_PROTO_MASK) << 3;
    switch (proto_bits) {
        case TRANSPORT_UDP:  *proto = PROTO_UDP; break;
        case TRANSPORT_TCP:  *proto = PROTO_TCP; break;
        case TRANSPORT_TLS:  *proto = PROTO_TLS; break;
        case TRANSPORT_SCTP: *proto = PROTO_SCTP; break;
        case TRANSPORT_WS:   *proto = PROTO_WS; break;
        case TRANSPORT_WSS:  *proto = PROTO_WSS; break;
        default: return -1;
    }

    ip_type = flags & SOCKET_IP_MASK;
    has_port = (flags & SOCKET_HAS_PORT) ? 1 : 0;

    if (ip_type == SOCKET_IPV4) {
        if (remaining < (4 + (has_port ? 2 : 0))) return -1;  // Need 4 bytes for IP + optional 2 for port
        inet_ntop(AF_INET, p, ip_str, INET_ADDRSTRLEN);
        ip->s = ip_str;
        ip->len = strlen(ip_str);
        p += 4;
    } else if (ip_type == SOCKET_IPV6) {
        if (remaining < (16 + (has_port ? 2 : 0))) return -1;  // Need 16 bytes for IP + optional 2 for port
        inet_ntop(AF_INET6, p, ip_str, INET6_ADDRSTRLEN);
        ip->s = ip_str;
        ip->len = strlen(ip_str);
        p += 16;
    } else {
        return -1;
    }

    if (has_port) {
        *port = (p[0] << 8) | p[1];
        p += 2;
    } else {
        *port = 0;
    }
    
    thinfo->pos = p - thinfo->buf;
    
    return 1;
}

#define BUILD_URI_STRING(scheme_val, transport_val, port_val) \
    do { \
        *s++ = '<'; \
        uri_start = s; \
        memcpy(s, SCHEME_STRINGS[scheme_val].s, SCHEME_STRINGS[scheme_val].len); \
        s += SCHEME_STRINGS[scheme_val].len; \
        *s++ = ':'; \
        if (username.len > 0) { \
            memcpy(s, username.s, username.len); \
            s += username.len; \
            if (password.len > 0) { \
                *s++ = ':'; \
                memcpy(s, password.s, password.len); \
                s += password.len; \
            } \
            *s++ = '@'; \
        } \
        if (domain_type == DOMAIN_IPV6) *s++ = '['; \
        memcpy(s, host.s, host.len); \
        s += host.len; \
        if (domain_type == DOMAIN_IPV6) *s++ = ']'; \
        if (port_val > 0) { \
            s += sprintf(s, ":%u", port_val); \
        } \
        if (transport_val != TRANSPORT_UDP) { \
            if (transport_val < sizeof(TRANSPORT_STRINGS)/sizeof(TRANSPORT_STRINGS[0]) && \
                TRANSPORT_STRINGS[transport_val] != NULL) { \
                *s++ = ';'; \
                t_len = strlen(TRANSPORT_STRINGS[transport_val]); \
                memcpy(s, TRANSPORT_STRINGS[transport_val], t_len); \
                s += t_len; \
            } \
        } \
        if (props & HAS_LR) { \
            memcpy(s, ";lr", 3); \
            s += 3; \
        } \
        if (has_r2) { \
            memcpy(s, ";r2=on", 6); \
            s += 6; \
        } \
        if (params.len > 0) { \
            *s++ = ';'; \
            memcpy(s, params.s, params.len); \
            s += params.len; \
        } \
        if (headers.len > 0) { \
            *s++ = '?'; \
            memcpy(s, headers.s, headers.len); \
            s += headers.len; \
        } \
        *s++ = '>'; \
        uris[uri_idx].s = uri_start - 1; \
        uris[uri_idx].len = s - uris[uri_idx].s; \
        if (uri_idx < uri_count - 1) { \
            *s++ = ','; \
            if (is_dual) *s++ = ' '; \
        } \
    } while(0)

#define DECODE_STR_FIELD(field, flag) \
    do { \
        field.len = 0; \
        if (props & flag) { \
            field.len = *p++; \
            memcpy(field.s, p, field.len); \
            p += field.len; \
        } \
    } while(0)

static char host_buf[UINT8_MAX], params_buf[UINT8_MAX], username_buf[UINT8_MAX], password_buf[UINT8_MAX], headers_buf[UINT8_MAX];

int thinfo_decode_uris(thinfo_encoded_t *thinfo, char decoded_uri_str[static MAX_ENCODED_URI_SIZE * 3], uint16_t uri_count, str uris[static uri_count]) {
    uint8_t domain_type, len, uri2_props = 0;
    uint8_t scheme1 = 0, scheme2 = 0, transport1 = 0, transport2 = 0;
    uint16_t port1 = 0, port2 = 0;
    int has_r2 = 0;
    int is_dual = 0;
    unsigned char *p;
    uint16_t props;
    char *s, *uri_start;
    int t_len;
    int uri_idx;
    str username = {username_buf, 0};
    str password = {password_buf, 0};
    str host = {host_buf, 0};
    str params = {params_buf, 0};
    str headers = {headers_buf, 0};

    if (!thinfo || thinfo->len < 3 || uri_count == 0) return -1;
    
    if (thinfo->pos == 0) {
        thinfo->pos = 3;
    }
    
    p = thinfo->buf + thinfo->pos;
    s = decoded_uri_str;
    
    uri_idx = 0;
    while (uri_idx < uri_count) {
        if ((p - thinfo->buf) >= thinfo->len) return -1;
        
        props = (p[0] << 8) | p[1];
        p += 2;

        // Validate magic bits - detect garbage data
        scheme1 = props & SCHEME_MASK;
        transport1 = props & TRANSPORT_MASK;
        domain_type = props & DOMAIN_MASK;
        
        if (scheme1 > SCHEME_URN_N || transport1 > TRANSPORT_WSS || domain_type > DOMAIN_FQDN) {
            LM_ERR("Invalid properties detected: props=0x%04x, scheme=0x%02x, transport=0x%02x, domain=0x%02x (garbage data)\n",
                props, scheme1, transport1, domain_type);
            return -1;
        }

        is_dual = (props & IS_DUAL_URI) ? 1 : 0;
        
        DECODE_STR_FIELD(username, HAS_USERNAME);

        DECODE_STR_FIELD(password, HAS_PASSWORD);

        domain_type = (props & DOMAIN_MASK);
        host.len = 0;
        if (domain_type == DOMAIN_IPV4) {
            inet_ntop(AF_INET, p, host.s, UINT8_MAX);
            host.len = strlen(host.s);
            p += 4;
        } else if (domain_type == DOMAIN_IPV6) {
            inet_ntop(AF_INET6, p, host.s, UINT8_MAX);
            host.len = strlen(host.s);
            p += 16;
        } else {
            len = *p++;
            host.len = len;
            memcpy(host.s, p, len);
            p += len;
        }

        if (props & HAS_PORT) {
            port1 = (p[0] << 8) | p[1];
            p += 2;
        }

        if (is_dual) {
            uri2_props = *p++;
            scheme2 = uri2_props & URI2_SCHEME_MASK;
            transport2 = uri2_props & URI2_TRANSPORT_MASK;
            has_r2 = (uri2_props & URI2_HAS_R2) ? 1 : 0;

            if (uri2_props & URI2_HAS_PORT) {
                port2 = (p[0] << 8) | p[1];
                p += 2;
            }
        }

        DECODE_STR_FIELD(params, HAS_PARAMS);

        DECODE_STR_FIELD(headers, HAS_HEADERS);
        
        BUILD_URI_STRING(scheme1, transport1, port1);
        
        LM_DBG("uri[%d]: s=%p, len=%d, content=[%.*s]\n",
            uri_idx, uris[uri_idx].s, uris[uri_idx].len, 
            uris[uri_idx].len, uris[uri_idx].s);
        
        uri_idx++;

        if (is_dual && uri_idx < uri_count) {
            BUILD_URI_STRING(scheme2, transport2, port2);
            
            LM_DBG("Dual uri[%d]: s=%p, len=%d, content=[%.*s]\n",
                uri_idx, uris[uri_idx].s, uris[uri_idx].len, 
                uris[uri_idx].len, uris[uri_idx].s);
            
            uri_idx++;
        }
    }
    
    thinfo->pos = p - thinfo->buf;
    
    return s - decoded_uri_str;
}

void thinfo_buffer_reset(thinfo_encoded_t *thinfo) {
    thinfo->len = 0;
    thinfo->pos = 0;
}

void thinfo_buffer_finalize(thinfo_encoded_t *thinfo, uint16_t flags, uint8_t count) {
    thinfo->buf[0] = (flags >> 8) & 0xFF;
    thinfo->buf[1] = flags & 0xFF;
    thinfo->buf[2] = count;
}

uint8_t thinfo_get_uri_count(thinfo_encoded_t *thinfo) {
    return thinfo->buf[2];
}

uint16_t thinfo_get_flags(thinfo_encoded_t *thinfo) {
    return (thinfo->buf[0] << 8) | thinfo->buf[1];
}