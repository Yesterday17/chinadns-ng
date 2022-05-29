#define _GNU_SOURCE
#include "netutils.h"
#include "logutils.h"
#include "chinadns.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/timerfd.h>
#include <nftables/libnftables.h>
#undef _GNU_SOURCE

/* since linux 3.9 */
#ifndef SO_REUSEPORT
  #define SO_REUSEPORT 15
#endif

/* nft cmd buffer maxlen */
#define MSGBUFFER_MAXLEN 256

/* static global variable declaration */
static struct nft_ctx *g_nft                        = NULL;
static char   g_nft_cmdbuffer[MSGBUFFER_MAXLEN]     = {0};  // get element xxx xxx {0xaddraddr}
static char   g_nft_cmdbuffer6[MSGBUFFER_MAXLEN]    = {0};
static char  *g_nft_cmdbuffer_start                 = NULL; // [first byte after 0x]
static char  *g_nft_cmdbuffer6_start                = NULL;
static char   g_hex_string[32 + 1]                  = {0};
static FILE  *g_dev_null                            = NULL;


/* setsockopt(IPV6_V6ONLY) */
static inline void set_ipv6_only(int sockfd) {
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &(int){1}, sizeof(int))) {
        LOGERR("[set_ipv6_only] setsockopt(%d, IPV6_V6ONLY): (%d) %s", sockfd, errno, strerror(errno));
        exit(errno);
    }
}

/* setsockopt(SO_REUSEADDR) */
static inline void set_reuse_addr(int sockfd) {
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int))) {
        LOGERR("[set_reuse_addr] setsockopt(%d, SO_REUSEADDR): (%d) %s", sockfd, errno, strerror(errno));
        exit(errno);
    }
}

/* setsockopt(SO_REUSEPORT) */
void set_reuse_port(int sockfd) {
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int))) {
        LOGERR("[set_reuse_port] setsockopt(%d, SO_REUSEPORT): (%d) %s", sockfd, errno, strerror(errno));
        exit(errno);
    }
}

/* create a udp socket (v4/v6) */
int new_udp_socket(int family) {
    int sockfd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK, 0); /* since Linux 2.6.27 */
    if (sockfd < 0) {
        LOGERR("[new_udp_socket] failed to create udp%c socket: (%d) %s", family == AF_INET ? '4' : '6', errno, strerror(errno));
        exit(errno);
    }
    if (family == AF_INET6) set_ipv6_only(sockfd);
    set_reuse_addr(sockfd);
    return sockfd;
}

/* create a timer fd (in seconds) */
int new_once_timerfd(time_t second) {
    int timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (timerfd < 0) {
        LOGERR("[new_once_timerfd] failed to create timer fd: (%d) %s", errno, strerror(errno));
        exit(errno);
    }
    struct itimerspec time_value;
    time_value.it_value.tv_sec = second;
    time_value.it_value.tv_nsec = 0;
    time_value.it_interval.tv_sec = 0;
    time_value.it_interval.tv_nsec = 0;
    if (timerfd_settime(timerfd, 0, &time_value, NULL)) {
        LOGERR("[new_once_timerfd] failed to settime for timer fd: (%d) %s", errno, strerror(errno));
        exit(errno);
    }
    return timerfd;
}

/* AF_INET or AF_INET6 or -1(invalid) */
int get_ipstr_family(const char *ipstr) {
    if (!ipstr) return -1;
    char buffer[IPV6_BINADDR_LEN]; /* v4 or v6 */
    if (inet_pton(AF_INET, ipstr, buffer) == 1) {
        return AF_INET;
    } else if (inet_pton(AF_INET6, ipstr, buffer) == 1) {
        return AF_INET6;
    } else {
        return -1;
    }
}

/* build ipv4 address structure */
static inline void build_socket_addr4(skaddr4_t *skaddr, const char *ipstr, portno_t port) {
    skaddr->sin_family = AF_INET;
    inet_pton(AF_INET, ipstr, &skaddr->sin_addr);
    skaddr->sin_port = htons(port);
}

/* build ipv6 address structure */
static inline void build_socket_addr6(skaddr6_t *skaddr, const char *ipstr, portno_t port) {
    skaddr->sin6_family = AF_INET6;
    inet_pton(AF_INET6, ipstr, &skaddr->sin6_addr);
    skaddr->sin6_port = htons(port);
}

/* build v4/v6 address structure */
void build_socket_addr(int family, void *skaddr, const char *ipstr, portno_t portno) {
    if (family == AF_INET) {
        build_socket_addr4(skaddr, ipstr, portno);
    } else {
        build_socket_addr6(skaddr, ipstr, portno);
    }
}

/* parse ipv4 address structure */
static inline void parse_socket_addr4(const skaddr4_t *skaddr, char *ipstr, portno_t *port) {
    inet_ntop(AF_INET, &skaddr->sin_addr, ipstr, INET_ADDRSTRLEN);
    *port = ntohs(skaddr->sin_port);
}

/* parse ipv6 address structure */
static inline void parse_socket_addr6(const skaddr6_t *skaddr, char *ipstr, portno_t *port) {
    inet_ntop(AF_INET6, &skaddr->sin6_addr, ipstr, INET6_ADDRSTRLEN);
    *port = ntohs(skaddr->sin6_port);
}

/* parse v4/v6 address structure */
void parse_socket_addr(const void *skaddr, char *ipstr, portno_t *portno) {
    if (((const skaddr4_t *)skaddr)->sin_family == AF_INET) {
        parse_socket_addr4(skaddr, ipstr, portno);
    } else {
        parse_socket_addr6(skaddr, ipstr, portno);
    }
}

/* init nft context for query */
void nft_create_ctx(void) {
    g_nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!g_nft) {
        LOGERR("[nft_create_ctx] failed to initialize nft context");
        g_nft = NULL;
        return;
    }

    g_dev_null = fopen("/dev/null", "w");
    if (nft_ctx_set_output(g_nft, g_dev_null) == NULL || nft_ctx_set_error(g_nft, g_dev_null) == NULL) {
        LOGERR("[nft_create_ctx] failed to set output and error to /dev/null");
        nft_ctx_free(g_nft);
        g_nft = NULL;
        return;
    }

    if (strlen(g_set_setname4) > 0) {
        sprintf(g_nft_cmdbuffer, "get element %s {0x00000000}", g_set_setname4);
        g_nft_cmdbuffer_start = g_nft_cmdbuffer + 16 + strlen(g_set_setname4);
    }

    if (strlen(g_set_setname6) > 0) {
        sprintf(g_nft_cmdbuffer6, "get element %s {0x00000000000000000000000000000000}", g_set_setname6);
        g_nft_cmdbuffer6_start = g_nft_cmdbuffer + 16 + strlen(g_set_setname6);
    }
}

bool nft_addr_is_exists(const void *addr_prt, bool is_ipv4) {
    if (g_nft == NULL) {
        return false;
    }

    void *ipaddr_buf = is_ipv4 ? g_nft_cmdbuffer_start : g_nft_cmdbuffer6_start;
    const char *addr = addr_prt;

    if (is_ipv4) {
        if (g_nft_cmdbuffer_start == NULL) {
            return false;
        }
        sprintf(g_hex_string, "%02x%02x%02x%02x", addr[0], addr[1], addr[2], addr[3]);
    } else {
        if (g_nft_cmdbuffer6_start == NULL) {
            return false;
        }
        sprintf(g_hex_string, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
          addr[0], addr[1], addr[2], addr[3],
          addr[4], addr[5], addr[6], addr[7],
          addr[8], addr[9], addr[10], addr[11],
          addr[12], addr[13], addr[14], addr[15]
        );
    }
    memcpy(ipaddr_buf, g_hex_string, (is_ipv4 ? IPV4_BINADDR_LEN : IPV6_BINADDR_LEN) * 2);

    int ret = nft_run_cmd_from_buffer(g_nft, is_ipv4 ? g_nft_cmdbuffer : g_nft_cmdbuffer6);
    if (!ret) {
        return false;
    }
    return true;
}
