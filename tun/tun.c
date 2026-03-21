#include <assert.h>
#include <stdint.h>
#include <stdarg.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>
#include <poll.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>

#include <tomlc17.h>

#include <net/if.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <libmnl/libmnl.h>

#include <seccomp.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/random.h>

static const char *client_id = "default";
static const char udp_hello[] = "hello";

#define TUNNEL_MIN_MTU 576
#define TUNNEL_DEFAULT_MTU 1360
#define TUNNEL_MAX_MTU 1500

#define DTLS_TIMEOUT_MIN 1
#define DTLS_TIMEOUT_MAX 8

#define POLL_TIMEOUT_MS 50

enum role {
    ROLE_SERVER = 0,
    ROLE_CLIENT
};

struct proto {
    const char *name;
    enum {
        PROTO_UDP,
        PROTO_DTLS12,
        PROTO_DTLS13,
    } proto;
};

static const struct proto protos[] = {
    { "ECDHE-PSK-AES128-CBC-SHA256", PROTO_DTLS12 },
    { "TLS13-AES128-CCM-8-SHA256", PROTO_DTLS13 },
    { "TLS13-CHACHA20-POLY1305-SHA256", PROTO_DTLS13 },
    { "TLS13-SHA256-SHA256", PROTO_DTLS13 },
    { "UDP", PROTO_UDP },
    { 0 }
};

struct address {
    in_addr_t addr;
    uint8_t prefix;
};

#define MAX_ROUTES 8

struct config {
    enum role role;
    const struct proto *proto;
    struct sockaddr_in endpoint_address;
    char tun_name[IFNAMSIZ];
    size_t mtu;
    struct address address;
    struct address routes[MAX_ROUTES];
    size_t n_routes;
    uint8_t psk[32];
    uint32_t psk_len;
    unsigned int verbosity;
    bool seccomp;
    time_t timeout;
} g_config;

static struct context {
    _Atomic bool running;
    _Atomic bool update_keys;
    int sockfd;
    WOLFSSL *ssl;
    int tunfd;
    int log_timestamp;
    struct timespec last_received;
} g_ctx;

enum log_level {
    LOG_INF = 0,
    LOG_WRN,
    LOG_ERR,
};

static void logmsg(enum log_level level, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    FILE *fp = level > LOG_WRN ? stderr : stdout;

    if (g_ctx.log_timestamp) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        struct tm *t = localtime(&tv.tv_sec);
        char buffer[30];
        strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", t);
        fprintf(fp, "%s.%03ld ", buffer, tv.tv_usec / 1000);
    }

    vfprintf(fp, format, args);
    fprintf(fp, "\n");
    fflush(fp);

    va_end(args);
}

#define LOG_INF(...) logmsg(LOG_INF, __VA_ARGS__)
#define LOG_WRN(...) logmsg(LOG_WRN, __VA_ARGS__)
#define LOG_ERR(...) logmsg(LOG_ERR, __VA_ARGS__)

#define LOGP(msg) logmsg(LOG_ERR, msg ": %s", strerror(errno))

static void wolfSSL_log_cb(const int log_level, const char *const log_message)
{
    enum log_level level = LOG_INF;
    switch (log_level) {
    case ERROR_LOG:
        level = LOG_ERR;
        break;
    case INFO_LOG:
    case CERT_LOG:
    case OTHER_LOG:
        level = LOG_INF;
        break;
    case ENTER_LOG:
    case LEAVE_LOG:
        if (g_config.verbosity < 3) {
            return;
        }
        break;
    default:
        level = LOG_ERR;
        logmsg(level, "unexpected wolfSSL log level");
    }
    logmsg(level, "  %s", log_message);
}

static const struct proto *find_proto(const char *name)
{
    const struct proto *proto = &protos[0];
    while (proto->name) {
        if (strcasecmp(proto->name, name) == 0) {
            return proto;
        }
        ++proto;
    }
    return NULL;
}

static void process_dtls(void);
static void process_udp(struct sockaddr_in *peer);
static int config_tun(void);
static int config_tun_routes(void);

static int create_tun(void)
{
    int ret;
    struct ifreq ifr;
    int tun_fd;

    LOG_INF("creating %s interface", g_config.tun_name);

    tun_fd = open("/dev/net/tun", O_RDWR);
    if (tun_fd < 0) {
        LOGP("opening /dev/net/tun");
        return 1;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, g_config.tun_name, IFNAMSIZ - 1);

    ret = ioctl(tun_fd, TUNSETIFF, (void *)&ifr);
    if (ret < 0) {
        LOGP("ioctl(TUNSETIFF)");
        close(tun_fd);
        return 1;
    }

    if (strcmp(g_config.tun_name, ifr.ifr_name) != 0) {
        LOG_WRN("using iface name %s instead", ifr.ifr_name);
        strcpy(g_config.tun_name, ifr.ifr_name);
    }

    LOG_INF("bringing %s up", g_config.tun_name);

    if (config_tun() != 0) {
        goto fail;
    }

    if (g_config.n_routes > 0) {
        if (config_tun_routes() != 0) {
            goto fail;
        }
    }

    g_ctx.tunfd = tun_fd;
    return 0;

fail:
    close(tun_fd);
    return 1;
}

static int config_tun(void)
{
    struct ifreq ifr;
    int sock_fd;

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        LOGP("socket");
        return 1;
    }

    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, g_config.tun_name, sizeof(ifr.ifr_name));

    ifr.ifr_mtu = g_config.mtu;
    if (ioctl(sock_fd, SIOCSIFMTU, &ifr) < 0) {
        LOGP("ioctl SIOCSIFMTU");
        goto fail;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = g_config.address.addr;

    if (ioctl(sock_fd, SIOCSIFADDR, &ifr) < 0) {
        LOGP("ioctl SIOCSIFADDR");
        goto fail;
    }

    struct sockaddr_in *mask = (struct sockaddr_in *)&ifr.ifr_netmask;
    mask->sin_family = AF_INET;
    mask->sin_addr.s_addr = htonl(~0U << (32 - g_config.address.prefix));

    if (ioctl(sock_fd, SIOCSIFNETMASK, &ifr) < 0) {
        LOGP("ioctl SIOCSIFNETMASK");
        goto fail;
    }

    if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) < 0) {
        LOGP("ioctl SIOCGIFFLAGS");
        goto fail;
    }

    ifr.ifr_flags &= ~IFF_MULTICAST;
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) < 0) {
        LOGP("ioctl SIOCSIFFLAGS");
        goto fail;
    }

    close(sock_fd);
    return 0;

fail:
    close(sock_fd);
    return 1;
}

static int config_tun_route(int iface, struct mnl_socket *nl, unsigned int portid,
                            struct address *address)
{
    int ret;
    struct nlmsghdr *nlh;
    struct rtmsg *rtm;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t seq;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_NEWROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
    nlh->nlmsg_seq = seq = time(NULL);

    rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    rtm->rtm_family = AF_INET;
    rtm->rtm_dst_len = address->prefix;
    rtm->rtm_src_len = 0;
    rtm->rtm_tos = 0;
    rtm->rtm_protocol = RTPROT_STATIC;
    rtm->rtm_table = RT_TABLE_MAIN;
    rtm->rtm_type = RTN_UNICAST;
    rtm->rtm_scope = RT_SCOPE_LINK;
    rtm->rtm_flags = 0;

    mnl_attr_put_u32(nlh, RTA_DST, address->addr);
    mnl_attr_put_u32(nlh, RTA_OIF, iface);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        LOGP("mnl_socket_sendto");
        return 1;
    }

    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    if (ret < 0) {
        LOGP("mnl_socket_recvfrom");
        return 1;
    }

    ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
    if (ret < 0) {
        LOGP("mnl_cb_run");
        return 1;
    }

    return 0;
}

static int config_tun_routes(void)
{
    int iface = if_nametoindex(g_config.tun_name);
    if (iface == 0) {
        LOGP("if_nametoindex");
        return 1;
    }

    struct mnl_socket *nl = mnl_socket_open(NETLINK_ROUTE);
    if (nl == NULL) {
        LOGP("mnl_socket_open");
        return 1;
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        LOGP("mnl_socket_bind");
        mnl_socket_close(nl);
        return 1;
    }

    uint32_t portid = mnl_socket_get_portid(nl);

    for (int i = 0; i < (int)g_config.n_routes; ++i) {
        struct address *address = &g_config.routes[i];
        struct in_addr addr = {.s_addr = address->addr};
        LOG_INF("ip route add %s/%d dev %s", inet_ntoa(addr), address->prefix, g_config.tun_name);
        if (config_tun_route(iface, nl, portid, address) != 0) {
            mnl_socket_close(nl);
            return 1;
        }
    }

    mnl_socket_close(nl);
    return 0;
}

#if defined(__has_feature)
#   if __has_feature(address_sanitizer) && !defined(__SANITIZE_ADDRESS__)
#       define __SANITIZE_ADDRESS__
#   endif
#endif

#define SCMP_ALLOW(syscall)                                                                        \
    do {                                                                                           \
        int ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(syscall), 0);                     \
        if (ret != 0) {                                                                            \
            return ret;                                                                            \
        }                                                                                          \
    } while (0)

static int seccomp_restrict(void)
{
#if defined(__SANITIZE_ADDRESS__)
    return 0;
#endif

    if (!g_config.seccomp) {
        return 0;
    }

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    if (ctx == NULL) {
        LOG_ERR("cannot initialize seccomp");
        return 1;
    }

    SCMP_ALLOW(getrandom);
    SCMP_ALLOW(clock_gettime);

    SCMP_ALLOW(read);
    SCMP_ALLOW(write);
    SCMP_ALLOW(writev);

    SCMP_ALLOW(fcntl);
    SCMP_ALLOW(newfstatat);
    SCMP_ALLOW(getsockopt);
    SCMP_ALLOW(setsockopt);
    SCMP_ALLOW(poll);
    SCMP_ALLOW(close);

    SCMP_ALLOW(sendto);
    SCMP_ALLOW(recvfrom);
    SCMP_ALLOW(recvmsg);
    SCMP_ALLOW(sendmsg);

    SCMP_ALLOW(mmap);
    SCMP_ALLOW(munmap);
    SCMP_ALLOW(brk);

    SCMP_ALLOW(exit);
    SCMP_ALLOW(exit_group);

    SCMP_ALLOW(rt_sigprocmask);
    SCMP_ALLOW(rt_sigreturn);

    int ret = seccomp_load(ctx);
    seccomp_release(ctx);
    return ret;
}

static void show_conn_info(WOLFSSL *ssl)
{
    LOG_INF("established %s %s %s", wolfSSL_get_version(ssl), wolfSSL_get_curve_name(ssl),
            wolfSSL_get_cipher(ssl));
}

static unsigned int psk_server_tls12_cb(WOLFSSL *ssl, const char *identity, unsigned char *key,
                                        unsigned int key_max_len)
{
    (void)ssl;

    if (strcmp(identity, client_id) != 0) {
        LOG_ERR("unknown client identity: %s", identity);
        return 0;
    }

    if (g_config.psk_len > key_max_len) {
        LOG_ERR("psk doesn't fit");
        return 0;
    }

    memcpy(key, g_config.psk, g_config.psk_len);

    return g_config.psk_len;
}

static unsigned int psk_server_tls13_cb(WOLFSSL *ssl, const char *identity, unsigned char *key,
                                        unsigned int key_max_len, const char **ciphersuite)
{
    (void)ssl;

    unsigned int ret = psk_server_tls12_cb(ssl, identity, key, key_max_len);
    if (ret != 0) {
        *ciphersuite = g_config.proto->name;
    }

    return ret;
}

static unsigned int psk_client_tls12_cb(WOLFSSL *ssl, const char *hint, char *identity,
                                        unsigned int id_max_len, unsigned char *key,
                                        unsigned int key_max_len)
{
    (void)ssl;
    (void)hint;

    if (g_config.psk_len > key_max_len) {
        LOG_ERR("bad key");
        return 0;
    }

    if (strlen(client_id) + 1 > id_max_len) {
        LOG_ERR("bad identity");
        return 0;
    }

    strncpy(identity, client_id, id_max_len);
    memcpy(key, g_config.psk, g_config.psk_len);

    return g_config.psk_len;
}

static unsigned int psk_client_tls13_cb(WOLFSSL *ssl, const char *hint, char *identity,
                                        unsigned int id_max_len, unsigned char *key,
                                        unsigned int key_max_len, const char **ciphersuite)
{
    (void)ssl;
    (void)hint;

    unsigned int ret = psk_client_tls12_cb(ssl, hint, identity, id_max_len, key, key_max_len);
    if (ret != 0) {
        *ciphersuite = g_config.proto->name;
    }

    return ret;
}

static void dtls_server(void)
{
    int ret;

    if (g_config.psk_len == 0) {
        LOG_WRN("using empty psk");
    }

    WOLFSSL_METHOD *method;
    if (g_config.proto->proto == PROTO_DTLS13) {
        method = wolfDTLSv1_3_server_method();
    } else {
        method = wolfDTLSv1_2_server_method();
    }

    WOLFSSL_CTX *ssl_ctx = wolfSSL_CTX_new(method);
    if (ssl_ctx == NULL) {
        LOG_ERR("cannot create wolfSSL context");
        return;
    }

    if (g_config.proto->proto == PROTO_DTLS13) {
        wolfSSL_CTX_set_psk_server_tls13_callback(ssl_ctx, psk_server_tls13_cb);
    } else {
        wolfSSL_CTX_set_psk_server_callback(ssl_ctx, psk_server_tls12_cb);
    }

    ret = wolfSSL_CTX_set_cipher_list(ssl_ctx, g_config.proto->name);
    if (ret != WOLFSSL_SUCCESS) {
        LOG_ERR("cannot set cipher suite");
        wolfSSL_CTX_free(ssl_ctx);
        return;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        LOGP("socket");
        wolfSSL_CTX_free(ssl_ctx);
        return;
    }

    ret = bind(sockfd, (struct sockaddr *)&g_config.endpoint_address, sizeof(struct sockaddr_in));
    if (ret < 0) {
        LOGP("bind");
        close(sockfd);
        wolfSSL_CTX_free(ssl_ctx);
        return;
    }

    if (seccomp_restrict() != 0) {
        LOG_ERR("cannot restrict myself using seccomp");
        close(sockfd);
        wolfSSL_CTX_free(ssl_ctx);
        return;
    }

    g_ctx.sockfd = sockfd;
    g_ctx.running = true;

    int flags = fcntl(sockfd, F_GETFL);

    while (g_ctx.running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        LOG_INF("listening");

        fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);
        struct timeval tv = {0, 0};
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        ret = recvfrom(sockfd, NULL, 0, MSG_PEEK, (struct sockaddr *)&client_addr, &client_len);
        if (ret < 0) {
            if (errno != EINTR) {
                LOGP("recvfrom");
            }
            break;
        }

        LOG_INF("incoming %s:%d", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        WOLFSSL *ssl = wolfSSL_new(ssl_ctx);
        if (ssl == NULL) {
            LOG_ERR("cannot create wolfSSL object");
            break;
        }

        wolfSSL_set_fd(ssl, sockfd);
        wolfSSL_dtls_set_peer(ssl, &client_addr, client_len);
        wolfSSL_dtls_set_timeout_init(ssl, DTLS_TIMEOUT_MIN);
        wolfSSL_dtls_set_timeout_max(ssl, DTLS_TIMEOUT_MAX);

        ret = wolfSSL_negotiate(ssl);
        if (ret != WOLFSSL_SUCCESS) {
            int err = wolfSSL_get_error(ssl, ret);
            LOG_ERR("handshake error code %d: %s", err, wolfSSL_ERR_error_string(err, NULL));
            wolfSSL_free(ssl);
            continue;
        }

        show_conn_info(ssl);

        g_ctx.ssl = ssl;
        wolfSSL_dtls_set_using_nonblock(ssl, 1);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

        process_dtls();

        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
    }

    close(sockfd);
    wolfSSL_CTX_free(ssl_ctx);
    wolfSSL_Cleanup();
}

static void dtls_client(void)
{
    int ret;

    WOLFSSL_METHOD *method;
    if (g_config.proto->proto == PROTO_DTLS13) {
        method = wolfDTLSv1_3_client_method();
    } else {
        method = wolfDTLSv1_2_client_method();
    }

    WOLFSSL_CTX *ssl_ctx = wolfSSL_CTX_new(method);
    if (ssl_ctx == NULL) {
        LOG_ERR("cannot create wolfSSL context");
        return;
    }

    if (g_config.proto->proto == PROTO_DTLS13) {
        wolfSSL_CTX_set_psk_client_tls13_callback(ssl_ctx, psk_client_tls13_cb);
    } else {
        wolfSSL_CTX_set_psk_client_callback(ssl_ctx, psk_client_tls12_cb);
    }

    ret = wolfSSL_CTX_set_cipher_list(ssl_ctx, g_config.proto->name);
    if (ret != WOLFSSL_SUCCESS) {
        LOG_ERR("cannot set cipher suite");
        wolfSSL_CTX_free(ssl_ctx);
        return;
    }

    int groups[] = {WOLFSSL_ECC_X25519};
    wolfSSL_CTX_set_groups(ssl_ctx, groups, 1);
    wolfSSL_CTX_only_dhe_psk(ssl_ctx);

    WOLFSSL *ssl = wolfSSL_new(ssl_ctx);
    if (ssl == NULL) {
        LOG_ERR("cannot create wolfSSL object");
        wolfSSL_CTX_free(ssl_ctx);
        return;
    }

    wolfSSL_dtls_set_peer(ssl, &g_config.endpoint_address, sizeof(struct sockaddr_in));

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        LOGP("socket");
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ssl_ctx);
        return;
    }

    ret = wolfSSL_set_fd(ssl, sockfd);
    if (ret != WOLFSSL_SUCCESS) {
        LOG_ERR("cannot set fd");
        close(sockfd);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ssl_ctx);
        return;
    }

    if (seccomp_restrict() != 0) {
        LOG_ERR("cannot restrict myself using seccomp");
        close(sockfd);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ssl_ctx);
        return;
    }

    LOG_INF("handshaking");
    ret = wolfSSL_negotiate(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, ret);
        LOG_ERR("handshake error code %d: %s", err, wolfSSL_ERR_error_string(err, NULL));
        close(sockfd);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ssl_ctx);
        return;
    }

    show_conn_info(ssl);

    g_ctx.sockfd = sockfd;
    g_ctx.ssl = ssl;
    wolfSSL_dtls_set_using_nonblock(ssl, 1);

    int flags = fcntl(sockfd, F_GETFL);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    g_ctx.running = true;
    process_dtls();

    fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);

    wolfSSL_shutdown(ssl);
    close(sockfd);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ssl_ctx);
    wolfSSL_Cleanup();
}

static void udp_server(void)
{
    int ret;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        LOGP("socket");
        return;
    }
    g_ctx.sockfd = sockfd;

    ret = bind(sockfd, (struct sockaddr *)&g_config.endpoint_address, sizeof(struct sockaddr_in));
    if (ret < 0) {
        LOGP("bind");
        close(sockfd);
        return;
    }

    if (seccomp_restrict() != 0) {
        LOG_ERR("cannot restrict myself using seccomp");
        close(sockfd);
        return;
    }

    int flags = fcntl(sockfd, F_GETFL);

    char tmp[sizeof(udp_hello)];
    g_ctx.running = true;
    while (g_ctx.running) {
        LOG_INF("listening");

        fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);

        ret = recvfrom(sockfd, tmp, sizeof(tmp), 0, (struct sockaddr *)&client_addr, &client_len);
        if (ret < 0) {
            if (errno != EINTR) {
                LOGP("recvfrom");
            }
            break;
        }

        LOG_INF("incoming %s:%d", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        if (ret != sizeof(tmp) || strncmp(tmp, udp_hello, sizeof(tmp)) != 0) {
            continue;
        }

        ret = sendto(g_ctx.sockfd, udp_hello, sizeof(udp_hello), 0, (struct sockaddr *)&client_addr, sizeof(struct sockaddr_in));
        if (ret < 0) {
            LOGP("sendto");
            break;
        }

        LOG_INF("established");

        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

        process_udp(&client_addr);
    }

    close(sockfd);
}

static void udp_client(void)
{
    int ret;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        LOGP("socket");
        return;
    }

    ret = connect(sockfd, (struct sockaddr *)&g_config.endpoint_address, sizeof(struct sockaddr_in));
    if (ret < 0) {
        LOGP("connect");
        close(sockfd);
        return;
    }

    if (write(sockfd, udp_hello, sizeof(udp_hello)) < 0) {
        LOGP("write");
        close(sockfd);
        return;
    }

    struct timeval tv = {3, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char tmp[sizeof(udp_hello)];
    ret = recv(sockfd, tmp, sizeof(tmp), 0);
    if (ret < 0) {
        LOGP("recv");
        close(sockfd);
        return;
    }

    if (strncmp(tmp, udp_hello, sizeof(tmp)) != 0) {
        LOG_ERR("wrong ack");
        close(sockfd);
        return;
    }

    LOG_INF("established");

    if (seccomp_restrict() != 0) {
        LOG_ERR("cannot restrict myself using seccomp");
        close(sockfd);
        return;
    }

    int flags = fcntl(sockfd, F_GETFL);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    g_ctx.sockfd = sockfd;
    g_ctx.running = true;

    process_udp(&g_config.endpoint_address);

    fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);

    close(sockfd);
}

static void signal_handler(int signum)
{
    switch (signum) {
    case SIGINT:
        g_ctx.running = false;
        break;
    case SIGHUP:
        g_ctx.update_keys = true;
        break;
    default:
        LOG_ERR("unexpected signum %d", signum);
    }
}

static int set_signal_action(void)
{
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = signal_handler;

    if (sigaction(SIGINT, &act, NULL) != 0) {
        LOGP("sigaction");
        return 1;
    }

    act.sa_flags |= SA_RESTART;
    if (sigaction(SIGHUP, &act, NULL) != 0) {
        LOGP("sigaction");
        return 1;
    }

    return 0;
}

static void last_received_update(void)
{
    if (g_config.timeout != 0) {
        clock_gettime(CLOCK_REALTIME, &g_ctx.last_received);
    }
}

static bool last_received_timeout(void)
{
    if (g_config.timeout == 0) {
        return false;
    }

    const int ns = 1000000000;
    struct timespec now;
    // TODO CLOCK_MONOTONIC
    clock_gettime(CLOCK_REALTIME, &now);
    time_t elapsed_ns = (now.tv_sec - g_ctx.last_received.tv_sec) * ns
        + now.tv_nsec - g_ctx.last_received.tv_nsec;

    return elapsed_ns > g_config.timeout * ns;
}

static void process_dtls(void)
{
    int ret;
    uint8_t buf[TUNNEL_MAX_MTU];

    struct pollfd pollfds[2];
    pollfds[0].fd = g_ctx.sockfd;
    pollfds[0].events = POLLIN;
    pollfds[1].fd = g_ctx.tunfd;
    pollfds[1].events = POLLIN;

    last_received_update();
    bool check_keys_updated = false;

    while (g_ctx.running) {
        if (check_keys_updated) {
            int required;
            ret = wolfSSL_key_update_response(g_ctx.ssl, &required);
            if (ret != 0) {
                LOG_ERR("cannot check key update response");
                check_keys_updated = false;
            } else if (required == 0) {
                LOG_INF("keys updated");
                check_keys_updated = false;
            }
        }

        if (g_ctx.update_keys) {
            g_ctx.update_keys = false;
            ret = wolfSSL_update_keys(g_ctx.ssl);
            if (ret != WOLFSSL_ERROR_WANT_WRITE && ret != WOLFSSL_SUCCESS) {
                LOG_ERR("cannot update keys");
            } else {
                LOG_INF("keys update requested");
                check_keys_updated = true;
            }
        }

        ret = poll(pollfds, 2, POLL_TIMEOUT_MS);
        if (ret < 0) {
            if (errno == EINTR) {
                /* a signal was caught */
                continue;
            }
            LOGP("poll");
            break;
        }
        if (ret == 0) {
            if (last_received_timeout()) {
                LOG_INF("disconnected on timeout");
                break;
            }
            continue;
        }

        if (pollfds[0].revents & POLLIN) {
            ret = wolfSSL_read(g_ctx.ssl, buf, g_config.mtu);
            if (ret == 0) {
                LOG_INF("disconnected");
                break;
            }
            if (ret < 0) {
                int err = wolfSSL_get_error(g_ctx.ssl, ret);
                if (err == WOLFSSL_ERROR_WANT_READ) {
                    goto ingress;
                }
                LOG_ERR("ssl read error code %d: %s", err, wolfSSL_ERR_error_string(err, NULL));
                break;
            }

            last_received_update();

            size_t size = ret;
            ret = write(g_ctx.tunfd, buf, size);
            if (ret == 0) {
                LOG_INF("exiting");
                break;
            }
            if (ret < 0) {
                LOGP("write");
                break;
            }
            if ((size_t)ret != size) {
                LOG_WRN("partial write");
            }
        }

ingress:
        if (pollfds[1].revents & POLLIN) {
            ret = read(g_ctx.tunfd, buf, g_config.mtu);
            if (ret == 0) {
                LOG_INF("exiting");
                break;
            }
            if (ret < 0) {
                LOGP("read");
                break;
            }

            size_t size = ret;
            ret = wolfSSL_write(g_ctx.ssl, buf, size);
            if (ret == 0) {
                LOG_INF("disconnected");
                break;
            }
            if (ret < 0) {
                int err = wolfSSL_get_error(g_ctx.ssl, ret);
                if (err == WOLFSSL_ERROR_WANT_WRITE) {
                    continue;
                }
                LOG_ERR("ssl write error code %d: %s", err, wolfSSL_ERR_error_string(err, NULL));
                break;
            }
        }
    }
}

static void process_udp(struct sockaddr_in *peer)
{
    int ret;
    uint8_t buf[TUNNEL_MAX_MTU];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(struct sockaddr_in);

    struct pollfd pollfds[2];
    pollfds[0].fd = g_ctx.sockfd;
    pollfds[0].events = POLLIN;
    pollfds[1].fd = g_ctx.tunfd;
    pollfds[1].events = POLLIN;

    g_ctx.running = true;
    last_received_update();

    while (g_ctx.running) {
        ret = poll(pollfds, 2, POLL_TIMEOUT_MS);
        if (ret < 0) {
            if (errno == EINTR) {
                /* a signal was caught */
                continue;
            }
            LOGP("poll");
            break;
        }
        if (ret == 0) {
            if (last_received_timeout()) {
                LOG_INF("disconnected on timeout");
                break;
            }
            continue;
        }

        if (pollfds[0].revents & POLLIN) {
            last_received_update();
            ret = recvfrom(g_ctx.sockfd, buf, g_config.mtu, MSG_DONTWAIT, (struct sockaddr *)&from, &from_len);
            if (ret == 0) {
                LOG_INF("disconnected");
                break;
            }
            if (ret < 0) {
                LOGP("recvfrom");
                break;
            }
            if (from.sin_addr.s_addr != peer->sin_addr.s_addr || from.sin_port != peer->sin_port) {
                char tmp[32];
                if (inet_ntop(AF_INET, &from.sin_addr, tmp, sizeof(tmp)) != NULL) {
                    LOG_WRN("recv from %s", tmp);
                } else {
                    LOG_WRN("recv from unknown");
                }
                continue;
            }
            size_t size = ret;
            ret = write(g_ctx.tunfd, buf, size);
            if (ret == 0) {
                LOG_INF("exiting");
                break;
            }
            if (ret < 0) {
                LOGP("write");
                break;
            }
            if ((size_t)ret != size) {
                LOG_WRN("partial write");
            }
        }

        if (pollfds[1].revents & POLLIN) {
            ret = read(g_ctx.tunfd, buf, g_config.mtu);
            if (ret == 0) {
                LOG_INF("disconnected");
                break;
            }
            if (ret < 0) {
                LOGP("read");
                break;
            }
            size_t size = ret;
            ret = sendto(g_ctx.sockfd, buf, size, 0, (struct sockaddr *)peer, sizeof(struct sockaddr_in));
            if (ret == 0) {
                LOG_INF("exiting");
                break;
            }
            if (ret < 0) {
                LOGP("sendto");
                break;
            }
            if ((size_t)ret != size) {
                LOG_WRN("partial write");
            }
        }
    }
}

static int conf_load_endpoint(toml_datum_t *conf)
{
    toml_datum_t endpoint = toml_get(*conf, "endpoint");
    if (endpoint.type == TOML_UNKNOWN) {
        LOG_ERR("cannot read endpoint");
        goto fail;
    }
    if (endpoint.type != TOML_STRING) {
        LOG_ERR("cannot parse endpoint: must be a string");
        goto fail;
    }

    char *port = strchr(endpoint.u.str.ptr, ':');
    if (!port) {
        LOG_ERR("cannot parse endpoint %s: valid format is ipv4:port", endpoint.u.str.ptr);
        goto fail;
    }
    char c = *port;
    *port = 0;

    int ret = inet_pton(AF_INET, endpoint.u.str.ptr, &g_config.endpoint_address.sin_addr);
    *port++ = c;
    if (ret != 1) {
        LOG_ERR("cannot parse endpoint %s: invalid ipv4", endpoint.u.str.ptr);
        goto fail;
    }

    errno = 0;
    char *endptr;
    uint32_t n = strtoul(port, &endptr, 10);
    if (errno == ERANGE || endptr == port || *endptr != 0 || n > 65535) {
        LOG_ERR("cannot parse endpoint %s: invalid port", endpoint.u.str.ptr);
        return 1;
    }
    g_config.endpoint_address.sin_port = htons(n);
    g_config.endpoint_address.sin_family = AF_INET;

    return 0;

fail:
    return 1;
}

static int parse_address(const char *str, struct address *address)
{
    int ret;
    char *pos = strchr(str, '/');
    if (!pos) {
        return 1;
    }
    char *prefix = pos + 1;

    errno = 0;
    char *endptr;
    uint32_t n = strtoul(prefix, &endptr, 10);
    if (errno == ERANGE || endptr == prefix || *endptr != 0 || n > 32) {
        return 1;
    }
    address->prefix = n;

    char c = *pos;
    *pos = 0;
    ret = inet_pton(AF_INET, str, &address->addr);
    *pos = c;
    if (ret != 1) {
        return 1;
    }

    return 0;
}

static int conf_load_address(toml_datum_t *conf)
{
    int ret;
    toml_datum_t tun_address = toml_get(*conf, "address");
    if (tun_address.type == TOML_UNKNOWN) {
        LOG_ERR("cannot read tun address");
        return 1;
    }
    if (tun_address.type != TOML_STRING) {
        LOG_ERR("cannot parse tun address: must be a string");
        return 1;
    }

    ret = parse_address(tun_address.u.s, &g_config.address);
    if (ret != 0) {
        LOG_ERR("cannot parse tun address %s: valid format is ipv4/prefix", tun_address.u.s);
        return 1;
    }

    return 0;
}

static int conf_load_routes(toml_datum_t *conf)
{
    toml_datum_t routes = toml_get(*conf, "routes");
    if (routes.type == TOML_UNKNOWN) {
        return 0;
    }
    if (routes.type != TOML_ARRAY) {
        LOG_ERR("cannot parse routes: must be an array");
        return 1;
    }

    int32_t n_routes = routes.u.arr.size;
    if (n_routes > MAX_ROUTES) {
        LOG_ERR("too many routes requested, at most %d are allowed", MAX_ROUTES);
        return 1;
    }

    for (int i = 0; i < n_routes; ++i) {
        toml_datum_t route = routes.u.arr.elem[i];
        if (route.type == TOML_UNKNOWN) {
            LOG_ERR("cannot read route at index %d", i);
            return 1;
        }
        if (route.type != TOML_STRING) {
            LOG_ERR("cannot read route at index %d: must be string ipv4/prefix", i);
            return 1;
        }
        int ret = parse_address(route.u.str.ptr, &g_config.routes[i]);
        if (ret != 0) {
            LOG_ERR("cannot parse route %s at index %i in routes array: "
                    "valid format is ipv4/prefix",
                    route.u.s, i);
            return 1;
        }
    }

    g_config.n_routes = n_routes;

    return 0;
}

static int config_load(const char *path)
{
    toml_result_t res;
    if (strcmp(path, "-") == 0) {
        res = toml_parse_file(stdin);
    } else {
        res = toml_parse_file_ex(path);
    }

    if (!res.ok) {
        LOG_ERR("cannot read config: %s", res.errmsg);
        goto fail;
    }

    toml_datum_t verbosity = toml_get(res.toptab, "verbosity");
    if (verbosity.type == TOML_UNKNOWN) {
        g_config.verbosity = 0;
    } else if (verbosity.type == TOML_INT64) {
        g_config.verbosity = (unsigned int)verbosity.u.int64;
    } else {
        LOG_ERR("cannot read verbosity: must be an integer");
        goto fail;
    }

    toml_datum_t role = toml_get(res.toptab, "role");
    if (role.type == TOML_UNKNOWN) {
        LOG_ERR("cannot read role");
        goto fail;
    }
    if (role.type != TOML_STRING) {
        LOG_ERR("cannot parse role: must be a string");
        goto fail;
    }

    if (strcmp(role.u.s, "server") == 0) {
        g_config.role = ROLE_SERVER;
    } else if (strcmp(role.u.s, "client") == 0) {
        g_config.role = ROLE_CLIENT;
    } else {
        LOG_ERR("unknown role %s: must be server or client", role.u.s);
        goto fail;
    }

    toml_datum_t proto = toml_get(res.toptab, "proto");
    if (proto.type == TOML_UNKNOWN) {
        LOG_ERR("cannot read proto");
        goto fail;
    }
    if (proto.type != TOML_STRING) {
        LOG_ERR("cannot parse proto: must be a string");
        goto fail;
    }

    g_config.proto = find_proto(proto.u.s);
    if (!g_config.proto) {
        LOG_ERR("unknown proto %s", proto.u.s);
        goto fail;
    }

    if (conf_load_endpoint(&res.toptab) != 0) {
        goto fail;
    }

    toml_datum_t tun = toml_get(res.toptab, "tun");
    if (tun.type == TOML_UNKNOWN) {
        LOG_ERR("cannot read tun name");
        goto fail;
    }
    if (tun.type != TOML_STRING) {
        LOG_ERR("cannot parse tun name: must be a string");
        goto fail;
    }

    if (strlen(tun.u.s) + 1 > sizeof(g_config.tun_name)) {
        LOG_ERR("tun name length must be shorter than %ld symbols", sizeof(g_config.tun_name));
        goto fail;
    }
    strncpy(g_config.tun_name, tun.u.s, sizeof(g_config.tun_name));

    toml_datum_t mtu = toml_get(res.toptab, "mtu");
    if (mtu.type == TOML_UNKNOWN) {
        g_config.mtu = TUNNEL_DEFAULT_MTU;
        if (g_config.verbosity > 0) {
            LOG_INF("using default mtu %d", g_config.mtu);
        }
    } else if (mtu.type == TOML_INT64) {
        if (mtu.u.int64 < TUNNEL_MIN_MTU || mtu.u.int64 > TUNNEL_MAX_MTU) {
            LOG_ERR("invalid mtu %ld: must be in range [%d, %d]", mtu.u.int64, TUNNEL_MIN_MTU,
                    TUNNEL_MAX_MTU);
            goto fail;
        }
        g_config.mtu = mtu.u.int64;
    } else {
        LOG_ERR("cannot parse mtu: must be an integer");
        goto fail;
    }

    if (conf_load_address(&res.toptab) != 0) {
        goto fail;
    }

    if (conf_load_routes(&res.toptab) != 0) {
        goto fail;
    }

    toml_datum_t psk = toml_get(res.toptab, "psk");
    if (psk.type == TOML_UNKNOWN) {
        if (g_config.proto->proto == PROTO_DTLS12 || g_config.proto->proto == PROTO_DTLS13) {
            LOG_ERR("cannot read psk: required for dtls proto");
            goto fail;
        }
    } else if (psk.type == TOML_STRING) {
        if (g_config.proto->proto == PROTO_UDP) {
            LOG_WRN("psk is not used for udp proto");
        }
        g_config.psk_len = sizeof(g_config.psk);
        int ret = Base64_Decode((const byte *)psk.u.str.ptr, psk.u.str.len, g_config.psk,
                                &g_config.psk_len);
        if (ret != 0) {
            LOG_ERR("cannot parse psk: must be a base64 string");
            goto fail;
        }
    } else {
        LOG_ERR("cannot parse psk: must be a base64 string");
        goto fail;
    }

    toml_datum_t seccomp = toml_get(res.toptab, "seccomp");
    if (seccomp.type == TOML_UNKNOWN) {
        g_config.seccomp = true;
    } else if (seccomp.type == TOML_BOOLEAN) {
        g_config.seccomp = seccomp.u.boolean;
    } else {
        LOG_ERR("cannot parse seccomp: must be a boolean");
        goto fail;
    }

    toml_datum_t timeout = toml_get(res.toptab, "timeout");
    if (timeout.type == TOML_UNKNOWN) {
        g_config.timeout = 0;
    } else if (timeout.type == TOML_INT64) {
        g_config.timeout = timeout.u.int64;
    } else {
        LOG_ERR("cannot parse timeout: must be an integer number of seconds");
        goto fail;
    }

    toml_free(res);
    return 0;

fail:
    toml_free(res);
    return 1;
}

static const char *config_get_role_name(void)
{
    switch (g_config.role) {
    case ROLE_SERVER:
        return "server";
    case ROLE_CLIENT:
        return "client";
    default:
        return "<unknown>";
    }
}

static char *config_print_routes(void)
{
    size_t n = g_config.n_routes;
    if (n == 0) {
        return NULL;
    }

    char *buf = malloc(n * strlen("\"111.111.111.111/11\", ") + 1);
    char *p = buf;

    for (size_t i = 0; i < n; ++i) {
        struct address *address = &g_config.routes[i];
        char addr[20];
        inet_ntop(AF_INET, &address->addr, addr, sizeof(addr));
        p += sprintf(p, "\"%s/%d\"", addr, address->prefix);
        if (i != n - 1) {
            p += sprintf(p, ", ");
        }
    }

    return buf;
}

static void config_print(void)
{
    char addr[16];
    char *routes_str = config_print_routes();

    printf("role = \"%s\"\n", config_get_role_name());
    printf("proto = \"%s\"\n", g_config.proto->name);
    inet_ntop(AF_INET, &g_config.endpoint_address.sin_addr, addr, sizeof(addr));
    printf("endpoint = \"%s:%d\"\n", addr, ntohs(g_config.endpoint_address.sin_port));
    printf("tun = \"%s\"\n", g_config.tun_name);
    printf("mtu = %ld\n", g_config.mtu);
    inet_ntop(AF_INET, &g_config.address.addr, addr, sizeof(addr));
    printf("address = \"%s/%d\"\n", addr, g_config.address.prefix);
    printf("routes = [ %s ]\n", routes_str ? routes_str : "");
    printf("psk = \"<hidden>\"\n");
    printf("verbosity = %d\n", g_config.verbosity);
    printf("seccomp = %s\n", g_config.seccomp ? "true" : "false");

    free(routes_str);
}

static void generate_psk(void)
{
    int ret;
    WC_RNG rng;
    uint8_t psk[16];
    uint8_t out[32];
    uint32_t out_len = sizeof(out);

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        LOG_ERR("cannot initialize RNG: %d", ret);
        return;
    }

    ret = wc_RNG_GenerateBlock(&rng, psk, sizeof(psk));
    wc_FreeRng(&rng);
    if (ret != 0) {
        LOG_ERR("cannot generate random bytes: %d", ret);
        return;
    }

    ret = Base64_Encode(psk, sizeof(psk), out, &out_len);
    if (ret != 0) {
        LOG_ERR("cannot encode base64: %d", ret);
        return;
    }

    printf("%s", out);
}

static void usage(void)
{
    printf("Usage: tun <conf.toml>\n"
           "       tun genpsk\n");
}

int main(int argc, char **argv)
{
    int ret;

    if (argc != 2) {
        usage();
        return 1;
    }

    const char *arg = argv[1];
    if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
        usage();
        return 0;
    }

    if (strcmp(arg, "genpsk") == 0) {
        generate_psk();
        return 0;
    }

    ret = config_load(arg);
    if (ret != 0) {
        return 1;
    }

    if (g_config.verbosity > 0) {
        config_print();
    }

    if (g_config.proto->proto == PROTO_DTLS12 || g_config.proto->proto == PROTO_DTLS13) {
        ret = wolfSSL_Init();
        if (ret != WOLFSSL_SUCCESS) {
            LOG_ERR("cannot initialize wolfSSL");
            return 1;
        }
        if (g_config.verbosity > 1) {
            wolfSSL_SetLoggingCb(wolfSSL_log_cb);
            wolfSSL_Debugging_ON();
        }
    }

    if (set_signal_action() != 0) {
        return 1;
    }
    g_ctx.log_timestamp = 1;

    ret = create_tun();
    if (ret != 0) {
        if (g_ctx.tunfd > 0) {
            close(g_ctx.tunfd);
        }
        return 1;
    }

    if (g_config.role == ROLE_CLIENT) {
        if (g_config.proto->proto == PROTO_UDP) {
            udp_client();
        } else {
            dtls_client();
        }
    } else {
        if (g_config.proto->proto == PROTO_UDP) {
            udp_server();
        } else {
            dtls_server();
        }
    }

    close(g_ctx.tunfd);
    if (g_ctx.running) {
        return 1;
    }

    return 0;
}
