#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>


#define NETCONF_CH_SSH_PORT 4334

#define SSHD "/usr/sbin/sshd" // FIXME
#define SSHD_CONF "ncch_sshd_config"

static void
fatal(int ecode, char *fmt, ...)
{
    va_list args;

    if (strlen(fmt) > 0) {
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
        fprintf(stderr, "\n");
    }
    exit(ecode);
}

static void
do_connect(int sock, struct sockaddr *addr, int addrlen)
{
    if (connect(sock,  addr, addrlen) < 0) {
        fatal(1, "Failed to connect to NETCONF client");
    }
}

static void
exec_sshd(int sock)
{
    if (setreuid(0, 0) == -1) {
        fprintf(stderr, "warning: failed to set uid\n");
    }
    printf("ok\n");
    fflush(stdout);
    if (dup2(sock, 0) < 0) {
        fatal(1, "Failed to dup2 to 0");
    }
    if (dup2(sock, 1) < 0) {
        fatal(1, "Failed to dup2 to 1");
    }
    if (dup2(sock, 2) < 0) {
        fatal(1, "Failed to dup2 to 2");
    }
    execl(SSHD, SSHD, "-ddd", "-E", "sshd.log",
          "-i", "-f", SSHD_CONF, (char *)NULL);
}

static struct option longopts[] = {
    {"ip",   1, NULL, 'I'},
    {"port", 1, NULL, 'P'},
    {NULL,   0, NULL, 0}
};

int
main(int argc, char* argv[])
{
    int sock;
    char *ipstr = NULL;
    int port = NETCONF_CH_SSH_PORT;
    struct sockaddr_in in_addr;
    struct sockaddr_in6 in6_addr;
    struct sockaddr *addr = NULL;
    int c, addrlen;

    memset(&in_addr, '\0', sizeof(in_addr));
    memset(&in6_addr, '\0', sizeof(in6_addr));

    while ((c = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
        switch(c) {
        case 'I':
            ipstr = optarg;
            break;
        case 'P':
            port = atoi(optarg);
            break;
        default:
            fatal(1, "unknown argument");
        }
    }

    if (ipstr == NULL) {
        fatal(1, "need an --ip");
    }
    if (inet_pton(AF_INET, ipstr, &in_addr.sin_addr) == 1) {
        in_addr.sin_family = AF_INET;
        in_addr.sin_port = htons(port);
        addr = (struct sockaddr *)&in_addr;
        addrlen = sizeof(in_addr);
    } else if (inet_pton(AF_INET6, ipstr, &in6_addr.sin6_addr) == 1) {
        in6_addr.sin6_family = AF_INET6;
        in6_addr.sin6_port = htons(port);
        addr = (struct sockaddr *)&in6_addr;
        addrlen = sizeof(in6_addr);
    } else {
        fatal(1, "%s is not an ip address", ipstr);
    }

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        fatal(1, "Failed to create socket");
    }
    do_connect(sock, addr, addrlen);
    exec_sshd(sock);
}
