/*    -*- C -*-
 *
 *  Copyright 2006 Tail-F Systems AB. All rights reserved.
 *
 *  This software is the confidential and proprietary
 *  information of Tail-F Systems AB.
 *
 *    File:      clistart.c
 *    Author:    Johan Bevemyr
 *    Created:   Thu Jan 19 02:08:29 2006
 *
 *  Compile with
 *
 *     gcc -o confd_cli clistart.c -lcurses
 *
 *  Possible exit codes:
 *    0 - normal exit
 *    1 - failed to read user data for initial handshake
 *    2 - close timeout, client side closed, session inactive
 *    3 - idle timeout triggered
 *    4 - tcp level error detected on ConfD side
 *    5 - internal error occured in ConfD/NCS
 *    6 - user interrupted clistart using special escape char (only
 *        generated locally in clistart/confd_cli/ncs_cli
 *    7 - ConfD/NCS abruptly closed socket (generated locally in C program)
 *    8 - ConfD/NCS stopped on error
 */

#define CLISTART_PROTO_VSN "1.2"

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <limits.h>

#ifdef NCURSES
#include <curses.h>
#else
#include <termios.h>
#include <sys/ioctl.h>
#endif

#include "confd_ipc_access.h"
#include "confd_util.h"

#ifdef NCS
#define SERVER "NCS"
#define PORT "4569"
#define CLI_OPAQUE "NCS_CLI_OPAQUE"
#define IPC_ADDR "NCS_IPC_ADDR"
#define IPC_PORT "NCS_IPC_PORT"
#define IPC_EXTADDR "NCS_IPC_EXTADDR"
#define IPC_EXTSOPATH "NCS_IPC_EXTSOPATH"
#else
#define SERVER "ConfD"
#define PORT "4565"
#define CLI_OPAQUE "CONFD_CLI_OPAQUE"
#define IPC_ADDR "CONFD_IPC_ADDR"
#define IPC_PORT "CONFD_IPC_PORT"
#define IPC_EXTADDR "CONFD_IPC_EXTADDR"
#define IPC_EXTSOPATH "CONFD_IPC_EXTSOPATH"
#endif
#define CLI_SOCK_ID 4
#define WANT_CHALLENGE (1 << 7)
#define IA_PROTO_UNAVAILABLE 13

/* Inband signalling codes */
#define INBAND_SIGWINCH  1
#define INBAND_WRITE_ACC 2


#define USER_ARGS /* Comment this out to remove the possibility to send
                   * a user provided user name. When used in a production
                   * environment you may want to remove this option and
                   * possibly some more, to prevent users from masquerading
                   * as other users.
                   */

#define FULL_ACCESS /* Comment this out to disable the ability for the
                     * confd_cli/ncs_cli to login as nouser atall but with all
                     * authorization turned off. The feature can be used
                     * to login to the CLI when the box is broken. For
                     * example when the AAA data is broken.
                     */

/* #define EXTERNAL_IPC */ /* Uncomment this to provide support for user-
                            * defined IPC towards the ConfD/NCS daemon.
                            * The CONFD_IPC_EXTADDR and CONFD_IPC_EXTSOPATH
                            * - or NCS_IPC_EXTADDR and NCS_IPC_EXTSOPATH -
                            * environment variables can then be used to
                            * request a connection using this IPC mechanism,
                            * see the deployment chapter in the User Guide.
                            * Note, on Linux this requires that -ldl is
                            * added to the LIBS definition in the Makefile.
                            */

#ifdef EXTERNAL_IPC
#include <dlfcn.h>
#include "ipc_drv.h"
#endif

#define put_int32(i, s) {((char*)(s))[0] = (char)((i) >> 24) & 0xff; \
                         ((char*)(s))[1] = (char)((i) >> 16) & 0xff; \
                         ((char*)(s))[2] = (char)((i) >> 8)  & 0xff; \
                         ((char*)(s))[3] = (char)((i)        & 0xff);}

#define get_int32(i, s) {i = (((((char*)(s))[0] & 0xff) << 24) |        \
                              ((((char*)(s))[1] & 0xff) << 16) |        \
                              ((((char*)(s))[2] & 0xff) <<  8) |        \
                              ((((char*)(s))[3] & 0xff)         ));}

#define MAX(a, b) ((a) < (b) ? (b) : (a))

static int interactive;
static int verbose = 0;
static int read_term_sz = 0; /* flag set by SIGWINCH handler */
static int width, height;
static int noaaa = 0;
static int stop_on_error = 0;
static int flowctrl = 1;
static char* nl_interactive = "\r\n";
static char* nl_batch       = "\n";
static char* nl;
static int nl_len = 1;
#ifdef __APPLE__
static int old_raw = 1;
#else
static int old_raw = 0;
#endif
struct pollfd fds[3];

static char *block0;
static int  block0_remain;
static char *block1;
static int  block1_remain;
static char in0buf[1024];
static char in1buf[1024];
static char *out0buf=NULL;
static size_t out0buf_len=2048;
static char out1buf[2048];

static unsigned int write_count = 0;
static int write_count_pending = 0;
static char pendbuf[6];


/* MD5 from public domain implementation by Alexandet Peslyak */

/* Any 32-bit or wider unsigned integer data type will do */
typedef unsigned int MD5_u32plus;

typedef struct {
        MD5_u32plus lo, hi;
        MD5_u32plus a, b, c, d;
        unsigned char buffer[64];
        MD5_u32plus block[16];
} MD5_CTX;

static void md5_init(MD5_CTX *ctx);
static void md5_update(MD5_CTX *ctx, void *data, unsigned long size);
static void md5_final(unsigned char *result, MD5_CTX *ctx);

/* End of public domain MD5 implementation */

static void md5_update_int(MD5_CTX *ctx, int val);

#define DIGEST_LENGTH 16
static MD5_CTX ctx;

static int write_fill_confd_noesc(int fd, char *buf, int len)
{
    int i;
    unsigned int done = 0;

    do {
        if ((i = write(fd, (buf+done), len-done)) < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                block0 = (buf+done);
                block0_remain = len-done;
                /* wait until ConfD is ready for more data */
                fds[1].events = fds[1].events | POLLOUT;
                /* plock additional input from terminal */
                fds[0].events = fds[0].events & ~POLLIN;
                return 0;
            }
            if (errno != EINTR)
                return (i);
            i = 0;
        }
        done += i;
    } while (done < len);

    /* check if we have a pend buf and write that if we can */
    if (write_count_pending == 1) {
        write_count_pending = 0;

        int i;
        for(i=0 ; i < 6 ; i++)
            out0buf[i] = pendbuf[i];

        write_fill_confd_noesc(fd, out0buf, 6);
    }

    return (len);
}

static int write_fill_confd(int fd, const char *buf, int len)
{
    int i, n, ret;

    for(i=0, n=0 ; i < len ; i++, n++) {
        /* check if out0buf is large enough */
        if (n >= out0buf_len - 1) {
            out0buf_len += 2048;
            out0buf = confd_xrealloc(out0buf, out0buf_len);
        }
        /* What is this? */
        if (buf[i] == 0) {
            out0buf[n++] = 0;
        }
        out0buf[n] = buf[i];
    }

    ret = write_fill_confd_noesc(fd, out0buf, n);

    return ret;
}

static int write_fill_term(int fd, char *buf, int len)
{
    int i;
    unsigned int done = 0;

    do {
        if ((i = write(fd, (buf+done), len-done)) < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                block1 = (buf+done);
                block1_remain = len-done;
                /* wait until term is ready for more data */
                fds[2].events = fds[2].events | POLLOUT;
                /* plock additional input from confd */
                fds[1].events = fds[1].events & ~POLLIN;
                return 0;
            }
            if (errno != EINTR)
                return (i);
            i = 0;
        }
        write_count += i;
        done += i;
    } while (done < len);

    /* time to report? */
    if (!interactive) {
        /* not interactive, ignore accs */
        write_count = 0;
    }
    else if (write_count > 1024) {
        /* can we write directly? */
        if (!(fds[1].events & POLLOUT)) {
            put_int32(write_count, &out0buf[2]);
            out0buf[0] = 0;  /* ESC char */
            out0buf[1] = INBAND_WRITE_ACC;
            write_fill_confd_noesc(fds[1].fd,  out0buf, 6);

            write_count = 0;
        }
        else if (write_count_pending == 0) {
            write_count_pending = 1;
            put_int32(write_count, &pendbuf[2]);
            pendbuf[0] = 0;  /* ESC char */
            pendbuf[1] = INBAND_WRITE_ACC;
            write_count = 0;
        }
        else {
            // update existing write count
            int oldcount;
            get_int32(oldcount, &pendbuf[2]);
            write_count += oldcount;
            put_int32(write_count, &pendbuf[2]);
            write_count = 0;
        }
    }

    return (len);
}


static int write_int(int fd, int val)
{
    char buf[4];
    put_int32(val, &buf[0]);
    return write_fill_confd(fd, buf, 4);
}

static int read_fill(int fd, unsigned char *buf, int len)
{
    int i;
    unsigned int got = 0;

    do {
        if ((i = read(fd, buf+got, len-got)) <= 0) {
            if (i == 0 || (i < 0 && errno == ECONNRESET)) {
                return -2;
            }
            if (errno != EINTR) {
                return -1;
            }
            i = 0;
        }
        got += i;
    } while (got < len);
    return len;
}

/* Connect to the ConfD/NCS daemon */
static int cli_connect(char *address, char *port)
{
    struct addrinfo hints;
    struct addrinfo *addr;
    int fd;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;

    if (getaddrinfo(address, port, &hints, &addr) != 0) return -1;

    fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (fd < 0) return -1;

    if (connect(fd, addr->ai_addr, addr->ai_addrlen) < 0)
        return -1;

    freeaddrinfo(addr);

    return fd;
}

#ifdef EXTERNAL_IPC
/* Connect to the ConfD/NCS daemon using user-provided IPC */
static int ext_cli_connect(char *addr)
{
    char *path;
    void *handle;
    confd_ext_ipc_init_func_t *ext_init_ops;
    struct confd_ext_ipc_cbs *ecb = NULL;
    confd_ipc_init_func_t *init_ops;
    struct confd_ipc_cbs *cb = NULL;
    char *errstr;
    int fd;

    if ((path = getenv(IPC_EXTSOPATH)) == NULL) {
        fprintf(stderr, "Environment " IPC_EXTSOPATH " must "
                "be set when using external IPC\n");
        return -1;
    }
    if ((handle = dlopen(path, RTLD_LOCAL|RTLD_LAZY)) == NULL) {
        fprintf(stderr, "Failed to load %s\n", path);
        return -1;
    }
    if ((ext_init_ops = (confd_ext_ipc_init_func_t *)
         dlsym(handle, "confd_ext_ipc_init")) != NULL) {
        ecb = (*ext_init_ops)();
    } else if ((init_ops = (confd_ipc_init_func_t *)
                dlsym(handle, "confd_ipc_init")) != NULL) {
        cb = (*init_ops)();
    }

    if (ecb != NULL) {
        if (ecb->connect != NULL) {
            if ((fd = ecb->connect(addr, &errstr)) < 0)
                return -1;
        } else {
            int family, type, protocol;
            struct sockaddr *saddr;
            socklen_t addrlen;
            if (ecb->getaddrinfo(addr, &family, &type, &protocol,
                                 &saddr, &addrlen, &errstr) < 0)
                return -1;
            if ((fd = ecb->socket(family, type, protocol, &errstr)) < 0)
                return -1;
            if (connect(fd, saddr, addrlen) < 0)
                return -1;
            free(saddr);
        }
    } else if (cb != NULL) {
        if ((fd = cb->connect(addr)) < 0)
            return -1;
    } else {
        fprintf(stderr, "Failed to init %s\n", path);
        return -1;
    }

    if (verbose)
        fprintf(stderr, "Connected to CLI server\n");

    return fd;
}
#endif

#ifndef NCURSES
struct termios prev_state;

static int tty_raw(int fd)
{
    struct termios  b;
    unsigned int iflag, lflag, cflag, oflag;

    if (tcgetattr(fd, &prev_state) < 0) return -1;

    iflag = prev_state.c_iflag;
    lflag = prev_state.c_lflag;
    cflag = prev_state.c_cflag;
    oflag = prev_state.c_oflag;

    b = prev_state;

    if (old_raw) {
        iflag = iflag & ~(ISTRIP | IXON | BRKINT | ICRNL);
        lflag = lflag & ~(ECHO | ICANON | IEXTEN | ISIG);
        cflag = (cflag & ~(CSIZE | PARENB)) | CS8;
        oflag = oflag & ~OPOST;
    }
    else {
        iflag = iflag & ~(ISTRIP | IXON | BRKINT | ICRNL);
        lflag = lflag & ~(ECHO | ICANON | IEXTEN | ISIG);
        cflag = (cflag & ~(CSIZE | PARENB)) | CS8;
        oflag = oflag | OPOST | ONLCR;
    }

    b.c_iflag = iflag;
    b.c_lflag = lflag;
    b.c_cflag = cflag;
    b.c_oflag = oflag;

    b.c_cc[VMIN] = 1;
    b.c_cc[VTIME] = 0;

    if (tcsetattr(fd, TCSAFLUSH, &b) < 0) return -1;

    return 0;
}

static int tty_restore(int fd)
{
    if (tcsetattr(fd, TCSAFLUSH, &prev_state) < 0)
        return -1;

    return 0;
}
#endif

int prev_fd_flags, prev_outfd_flags;

void set_nonblocking(int fd, int outfd)
{
    /* configure socket for non-blocking io */
    prev_fd_flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, prev_fd_flags | O_NONBLOCK);

    prev_outfd_flags = fcntl(outfd, F_GETFL, 0);
    fcntl(outfd, F_SETFL, prev_outfd_flags | O_NONBLOCK);
}

void restore_blocking(int fd, int outfd)
{
    /* restore blocking io */
    fcntl(fd, F_SETFL, prev_fd_flags);
    fcntl(outfd, F_SETFL, prev_outfd_flags);
}

static void usage(char *cmd) {
    fprintf(stderr, "Usage: %s [options] [file]\n", cmd);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --help, -h            display this help\n");
    fprintf(stderr, "  --host, -H <host>     current host name "
            "(used in prompt)\n");
    fprintf(stderr, "  --address, -A <addr>  cli address to connect to\n");
    fprintf(stderr, "  --port, -P <port>     cli port to connect to\n");
    fprintf(stderr, "  --cwd,  -c <dir>      current working directory\n");
    fprintf(stderr, "  --proto, -p <proto>   type of connection (tcp, ssh, "
            "console)\n");
    fprintf(stderr, "  --verbose, -v         verbose output\n");
    fprintf(stderr, "  --ip, -i              clients source ip[/port]\n");
    fprintf(stderr, "  --interactive, -n     force interactive mode\n");
    fprintf(stderr, "  --escape-char, -E <C> brute force shutdown when user "
            "enters ASCII C\n");
#ifndef NCS
    fprintf(stderr, "  --old-raw, -o         use raw tty processing for tty "
            "sessions\n");
    fprintf(stderr, "  --noninteractive, -N  force noninteractive mode\n");
    fprintf(stderr, "  --ttyname, -T <name>  tty name\n");
    fprintf(stderr, "  --terminal, -t <name> terminal name\n");
#endif
    fprintf(stderr, "  -J                    Juniper style CLI\n");
    fprintf(stderr, "  -C                    Cisco XR style CLI\n");
#ifndef NCS
    fprintf(stderr, "  -I                    Cisco IOS style CLI\n");
#endif
#ifdef USER_ARGS
    fprintf(stderr, "  --user, -u <user>     clients user name\n");
    fprintf(stderr, "  --uid, -U <uid>       clients user id\n");
    fprintf(stderr, "  --groups, -g <groups> clients group list\n");
    fprintf(stderr, "  --gids, -D <gids>     clients group id list\n");
    fprintf(stderr, "  --gid, -G <gid>       clients group id\n");
#endif
#ifdef FULL_ACCESS
    fprintf(stderr, "  --noaaa               disable AAA\n");
#endif
    fprintf(stderr, "  --opaque, -O <opaque> pass opaque info\n");
    fprintf(stderr, "  --stop-on-error, -s   stop on error\n");
    fprintf(stderr, "\n");
}

static struct option long_options[] = {
    {"host",    1, 0, 'H'},
    {"cwd",     1, 0, 'c'},
    {"proto",   1, 0, 'p'},
    {"address", 1, 0, 'A'},
    {"port",    1, 0, 'P'},
    {"help",    0, 0, 'h'},
    {"verbose", 0, 0, 'v'},
    {"ip",      1, 0, 'i'},
    {"interactive",      0, 0, 'n'},
    {"noninteractive",      0, 0, 'N'},
    {"old-raw",      0, 0, 'o'},
    {"cisco",   0, 0, 'C'},
    {"juniper", 0, 0, 'J'},
#ifndef NCS
    {"ios",     0, 0, 'I'},
#endif
    {"ttyname", 1, 0, 'T'},
#ifdef USER_ARGS
    {"user",    1, 0, 'u'},
    {"uid",     1, 0, 'U'},
    {"groups",  1, 0, 'g'},
    {"gids",    1, 0, 'D'},
    {"gid",     1, 0, 'G'},
#endif
#ifdef FULL_ACCESS
    {"noaaa",  0, 0, 'a'},
#endif
    {"terminal",1, 0, 't'},
    {"opaque",  1, 0, 'O'},
    {"escape-char",  1, 0, 'E'},
    {"stop-on-error",  0, 0, 's'},
    {0,         0, 0, 0}
};


static void sig_handler(int sig)
{
    if (sig == SIGWINCH)
        read_term_sz = 1;
    return;
}

static void get_size()
{
#ifdef NCURSES
    static WINDOW *w;
    getmaxyx(w, height, width);
#else
    {
        struct winsize size;
        ioctl(STDIN_FILENO, TIOCGWINSZ, (char *) &size);

        width = size.ws_col;
        height = size.ws_row;

    }
#endif
}

int is_ip_char(char c)
{
    return
        isdigit(c) ||
        c == '.' ||
        c == ':' ||
        (c >= 'a' && c <= 'f') ||
        (c >= 'A' && c <= 'F');
}


static int get_login(char **buf, ssize_t *buflen)
{
    int ret = getlogin_r(*buf, *buflen);
    while (ret == ERANGE) {
        /* buffer was not big enough, grow */
        *buflen = *buflen + 4096;
        *buf = confd_xrealloc(*buf, *buflen);
        ret = getlogin_r(*buf, *buflen);
    }
    return ret;
}

static char *get_pw_name(const char *user, ssize_t pwsize)
{
    struct passwd passwd;
    struct passwd *pwd = NULL;
    char *pwbuf = confd_xmalloc(pwsize);
    if (!confd_get_pwnam(user, &passwd, &pwbuf, &pwsize, &pwd)
        && pwd->pw_uid != getuid()
        && !confd_get_pwuid(getuid(), &passwd, &pwbuf, &pwsize, &pwd)) {
        user = pwd->pw_name;
    }
    char *user_dup = strdup(user);
    free(pwbuf);
    return user_dup;
}

int main(int argc, char *argv[])
{
    struct pollfd *fdsptr = fds;
    int nfds;
    int fd;
    char *user = NULL;
    char *term = NULL;
    char ip[1024];
    char ctype[1024];
    char *host = NULL;
    char socktype[1];
    char cwd[1024];
    char *groups = NULL;
    int *gids = NULL;
    int gidsn = 0;
    int uid;
    int gid;
    char *opaque = NULL;
    int interactive_send = -1;
    char *address = "127.0.0.1";
    char *port = PORT;
    char *ssh_connection;
    int escape_count=0;
    int infd = fileno(stdin);
    int outfd = fileno(stdout);
    char *style = "unset";
#ifdef EXTERNAL_IPC
    char *extaddr;
#endif
    unsigned char secret[1024];
    int do_access;
    int exit_code=7;
    int next_may_be_exit_code=0;
    char escape=-1;
    int num_read;
    char control_ch;
    long tmpsize;
    if ((tmpsize = sysconf(_SC_TTY_NAME_MAX)) < 1) {
        tmpsize = 1024;
    }
    char tty_name[tmpsize];

    out0buf = confd_xmalloc(out0buf_len);

    /* Check if we are invoked from an OpenSSH connection */
    ssh_connection = getenv("SSH_CONNECTION");
    if (ssh_connection) {
        char *end=NULL;

        confd_strlcpy(ctype, "ssh", sizeof(ctype));
        /* look for first two elements of ssh_connection */
        end = strchr(ssh_connection, ' ');
        if (end != NULL) {
            int i;
            int n = end-ssh_connection;
            char *p = end;

            for(i=0 ; i < n && is_ip_char(ssh_connection[i]) ; i++)
                ip[i] = ssh_connection[i];

            ip[n] = '\0';

            /* Skip any trailing stuff in the ip address, for example,
             * zone index (%eth).
             */
            while(*p != ' ' && *p != '\0')
                p++;

            /* skip whitespace */
            while (*p == ' ')
                p++;

            end = strchr(p, ' ');
            if (end != NULL) {
                int iplen = strlen(ip);
                n = end - p;
                /* address/port */
                snprintf(&ip[iplen], 1024-iplen, "/%.*s", n, p);
            }
        }
        else {
            confd_strlcpy(ip, "127.0.0.1", sizeof(ip));
        }
    }
    else {
        /* default to console as we do not detect telnet at this point */
        confd_strlcpy(ctype, "console", sizeof(ctype));
        confd_strlcpy(ip, "127.0.0.1", sizeof(ip));
    }

    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        perror("getcwd");
        return 1;
    }

    /* Check environment for address/port to connect to the  daemon */
    {
        char *atmp = getenv(IPC_ADDR);
        char *ptmp = getenv(IPC_PORT);
        if (atmp) {
            address = atmp;
        }
        if (ptmp) {
            port = ptmp;
        }
    }

    /* we use the effective uid of current process */
    uid = geteuid();

    /* we use the effective gid of current process */
    gid = getegid();

    /* determine default ttyname */
    {
        if (ttyname_r(infd, tty_name, sizeof(tty_name))) {
            tty_name[0] = '\0';
        }
    }

    /* check environment for "opaque" string */
    opaque = getenv(CLI_OPAQUE);

    /* Process command line arguments */
    while(1) {
        char *rpath;
        int option_index;
        int c;

        /* this call can easily be replaced with a more portable version
         * if needed
         */
        c = getopt_long(argc, argv, "c:hp:H:A:P:vi:u:U:g:G:D:t:nNaCIJE:T:oO:s",
                        long_options, &option_index);

        if (c == -1) break;

        switch(c) {
        case 'H':
            host = optarg;
            break;

        case 'T':
            tty_name[sizeof(tty_name)-1] = '\0';
            confd_strlcpy(tty_name, optarg, sizeof(tty_name));
            break;

        case 'c':
            rpath = realpath(optarg, NULL);
            if (NULL == rpath)
            {
                fprintf(stderr, "Error: %s for path %s\n",
                        strerror(errno), optarg);
                exit(1);
            }
            cwd[sizeof(cwd)-1] = '\0';
            confd_strlcpy(cwd, rpath, sizeof(cwd));
            break;

        case 'h':
            usage(argv[0]);
            free(gids);
            return 0;

        case 'p':
            ctype[sizeof(ctype)-1] = '\0';
            if (strcmp(optarg, "tcp") != 0 &&
                strcmp(optarg, "ssh") != 0 &&
                strcmp(optarg, "http") != 0 &&
                strcmp(optarg, "https") != 0 &&
                strcmp(optarg, "console") != 0) {
                fprintf(stderr, "Error: unsupported protocol type: %s\n",
                        optarg);
                usage(argv[0]);
                free(gids);
                exit(1);
            }
            else
                confd_strlcpy(ctype, optarg, sizeof(ctype));
            break;

        case 'A':
            address = optarg;
            break;

        case 'o':
            old_raw = 1;
            break;

        case 'P':
            port = optarg;
            break;

        case 'v':
            verbose = 1;
            break;

        case 'i':
            confd_strlcpy(ip, optarg, sizeof(ip));
            break;

        case 'n':
            interactive_send = 1;
            break;
        case 'N':
            interactive_send = 0;
            break;
#ifndef NCS
        case 'I':
            style = "i";
            break;
#endif
        case 'J':
            style = "j";
            break;

        case 'C':
            style = "c";
            break;
#ifdef USER_ARGS
        case 'u':
            user = optarg;
            break;

        case 'U':
            uid = atoi(optarg);
            break;

        case 'g':
            groups = optarg;
            break;

        case 'D':
        {
            /* parse lists of gids, for example
             * 10,201,45
             */

            if (gids) {
                fprintf(stderr, "Only one -D option allowed.\n");
                exit(1);
            }

            char *gidsstr = optarg;
            char *tmp = gidsstr;

            /* count upper bound on groups first */
            int i = 1;
            while (*tmp != '\0') {
                if (*tmp == ',') i++;
                tmp++;
            }

            gids = confd_xmalloc(sizeof(int) * i);

            if (gids == NULL) {
                fprintf(stderr, "Failed to allocate memory.\n");
                exit(1);
            }

            i = 0;
            char *saveptr = NULL;
            while ((tmp = strtok_r(gidsstr, ",", &saveptr)) != NULL) {
                gidsstr = NULL;
                char *endptr;

                int res = (int)strtol(tmp, &endptr, 0);
                if (endptr == tmp) {
                    /* no digit found */
                    fprintf(stderr, "Error: illegal gid %s\n", tmp);
                    free(gids);
                    exit(1);
                } else {
                    gids[i++] = res;
                }
            }

            gidsn = i;

            break;
        }

        case 'G':
            gid = atoi(optarg);
            break;
#endif
#ifdef FULL_ACCESS
        case 'a':
            noaaa = 1;
            break;
#endif
        case 't':
            term = optarg;
            break;

        case 'O':
            opaque = optarg;
            break;

        case 'E':
            escape = (char) atoi(optarg);
            break;

        case 's':
            stop_on_error = 1;
            break;

        default:
            usage(argv[0]);
            free(gids);
            return 1;
        }
    }

    if (optind < argc) {
        /* a file argument was supplied, read input from file */
        int filefd = open(argv[optind], O_RDONLY);

        if (filefd > 0) {
            infd = filefd;
        }
        else {
            fprintf(stderr, "%s: failed to open %s\n", argv[0], argv[optind]);
            exit(1);
        }
    }

#ifdef EXTERNAL_IPC
    if ((extaddr = getenv(IPC_EXTADDR)) != NULL)
        fd = ext_cli_connect(extaddr);
    else
#endif
        fd = cli_connect(address, port);

    if (fd < 0) {
        fprintf(stderr, "Failed to connect to server\n");
        return 1;
    }

    /* get access check secret */
    if ((do_access = confd_ipc_access_get_secret(secret, sizeof(secret))) < 0) {
        do_access = 0;
    }

    /* send socket type */
    socktype[0] = CLI_SOCK_ID;
    if (do_access)
        socktype[0] |= WANT_CHALLENGE;
    write_fill_confd(fd,  socktype, 1);

    /* Check that ConfD really accepts the CLI
     * Read byte from ConfD determining if CLI is registered
     */
    if ((num_read = read(fd, &control_ch, 1)) <= 0) {
        if (num_read == 0 || (num_read < 0 && errno == ECONNRESET)) {
            num_read = -2;
        }
        if (errno != EINTR) {
            num_read = -1;
        }
    }

    /* If ConfD is in phase1, CLI is not allowed to connect
     * If socket is down but access check is required, skip this
     */
    if((num_read == 1 && control_ch == IA_PROTO_UNAVAILABLE) ||
       (num_read < 0 && do_access == 0)) {
        fprintf(stderr, "Failed to connect to server\n");
        return 1;
    }

    /* run access check if needed */
    if (do_access && confd_ipc_access_check(fd, secret) != 1) {
        fprintf(stderr, "Access check failed\n");
        return 1;
    }

    /* send version */
    write_fill_confd(fd,  CLISTART_PROTO_VSN, strlen(CLISTART_PROTO_VSN));
    write_fill_confd(fd,  ";", 1);
    if (verbose) fprintf(stderr, "cli: sending version\n");

    if (do_access) {
        unsigned char challange[DIGEST_LENGTH];
        int n;

        if ((n=read_fill(fd, challange, DIGEST_LENGTH)) != DIGEST_LENGTH) {
            fprintf(stderr, "Failed to read challange: %d\n", n);
            return 1;
        }

        md5_init(&ctx);
        md5_update(&ctx, challange, DIGEST_LENGTH);
        md5_update(&ctx, secret, strlen((char*) secret));
        md5_update(&ctx, CLISTART_PROTO_VSN, strlen(CLISTART_PROTO_VSN));
        md5_update(&ctx, ";", 1);
    }

    /* remove secret from memory */
    memset(secret, 0, sizeof(secret));

    /* determine user name */
    if (user == NULL) {
        ssize_t loginsize = MAX(sysconf(_SC_LOGIN_NAME_MAX),
                                sysconf(_SC_GETPW_R_SIZE_MAX));
        if (loginsize < 1) {
            loginsize = 4096; /* really huge (from Mac) */
        }
        char *loginbuf = confd_xmalloc(loginsize);
        if (get_login(&loginbuf, &loginsize) == 0) {
            user = loginbuf;
        } else {
            user = NULL;
        }
        if (user == NULL) user = getenv("LOGNAME");
        if (user == NULL) user = getenv("USERNAME");
        if (user == NULL) user = getenv("USER");
        if (user == NULL) {
            fprintf(stderr, "Failed to determine user name\n");
            free(loginbuf);
            return 1;
        }
        /* handle 'su -' (getlogin() returns original user on Linux) */

        user = get_pw_name(user, loginsize);
        free(loginbuf);
    } else {
        user = strdup(user);
    }

    /* determine terminal name */
    if (term == NULL) {
        term = getenv("TERM");

        if (term == NULL) term = "vt100";
    }

    /* extract group name information */
    if (groups == NULL) {
        int n = getgroups(0, NULL);
        gid_t *list = confd_xmalloc(n*sizeof(gid_t));

        if (list == NULL) {
            fprintf(stderr, "Failed to allocate memory.");
            exit(1);
        }

        if ((n = getgroups(n, list)) > 0) {
            ssize_t grpsize = confd_sysconf_size(_SC_GETGR_R_SIZE_MAX);
            char *grpbuf = confd_xmalloc(grpsize);
            int size = confd_get_group_name_len(list, n, &grpbuf, &grpsize);
            groups = confd_build_group_names(list, n, size, &grpbuf, &grpsize);
            free(grpbuf);
        }
        free(list);
    } else {
        groups = strdup(groups);
    }

    /* no group specified or failure to read groups */
    if (groups == NULL) {
        groups = strdup("");
    }

    /* extract group gid information */
    if (gids == NULL) {
        int n = getgroups(0, NULL);
        gid_t *list = confd_xmalloc(n*sizeof(gid_t));

        if ((n = getgroups(n, list)) > 0) {
            gids = confd_xmalloc(sizeof(int) * n);
            gidsn = n;

            for(int i = 0 ; i < n ; i++) {
                gids[i] = list[i];
            }
        }
        free(list);
    }

    /* send username */
    write_fill_confd(fd,  user, strlen(user));
    write_fill_confd(fd,  ";", 1);
    if (do_access) md5_update(&ctx, user, strlen(user));
    if (do_access) md5_update(&ctx, ";", 1);
    if (verbose) fprintf(stderr, "cli: sending username\n");

    /* send ip */
    write_fill_confd(fd,  ip, strlen(ip));
    write_fill_confd(fd,  ";", 1);
    if (do_access) md5_update(&ctx, ip, strlen(ip));
    if (do_access) md5_update(&ctx, ";", 1);
    if (verbose) fprintf(stderr, "cli: sending ip\n");

    /* send proto type (ssh, tcp, console) */
    write_fill_confd(fd,  ctype, strlen(ctype));
    write_fill_confd(fd,  ";", 1);
    if (do_access) md5_update(&ctx, ctype, strlen(ctype));
    if (do_access) md5_update(&ctx, ";", 1);
    if (verbose) fprintf(stderr, "cli: sending type\n");

    /* send opaque (as "special" first group for back/forward compat) */
    if (opaque != NULL) {
        int i, len = strlen(opaque);

        for (i = 0; i < len; i++) {
            /* turn comma into NUL since it is separator in group list */
            if (opaque[i] == ',')
                opaque[i] = '\0';
        }
        write_fill_confd(fd, "OPAQUE=", strlen("OPAQUE="));
        if (do_access) md5_update(&ctx, "OPAQUE=", strlen("OPAQUE="));
        write_fill_confd(fd, opaque, len);
        if (do_access) md5_update(&ctx, opaque, len);
        write_fill_confd(fd,  ",", 1);
        if (do_access) md5_update(&ctx, ",", 1);
        if (verbose) fprintf(stderr, "cli: sending opaque\n");
    }

    /* send groups */
    write_fill_confd(fd,  groups, strlen(groups));
    write_fill_confd(fd,  ";", 1);
    if (verbose) fprintf(stderr, "cli: sending groups\n");
    if (do_access) md5_update(&ctx, groups, strlen(groups));
    if (do_access) md5_update(&ctx, ";", 1);

    /* send host name */
    write_fill_confd(fd, "HOST=", strlen("HOST="));
    if (do_access) md5_update(&ctx, "HOST=", strlen("HOST="));
    if (host != NULL) {
      write_fill_confd(fd,  host, strlen(host));
      if (do_access) md5_update(&ctx, host, strlen(host));
    }
    write_fill_confd(fd,  ";", 1);
    if (do_access) md5_update(&ctx, ";", 1);
    if (verbose) fprintf(stderr, "cli: sending hostname\n");

    /* send ttyname */
    write_fill_confd(fd,  tty_name, strlen(tty_name));
    write_fill_confd(fd,  ";", 1);
    if (do_access) md5_update(&ctx, tty_name, strlen(tty_name));
    if (do_access) md5_update(&ctx, ";", 1);
    if (verbose) fprintf(stderr, "cli: sending ttyname\n");

    /* send current working directory */
    write_fill_confd(fd,  cwd, strlen(cwd));
    write_fill_confd(fd,  ";", 1);
    if (do_access) md5_update(&ctx, cwd, strlen(cwd));
    if (do_access) md5_update(&ctx, ";", 1);
    if (verbose) fprintf(stderr, "cli: sending cwd\n");

    /* send terminal */
    write_fill_confd(fd,  term, strlen(term));
    write_fill_confd(fd,  ";", 1);
    if (do_access) md5_update(&ctx, term, strlen(term));
    if (do_access) md5_update(&ctx, ";", 1);
    if (verbose) fprintf(stderr, "cli: sending terminal\n");

    /* send SSH_CONNECTION */
    if (ssh_connection) {
        write_fill_confd(fd,  ssh_connection, strlen(ssh_connection));
        write_fill_confd(fd,  ";", 1);
        if (do_access) md5_update(&ctx, ssh_connection, strlen(ssh_connection));
        if (do_access) md5_update(&ctx, ";", 1);
    }
    else {
        write_fill_confd(fd,  ";", 1);
        if (do_access) md5_update(&ctx, ";", 1);
    }
    if (verbose) fprintf(stderr, "cli: sending ssh_connection info\n");

    /* send cli style */
    write_fill_confd(fd, style, strlen(style));
    write_fill_confd(fd,  ";", 1);
    if (do_access) md5_update(&ctx, style, strlen(style));
    if (do_access) md5_update(&ctx, ";", 1);
    if (verbose) fprintf(stderr, "cli: sending CLI style\n");

    /* send user identity (uid) */
    write_int(fd, uid);
    if (verbose) fprintf(stderr, "cli: sending uid\n");
    if (do_access) md5_update_int(&ctx, uid);

    /* send user gid (gid) */
    write_int(fd, gid);
    if (verbose) fprintf(stderr, "cli: sending gid\n");
    if (do_access) md5_update_int(&ctx, gid);

    /* send users secondary groups */
    write_int(fd, gidsn);
    if (do_access) md5_update_int(&ctx, gidsn);
    {
        int i;
        for(i=0 ; i < gidsn ; i++) {
            write_int(fd, gids[i]);
            if (do_access) md5_update_int(&ctx, gids[i]);
        }
    }
    if (verbose) fprintf(stderr, "cli: sending gids\n");

    /* activate raw mode */
    interactive = isatty(infd);

    if (interactive_send == -1)
        interactive_send = interactive;

    if (interactive) {
        tty_raw(infd);
        signal(SIGWINCH, sig_handler);
        get_size();
        if (old_raw) {
            nl = nl_interactive;
            nl_len = 2;
        } else {
            nl = nl_batch;
            nl_len = 1;
        }
    }
    else {
        nl = nl_batch;
        nl_len = 1;
    }

    if (height == 0) height = 24;
    if (width == 0) width = 80;

    write_int(fd,  width);
    if (verbose) fprintf(stderr, "cli: sending width%s", nl);
    if (do_access) md5_update_int(&ctx, width);
    write_int(fd,  height);
    if (verbose) fprintf(stderr, "cli: sending height%s", nl);
    if (do_access) md5_update_int(&ctx, height);
    write_int(fd, interactive_send);
    if (verbose) fprintf(stderr, "cli: sending interactive%s", nl);
    if (do_access) md5_update_int(&ctx, interactive_send);
    write_int(fd, noaaa);
    if (verbose) fprintf(stderr, "cli: sending noaaa%s", nl);
    if (do_access) md5_update_int(&ctx, noaaa);
    write_int(fd, stop_on_error);
    if (verbose) fprintf(stderr, "cli: sending stop_on_error %s", nl);
    if (do_access) md5_update_int(&ctx, stop_on_error);

    if (!interactive) {
      /* not interactive, flow ctrl disabled */
      flowctrl = 0;
    }
    write_int(fd, flowctrl);
    if (verbose) fprintf(stderr, "cli: sending flowctrl %s", nl);
    if (do_access) md5_update_int(&ctx, flowctrl);

    if (do_access) {
        unsigned char buf[DIGEST_LENGTH];
        md5_final(buf, &ctx);
        write_fill_confd(fd, (char *) buf, DIGEST_LENGTH);
    }

    /**********************************************************************
     * Set up sockets for main proxy loop, enter non-blocking mode
     */

    fds[0].fd = infd;
    fds[0].events = POLLIN;

    fds[1].fd = fd;
    fds[1].events = POLLIN;

    fds[2].fd = outfd;
    fds[2].events = 0;

    nfds = 3;

    set_nonblocking(fd, outfd);

    /* Tunnel IO */
    while(1) {
        int r;

        if (fds[2].events == 0) {
            /* Do not poll outfd unless we are interested
             * in the result to avoid looping when outfd is
             * closed.
             */
            r = poll(fdsptr, nfds-1, -1);
        }
        else {
            r = poll(fdsptr, nfds, -1);
        }

        if (verbose && r < 0) perror("poll");

        if (r < 0 && interactive && !(fds[1].events & POLLOUT)) {
            /* Check for term resize event */
            if (read_term_sz == 1) {
                read_term_sz = 0;
                get_size();
                if (verbose) {
                    fprintf(stderr, "sigwinch %d %d%s", width, height, nl);
                }
                put_int32(width, &out0buf[2]);
                put_int32(height, &out0buf[6]);
                out0buf[0] = 0;  /* ESC char */
                out0buf[1] = INBAND_SIGWINCH;
                write_fill_confd_noesc(fd,  out0buf, 10);
            }
            continue;
        }

        /* check if we are waiting for confd to be ready to accept
         * more data
         */
        if (fds[1].revents & POLLOUT && fds[1].events & POLLOUT) {
            /* ready, write */

            /* restore poll flags, write_fill_confd_noesc will
             * re-set them if we block again
             */
            fds[1].events = fds[1].events & ~POLLOUT;
            fds[0].events = fds[0].events | POLLIN;

            /* write remaining unwritten data */
            write_fill_confd_noesc(fd, block0, block0_remain);
        }

        /* check if we are waiting for terminal to be ready to accept
         * more data
         */
        if (fds[2].revents & POLLOUT && fds[2].events & POLLOUT) {
            int w;
            /* ready, write */

            /* restore poll flags, write_fill_term will re-set them if
             * we block again
             */
            fds[2].events = fds[2].events & ~POLLOUT;
            fds[1].events = fds[1].events | POLLIN;

            w = write_fill_term(outfd, block1, block1_remain);

            if (w < 0) {
                perror("write");
                if (verbose)
                    fprintf(stderr, "cli: write error to stdout%s", nl);
                goto error;
            }
        }

        /* Data from terminal side? */
        if (fds[0].revents & (POLLIN | POLLHUP) && fds[0].events & POLLIN) {
            int n, w, i;

            n = read(fds[0].fd, in0buf, 1024);
            if (n < 0 && errno == EAGAIN) {
                /* changed its mind on pollin, broken kernel? */
                n = 0;
            }
            else if (n < 0 && errno != ECONNRESET) {
                perror("read");
                if (verbose)
                    fprintf(stderr, "cli: error reading from stdin%s", nl);
                goto error;
            }
            else if (n == 0 || (n < 0 && errno == ECONNRESET)) {
                if (verbose)
                    fprintf(stderr, "cli: read close on stdin%s", nl);

                if (interactive) {
                    goto error;
                }
                else {
                    shutdown(fds[1].fd, SHUT_WR);
                    /* wait for the server to close */
                    if (fdsptr == fds) {
                        fdsptr++;
                        nfds--;
                    }
                    fds[0].revents = 0;
                }
            }

            /* Scan for global panic character: three consecutive
             *  ctrl-_
             */
            for(i=0 ; i < n && n > 0 ; i++) {
                if (in0buf[i] == 31) {
                    escape_count++;
                    if (escape_count == 3) {
                        if (verbose)
                            fprintf(stderr, "cli: read escape sequence%s", nl);
                        exit_code=6;
                        goto error;
                    }
                }
                else if (escape != -1 && in0buf[i] == escape) {
                    exit_code=6;
                    goto error;
                }
                else {
                    escape_count = 0;
                }
            }

            if (n > 0) {
                w = write_fill_confd(fd,  in0buf, n);
                if (w < 0) {
                    perror("write");
                    if (verbose)
                        fprintf(stderr, "cli: write error to server%s", nl);
                    goto error;
                }
            }
        }
        else if (fds[0].revents & ~POLLOUT && fds[0].events != 0) {
            if (verbose)
                fprintf(stderr, "cli: error events on stdin%s", nl);
            if (interactive)
                goto error;
            else {
                shutdown(fds[1].fd, SHUT_WR);
                /* wait for the server to close */
                if (fdsptr == fds) {
                    fdsptr++;
                    nfds--;
                }
                fds[0].revents = 0;
            }
        }

        /* Data from ConfD? */
        if (fds[1].revents & POLLIN && fds[1].events & POLLIN) {
            int n, w, i, j;

            n = read(fds[1].fd, in1buf, 1024);
            if (n < 0 && errno == EAGAIN) {
                /* changed its mind on pollin, broken kernel? */
                n=0;
            }
            else if (n < 0 && errno != ECONNRESET) {
                perror("read");
                if (verbose)
                    fprintf(stderr, "cli: read error from server%s", nl);
                goto error;
            }
            else if (n == 0 || (n < 0 && errno == ECONNRESET)) {
                if (verbose)
                    fprintf(stderr, "cli: read close from server%s", nl);
                goto error;
            }

            /* escape \n with \r\n */
            for(i=0,j=0 ; i < n ; i++,j++) {
                if (next_may_be_exit_code) {
                    next_may_be_exit_code=0;
                    if (in1buf[i] != '\0') {
                        exit_code = (int) ((unsigned char)in1buf[i]);
                        if (exit_code ==  254)
                            exit_code=0;
                        if (verbose)
                            fprintf(stderr, "cli: setting exit code: %d%s",
                                    exit_code, nl);
                        j--;
                    } else
                        out1buf[j]=in1buf[i];
                }
                else if (in1buf[i] == '\n' &&
                    nl_len == 2) {
                    out1buf[j++] = nl[0];
                    out1buf[j]   = nl[1];
                }
                else if (in1buf[i] == '\0') {
                    next_may_be_exit_code=1;
                    j--;
                }
                else
                    out1buf[j] = in1buf[i];
            }

            if (j > 0)
                w = write_fill_term(outfd, out1buf, j);
            else
                w = 0;

            if (w < 0) {
                perror("write");
                if (verbose)
                    fprintf(stderr, "cli: write error to stdout%s", nl);
                goto error;
            }
        }
        else if ((fds[1].revents & ~POLLOUT && fds[1].events != 0) &&
                 (fds[2].revents & ~POLLOUT && fds[2].events != 0) ) {
            if (verbose)
                fprintf(stderr, "cli: error on server socket%s", nl);
            goto error;
        }
    }

 error:
    if (interactive) {
#ifdef NCURSES
        endwin();
#else
        tty_restore(1);
#endif
    }

    restore_blocking(fd, outfd);
    free(user);
    free(groups);

    return exit_code;
}

/* MD5 from public domain implementation by Alexandet Peslyak */

/*
 * The basic MD5 functions.
 *
 * F and G are optimized compared to their RFC 1321 definitions for
 * architectures that lack an AND-NOT instruction, just like in Colin Plumb's
 * implementation.
 */
#define F(x, y, z)                      ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)                      ((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)                      ((x) ^ (y) ^ (z))
#define I(x, y, z)                      ((y) ^ ((x) | ~(z)))

/*
 * The MD5 transformation for all four rounds.
 */
#define STEP(f, a, b, c, d, x, t, s) \
        (a) += f((b), (c), (d)) + (x) + (t); \
        (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
        (a) += (b);

/*
 * SET reads 4 input bytes in little-endian byte order and stores them
 * in a properly aligned word in host byte order.
 *
 * The check for little-endian architectures that tolerate unaligned
 * memory accesses is just an optimization.  Nothing will break if it
 * doesn't work.
 */
#if defined(__i386__) || defined(__x86_64__) || defined(__vax__)
#define SET(n) \
        (*(MD5_u32plus *)&ptr[(n) * 4])
#define GET(n) \
        SET(n)
#else
#define SET(n) \
        (ctx->block[(n)] = \
        (MD5_u32plus)ptr[(n) * 4] | \
        ((MD5_u32plus)ptr[(n) * 4 + 1] << 8) | \
        ((MD5_u32plus)ptr[(n) * 4 + 2] << 16) | \
        ((MD5_u32plus)ptr[(n) * 4 + 3] << 24))
#define GET(n) \
        (ctx->block[(n)])
#endif

/*
 * This processes one or more 64-byte data blocks, but does NOT update
 * the bit counters.  There are no alignment requirements.
 */
static void *body(MD5_CTX *ctx, void *data, unsigned long size)
{
        unsigned char *ptr;
        MD5_u32plus a, b, c, d;
        MD5_u32plus saved_a, saved_b, saved_c, saved_d;

        ptr = data;

        a = ctx->a;
        b = ctx->b;
        c = ctx->c;
        d = ctx->d;

        do {
                saved_a = a;
                saved_b = b;
                saved_c = c;
                saved_d = d;

/* Round 1 */
                STEP(F, a, b, c, d, SET(0), 0xd76aa478, 7)
                STEP(F, d, a, b, c, SET(1), 0xe8c7b756, 12)
                STEP(F, c, d, a, b, SET(2), 0x242070db, 17)
                STEP(F, b, c, d, a, SET(3), 0xc1bdceee, 22)
                STEP(F, a, b, c, d, SET(4), 0xf57c0faf, 7)
                STEP(F, d, a, b, c, SET(5), 0x4787c62a, 12)
                STEP(F, c, d, a, b, SET(6), 0xa8304613, 17)
                STEP(F, b, c, d, a, SET(7), 0xfd469501, 22)
                STEP(F, a, b, c, d, SET(8), 0x698098d8, 7)
                STEP(F, d, a, b, c, SET(9), 0x8b44f7af, 12)
                STEP(F, c, d, a, b, SET(10), 0xffff5bb1, 17)
                STEP(F, b, c, d, a, SET(11), 0x895cd7be, 22)
                STEP(F, a, b, c, d, SET(12), 0x6b901122, 7)
                STEP(F, d, a, b, c, SET(13), 0xfd987193, 12)
                STEP(F, c, d, a, b, SET(14), 0xa679438e, 17)
                STEP(F, b, c, d, a, SET(15), 0x49b40821, 22)

/* Round 2 */
                STEP(G, a, b, c, d, GET(1), 0xf61e2562, 5)
                STEP(G, d, a, b, c, GET(6), 0xc040b340, 9)
                STEP(G, c, d, a, b, GET(11), 0x265e5a51, 14)
                STEP(G, b, c, d, a, GET(0), 0xe9b6c7aa, 20)
                STEP(G, a, b, c, d, GET(5), 0xd62f105d, 5)
                STEP(G, d, a, b, c, GET(10), 0x02441453, 9)
                STEP(G, c, d, a, b, GET(15), 0xd8a1e681, 14)
                STEP(G, b, c, d, a, GET(4), 0xe7d3fbc8, 20)
                STEP(G, a, b, c, d, GET(9), 0x21e1cde6, 5)
                STEP(G, d, a, b, c, GET(14), 0xc33707d6, 9)
                STEP(G, c, d, a, b, GET(3), 0xf4d50d87, 14)
                STEP(G, b, c, d, a, GET(8), 0x455a14ed, 20)
                STEP(G, a, b, c, d, GET(13), 0xa9e3e905, 5)
                STEP(G, d, a, b, c, GET(2), 0xfcefa3f8, 9)
                STEP(G, c, d, a, b, GET(7), 0x676f02d9, 14)
                STEP(G, b, c, d, a, GET(12), 0x8d2a4c8a, 20)

/* Round 3 */
                STEP(H, a, b, c, d, GET(5), 0xfffa3942, 4)
                STEP(H, d, a, b, c, GET(8), 0x8771f681, 11)
                STEP(H, c, d, a, b, GET(11), 0x6d9d6122, 16)
                STEP(H, b, c, d, a, GET(14), 0xfde5380c, 23)
                STEP(H, a, b, c, d, GET(1), 0xa4beea44, 4)
                STEP(H, d, a, b, c, GET(4), 0x4bdecfa9, 11)
                STEP(H, c, d, a, b, GET(7), 0xf6bb4b60, 16)
                STEP(H, b, c, d, a, GET(10), 0xbebfbc70, 23)
                STEP(H, a, b, c, d, GET(13), 0x289b7ec6, 4)
                STEP(H, d, a, b, c, GET(0), 0xeaa127fa, 11)
                STEP(H, c, d, a, b, GET(3), 0xd4ef3085, 16)
                STEP(H, b, c, d, a, GET(6), 0x04881d05, 23)
                STEP(H, a, b, c, d, GET(9), 0xd9d4d039, 4)
                STEP(H, d, a, b, c, GET(12), 0xe6db99e5, 11)
                STEP(H, c, d, a, b, GET(15), 0x1fa27cf8, 16)
                STEP(H, b, c, d, a, GET(2), 0xc4ac5665, 23)

/* Round 4 */
                STEP(I, a, b, c, d, GET(0), 0xf4292244, 6)
                STEP(I, d, a, b, c, GET(7), 0x432aff97, 10)
                STEP(I, c, d, a, b, GET(14), 0xab9423a7, 15)
                STEP(I, b, c, d, a, GET(5), 0xfc93a039, 21)
                STEP(I, a, b, c, d, GET(12), 0x655b59c3, 6)
                STEP(I, d, a, b, c, GET(3), 0x8f0ccc92, 10)
                STEP(I, c, d, a, b, GET(10), 0xffeff47d, 15)
                STEP(I, b, c, d, a, GET(1), 0x85845dd1, 21)
                STEP(I, a, b, c, d, GET(8), 0x6fa87e4f, 6)
                STEP(I, d, a, b, c, GET(15), 0xfe2ce6e0, 10)
                STEP(I, c, d, a, b, GET(6), 0xa3014314, 15)
                STEP(I, b, c, d, a, GET(13), 0x4e0811a1, 21)
                STEP(I, a, b, c, d, GET(4), 0xf7537e82, 6)
                STEP(I, d, a, b, c, GET(11), 0xbd3af235, 10)
                STEP(I, c, d, a, b, GET(2), 0x2ad7d2bb, 15)
                STEP(I, b, c, d, a, GET(9), 0xeb86d391, 21)

                a += saved_a;
                b += saved_b;
                c += saved_c;
                d += saved_d;

                ptr += 64;
        } while (size -= 64);

        ctx->a = a;
        ctx->b = b;
        ctx->c = c;
        ctx->d = d;

        return ptr;
}

static void md5_init(MD5_CTX *ctx)
{
        ctx->a = 0x67452301;
        ctx->b = 0xefcdab89;
        ctx->c = 0x98badcfe;
        ctx->d = 0x10325476;

        ctx->lo = 0;
        ctx->hi = 0;
}

static void md5_update(MD5_CTX *ctx, void *data, unsigned long size)
{
        MD5_u32plus saved_lo;
        unsigned long used, free;

        saved_lo = ctx->lo;
        if ((ctx->lo = (saved_lo + size) & 0x1fffffff) < saved_lo)
                ctx->hi++;
        ctx->hi += size >> 29;

        used = saved_lo & 0x3f;

        if (used) {
                free = 64 - used;

                if (size < free) {
                        memcpy(&ctx->buffer[used], data, size);
                        return;
                }

                memcpy(&ctx->buffer[used], data, free);
                data = (unsigned char *)data + free;
                size -= free;
                body(ctx, ctx->buffer, 64);
        }

        if (size >= 64) {
                data = body(ctx, data, size & ~(unsigned long)0x3f);
                size &= 0x3f;
        }

        memcpy(ctx->buffer, data, size);
}

static void md5_final(unsigned char *result, MD5_CTX *ctx)
{
        unsigned long used, free;

        used = ctx->lo & 0x3f;

        ctx->buffer[used++] = 0x80;

        free = 64 - used;

        if (free < 8) {
                memset(&ctx->buffer[used], 0, free);
                body(ctx, ctx->buffer, 64);
                used = 0;
                free = 64;
        }

        memset(&ctx->buffer[used], 0, free - 8);

        ctx->lo <<= 3;
        ctx->buffer[56] = ctx->lo;
        ctx->buffer[57] = ctx->lo >> 8;
        ctx->buffer[58] = ctx->lo >> 16;
        ctx->buffer[59] = ctx->lo >> 24;
        ctx->buffer[60] = ctx->hi;
        ctx->buffer[61] = ctx->hi >> 8;
        ctx->buffer[62] = ctx->hi >> 16;
        ctx->buffer[63] = ctx->hi >> 24;

        body(ctx, ctx->buffer, 64);

        result[0] = ctx->a;
        result[1] = ctx->a >> 8;
        result[2] = ctx->a >> 16;
        result[3] = ctx->a >> 24;
        result[4] = ctx->b;
        result[5] = ctx->b >> 8;
        result[6] = ctx->b >> 16;
        result[7] = ctx->b >> 24;
        result[8] = ctx->c;
        result[9] = ctx->c >> 8;
        result[10] = ctx->c >> 16;
        result[11] = ctx->c >> 24;
        result[12] = ctx->d;
        result[13] = ctx->d >> 8;
        result[14] = ctx->d >> 16;
        result[15] = ctx->d >> 24;

        memset(ctx, 0, sizeof(*ctx));
}

/* End of public domain MD5 implementation */

static void md5_update_int(MD5_CTX *ctx, int val) {
    char buf[4];
    put_int32(val, &buf[0]);
    md5_update(ctx, buf, 4);
}

#if 0
static void md5(unsigned char *d, int n, unsigned char *md)
{
    MD5_CTX ctx;

    md5_init(&ctx);
    md5_update(&ctx, d, n);
    md5_final(md, &ctx);
}
#endif
