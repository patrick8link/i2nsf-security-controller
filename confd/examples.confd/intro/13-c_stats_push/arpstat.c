/*********************************************************************
 * Introduction example for pushing data to the CDB oper datastore
 *
 * (C) 2005-2018 Tail-f Systems
 * Permission to use this code as a starting point hereby granted
 * This is ConfD Sample Code.
 *
 * See the README file for more information
 ********************************************************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <signal.h>

#include <confd_lib.h>
#include <confd_dp.h>
#include <confd_maapi.h>
#include "arpe.h"

/* How often in seconds we read the ARP table into CDB */
#define INTERVAL 5
/* Max chunk of ARP objects / list entries / rows that
   we push into CDB */
#define MAX_NOBJS 100

static int navals;
static int msock, th;

/********************************************************************/
static volatile int do_run_arp = 0;

static void catch_alarm(int sig)
{
    do_run_arp++;
}

/********************************************************************/

/* parse output fom arp -an and push the output to CDB oper */
static void run_arp(int max_nobjs)
{
    char *sep = " ?()<>\n";
    FILE *fp;
    char buf[BUFSIZ];
    confd_tag_value_t *v = (confd_tag_value_t *)
                           malloc(sizeof(confd_tag_value_t) *
                                  (navals+2) *
                                  max_nobjs);
    int i = 0;
    struct in_addr ip4;
    char *hwaddr;
    char *ifname;
    int perm, pub, ret;

    if ((fp = popen("arp -an", "r")) == NULL)
        return;

    if ((th = maapi_start_trans(msock,CONFD_OPERATIONAL,
                                CONFD_READ_WRITE)) < 0) {
        confd_fatal("failed to start trans\n");
    }
    maapi_set_namespace(msock, th, arpe__ns);
    if ((ret = maapi_delete(msock, th, "arpentries/arpe")) < 0) {
        confd_fatal("maapi_delete() failed");
    }

    while (fgets(&buf[0], BUFSIZ, fp) != NULL) {
        char *cp = strtok(&buf[0], sep);
        perm = pub = 0;

        /* Now lazy parse lines like */
        /* ? (192.168.1.1) at 00:0F:B5:EF:11:00 [ether] on eth0 */
        /* slightly different arp output on Linux and BSD */
        ip4.s_addr = inet_addr(cp);
        /* skip "at" */
        assert(strcmp(strtok(NULL, sep), "at") == 0);
        cp = strtok(NULL, sep);

        if ((strcmp(cp, "incomplete") == 0)) {
            assert(strcmp(strtok(NULL, sep), "on") == 0);
            cp = strtok(NULL, sep);
        } else if ((strcmp(cp, "<from_interface>") == 0)) {
            cp = strtok(NULL, sep);
            while (cp) {
                if (strcmp(cp, "on") == 0) {
                    cp = strtok(NULL, sep);
                    break;
                }
                cp = strtok(NULL, sep);
            }
        } else {
            /* some common error cases handled, get real hw addr */
            hwaddr = strdup(cp);

            while (1) {
                cp = strtok(NULL, sep);
                if (cp == NULL)
                    break;
                else if (strcmp(cp, "PERM") == 0)
                    perm = 1;
                else if (strcmp(cp, "PUB") == 0)
                    pub = 1;
                else if (strcmp(cp, "[ether]") == 0)
                    ;
                else if (strcmp(cp, "on") == 0) {
                    cp = strtok(NULL, sep);
                    break;
                }
            }
        }

        /* cp should now point to the interface name
           - this is required since it is a key */
        if (cp) {
            CONFD_SET_TAG_XMLBEGIN(&v[i], arpe_arpe, arpe__ns); i++;
            CONFD_SET_TAG_IPV4(&v[i], arpe_ip, ip4); i++;
            ifname = strdup(cp);
            CONFD_SET_TAG_STR(&v[i], arpe_ifname, ifname); i++;
            CONFD_SET_TAG_STR(&v[i], arpe_hwaddr, hwaddr); i++;

            /* Some OSes have perm/pub after interface name */
            while ((cp = strtok(NULL, sep)) != NULL) {
                if (strcmp(cp, "permanent") == 0)
                    perm = 1;
                else if (strcmp(cp, "published") == 0)
                    pub = 1;
            }

            CONFD_SET_TAG_BOOL(&v[i], arpe_permanent, perm); i++;
            CONFD_SET_TAG_BOOL(&v[i], arpe_published, pub); i++;

            CONFD_SET_TAG_XMLEND(&v[i], arpe_arpe, arpe__ns); i++;
            if(i == max_nobjs*(navals+2)) {
                if ((ret = maapi_set_values(msock,th,v,i,
                                            "/arpentries")) < 0) {
                    confd_fatal("maapi_set_values() failed");
                }
                i = 0;
            }
        } else {
            /* skip this entry */
        }
    }
    if(i > 0) {
        if ((ret = maapi_set_values(msock,th, v, i,
                                    "/arpentries")) < 0) {
            confd_fatal("maapi_set_values() failed");
        }
    }
    if ((ret = maapi_apply_trans(msock, th, 0)) < 0) {
        confd_fatal("maapi_apply_trans() failed");
    }
    maapi_finish_trans(msock, th);
    free(v);
    pclose(fp);
}

/********************************************************************/

int main(int argc, char *argv[])
{
    struct sockaddr_in addr;
    int debuglevel = CONFD_TRACE;
    int interval = INTERVAL;
    int max_nobjs = MAX_NOBJS;
    time_t now;
    struct tm *tm;
    struct itimerval timer;
    struct confd_cs_node *object;
    int c;
    struct confd_ip ip;
    const char *groups[] = { "admin" };
    char *context = "system";

    while ((c = getopt(argc, argv, "i:x:dpts")) != EOF) {
        switch(c) {
        case 'i':
            interval = atoi(optarg);
            break;
        case 'x':
            max_nobjs = atoi(optarg);
            break;
        case 'd':
            debuglevel = CONFD_DEBUG;
            break;
        case 'p':
            debuglevel = CONFD_PROTO_TRACE;
            break;
        case 't':
            debuglevel = CONFD_TRACE;
            break;
        case 's':
            debuglevel = CONFD_SILENT;
            break;
        }
    }

    /* initialize ConfD library */
    confd_init("arpe_app", stderr, debuglevel);

    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_family = AF_INET;
    addr.sin_port = htons(CONFD_PORT);

    if (confd_load_schemas((struct sockaddr*)&addr,
                           sizeof (struct sockaddr_in)
                          ) != CONFD_OK)
        confd_fatal("failed to load schemas from confd\n");

    object = confd_cs_node_cd(NULL, "/arpe:arpentries/arpe");
    navals = confd_max_object_size(object);

    if ((msock = socket(PF_INET, SOCK_STREAM, 0)) < 0 ) {
        confd_fatal("failed to create socket\n");
    }

    if (maapi_connect(msock, (struct sockaddr*)&addr,
                      sizeof(addr)) < 0) {
        confd_fatal("failed to connect to confd\n");
    }

    ip.af = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &ip.ip.v4);

    if ((maapi_start_user_session(msock, "admin", context,groups,
                                  sizeof(groups) / sizeof(*groups),
                                  &ip,
                                  CONFD_PROTO_TCP) != CONFD_OK)) {
        confd_fatal("failed to start user session");
    }

    signal(SIGALRM, catch_alarm);

    /* start at next multiple of interval */
    now = time(NULL);
    tm = localtime(&now);
    timer.it_value.tv_sec = interval - tm->tm_sec % interval;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = interval;
    timer.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &timer, NULL);

    do_run_arp = 1;

    while(1) {
        pause();
        if (do_run_arp) {
            do_run_arp = 0;
            run_arp(max_nobjs);
        }
    }
}

/********************************************************************/
