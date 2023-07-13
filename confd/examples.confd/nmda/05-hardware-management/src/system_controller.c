/*********************************************************************
 * IETF Hardware NMDA example
 *
 * (C) 2021 Tail-f Systems
 * Permission to use this code as a starting point hereby granted
 *
 * See the README file for more information
 ********************************************************************/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>

#include <confd_lib.h>
#include <confd_cdb.h>
#include <confd_dp.h>
#include <confd_maapi.h>

#include "ietf-hardware.h"
#include "iana-hardware.h"

#define NAMESIZ 50

static int cdbsock, cdbopersock, ctlsock, workersock, subsock, maapisock;
static struct confd_daemon_ctx *dctx;
struct confd_notification_ctx *live_ctx;

struct component_id {
  struct component_id *next; /* For the linked list */
  char name[NAMESIZ];
  struct confd_identityref class;
  char parent_name[NAMESIZ];
  int parent_rel_pos;
};

static struct component_id *component_ids;

#define COMPONENT_ADD(components, component)    \
  do {                                          \
    (component)->next = *(components);          \
    *(components) = (component);                \
  } while(0)

/* Tag value print helper function */
#if 0
#define BUFF_LEN 65536
#define INDENT_SIZE 4
#define INDENT_STR ""

struct pr_doc {
  size_t alloc_len;
  int len;
  char *data;
};

static void doc_init(struct pr_doc *document)
{
  document->alloc_len = BUFF_LEN;
  document->len = 0;
  document->data = malloc(document->alloc_len);
  memset(document->data, 0x00, document->alloc_len);
}

static int doc_append(struct pr_doc *document, char *str)
{
  size_t str_len = strnlen(str, BUFF_LEN);
  size_t remaining_len = (document->alloc_len - document->len);

  if (str_len > remaining_len) {
    document->data = realloc(document->data, document->alloc_len + BUFF_LEN);
  }

  strncpy(document->data + document->len, str, str_len);
  document->len += str_len;

  return str_len;
}

/* For debug purposes - print a tag_value */
static int write_tag_value(struct pr_doc *document, confd_tag_value_t *tag_val,
                           int *indent)
{
  char *tag_str = confd_xmltag2str(tag_val->tag.ns, tag_val->tag.tag);

  char buff[BUFF_LEN+7];
  char value_buff[BUFF_LEN];

  switch (tag_val->v.type) {
    // start a container/list entry creation/modification
  case C_XMLBEGIN:
    snprintf(buff, sizeof(buff), "%*s<%s:%s>\n", *indent, INDENT_STR,
             confd_ns2prefix(CONFD_GET_TAG_NS(tag_val)), tag_str);
    *indent += INDENT_SIZE;
    break;
    // start a container/list entry creation/modification based on index
  case C_CDBBEGIN:
    snprintf(buff, sizeof(buff), "%*s<%s:%s>\n", *indent, INDENT_STR,
             confd_ns2prefix(CONFD_GET_TAG_NS(tag_val)), tag_str);
    *indent += INDENT_SIZE;
    break;
    // exit from a processing of container/list entry creation/modification
  case C_XMLEND:
    *indent -= INDENT_SIZE;
    snprintf(buff, sizeof(buff), "%*s</%s:%s>\n", *indent, INDENT_STR,
             confd_ns2prefix(CONFD_GET_TAG_NS(tag_val)), tag_str);
    break;
    // deletion of a leaf
  case C_NOEXISTS:
    snprintf(buff, sizeof(buff), "%*s<%s:%s operation=\"noexists\">\n",
             *indent, INDENT_STR, confd_ns2prefix(CONFD_GET_TAG_NS(tag_val)),
             tag_str);
    break;
    // deletion of a list entry / container
  case C_XMLBEGINDEL:
    snprintf(buff, sizeof(buff), "%*s<%s operation=\"xmlbegindel\">\n",
             *indent, INDENT_STR, tag_str);
    *indent += INDENT_SIZE;
    break;
    // type empty leaf creation
  case C_XMLTAG:
    snprintf(buff, sizeof(buff), "%*s<%s/>\n", *indent, INDENT_STR,
             tag_str);
    break;
    // regular leaf creation/modification
  default:
    confd_pp_value(value_buff, sizeof(value_buff), &tag_val->v);
    snprintf(buff, sizeof(buff), "%*s<%s:%s>%s</%s:%s>\n", *indent,
             INDENT_STR, confd_ns2prefix(CONFD_GET_TAG_NS(tag_val)), tag_str,
             value_buff, confd_ns2prefix(CONFD_GET_TAG_NS(tag_val)), tag_str);
  }

  int chars_written = doc_append(document, buff);
  return chars_written;
}

/* For debug purposes - print a tag value array */
static void print_tag_value_array(confd_tag_value_t *tvs, int tvs_cnt,
                                  void *dummy, int dummy2)
{
  struct pr_doc doc;
  doc_init(&doc);

  int indent = 0;

  int i;
  for (i = 0; i <tvs_cnt; i++) {
    write_tag_value(&doc, &tvs[i], &indent);
  }
  fprintf(stderr, "\n%s\n", doc.data);
}
#endif

static int maapi_socket(int *msock, struct sockaddr_in *addr)
{
  if ((*msock = socket(PF_INET, SOCK_STREAM, 0)) < 0 ) {
    return CONFD_ERR;
  }
  if (maapi_connect(*msock, (struct sockaddr*)addr,
                    sizeof (struct sockaddr_in)) < 0) {
    return CONFD_ERR;
  }
  return CONFD_OK;
}

static void getdatetime(struct confd_datetime *datetime)
{
  struct tm tm;
  struct timeval tv;

  gettimeofday(&tv, NULL);
  gmtime_r(&tv.tv_sec, &tm);

  memset(datetime, 0, sizeof(*datetime));
  datetime->year = 1900 + tm.tm_year;
  datetime->month = tm.tm_mon + 1;
  datetime->day = tm.tm_mday;
  datetime->sec = tm.tm_sec;
  datetime->micro = tv.tv_usec;
  datetime->timezone = 0;
  datetime->timezone_minutes = 0;
  datetime->hour = tm.tm_hour;
  datetime->min = tm.tm_min;
}

static void send_hardware_state_change(struct confd_notification_ctx **live_ctx)
{
  struct confd_datetime eventTime;
  confd_tag_value_t vals[2];
  int i = 0, ret;

  CONFD_SET_TAG_XMLBEGIN(&vals[i], hw_hardware_state_change, hw__ns);  i++;
  CONFD_SET_TAG_XMLEND(&vals[i], hw_hardware_state_change, hw__ns);  i++;
  getdatetime(&eventTime);
  if ((ret = confd_notification_send(*live_ctx, &eventTime, vals, i))
      != CONFD_OK) {
    confd_fatal("Sending HW state change notification failed");
  }
}

void *apply_trans(void *thandle) {
  int th = *((int *)thandle);
  int ret;

  if ((ret = maapi_apply_trans(maapisock, th, 0)) < 0) {
    confd_fatal("maapi_apply_trans() failed");
  }
  maapi_finish_trans(maapisock, th);
  free(thandle);
  return NULL;
}

typedef enum {MODIFY, SKIP} modification_type;

static void handle_modifications(confd_tag_value_t *val, int nvals)
{
  char *name = NULL, *parent_name = NULL, emmpty_parent_name = '\0';
  char oldname[NAMESIZ];
  struct confd_identityref class = {.ns = 0, .id = 0};
  int parent_rel_pos = -1;
  int bufsiz = NAMESIZ;
  int i, j, n, ret, pos = 0, free_parent = 0;
  int *th = malloc(sizeof(int));
  modification_type mod = SKIP;
  struct component_id *cid;
  struct confd_datetime datetime;
  //confd_value_t tokey;
  confd_tag_value_t tv[100];

  for (i = 0; i < nvals; i++) {
    switch (CONFD_GET_TAG_VALUE(&val[i])->type) {
    case C_XMLBEGIN:
      /* Check if match a system component at C_XMLEND */
      n = 1;
      pos = i;
      mod = MODIFY;
      break;
    case C_XMLBEGINDEL:
      /* Will not affect the operational state of the card */
      mod = SKIP;
      break;
    case C_XMLEND:
      if (mod == MODIFY && name != NULL) {
        if (class.ns == 0 && class.id == 0) {
          cdb_get_identityref(cdbsock, &class,
                              "/hw:hardware/hw:component{%s}/class", name);
        }
        if (parent_name == NULL) {
          if(cdb_exists(cdbsock, "/hw:hardware/hw:component{%s}/parent",
                        name)) {
            cdb_get_buf(cdbsock, (unsigned char **)&parent_name, &bufsiz,
                        "/hw:hardware/hw:component{%s}/parent", name);
            free_parent = 1;
          } else {
            parent_name = &emmpty_parent_name;
          }
        }
        if (parent_rel_pos == -1) {
          cdb_get_int32(cdbsock, &parent_rel_pos,
                        "/hw:hardware/hw:component{%s}/parent-rel-pos", name);
        }
        for(cid = component_ids; cid != NULL; cid = cid->next) {
          if(class.ns == cid->class.ns && class.id == cid->class.id
             && strcmp(parent_name, cid->parent_name) == 0
             && parent_rel_pos == cid->parent_rel_pos) {
            strncpy(&(oldname[0]), &(cid->name[0]), NAMESIZ);
            strncpy(&(cid->name[0]), name, NAMESIZ);
            break;
          }
        }
        if(cid != NULL) {
          n++;
          if ((*th = maapi_start_trans(maapisock, CONFD_OPERATIONAL,
                                       CONFD_READ_WRITE)) < 0) {
            confd_fatal("Failed to start trans\n");
          }
          if (strncmp(&(oldname[0]), name, NAMESIZ) != 0) {
            /* move list entry */
            //CONFD_SET_STR(&tokey, name);
            //maapi_move(maapisock, th, &tokey, 1,
            //             "/hw:hardware/hw:component{%s}",
            //             &(cid->name[0]));
            j = 0;
            CONFD_SET_TAG_NOEXISTS(&tv[j], hw_class); j++;
            CONFD_SET_TAG_NOEXISTS(&tv[j], hw_description); j++;
            CONFD_SET_TAG_NOEXISTS(&tv[j], hw_parent); j++;
            CONFD_SET_TAG_NOEXISTS(&tv[j], hw_parent_rel_pos); j++;
            CONFD_SET_TAG_NOEXISTS(&tv[j], hw_contains_child); j++;
            CONFD_SET_TAG_NOEXISTS(&tv[j], hw_hardware_rev); j++;
            CONFD_SET_TAG_NOEXISTS(&tv[j], hw_firmware_rev); j++;
            CONFD_SET_TAG_NOEXISTS(&tv[j], hw_software_rev); j++;
            CONFD_SET_TAG_NOEXISTS(&tv[j], hw_serial_num); j++;
            CONFD_SET_TAG_NOEXISTS(&tv[j], hw_mfg_name); j++;
            CONFD_SET_TAG_NOEXISTS(&tv[j], hw_model_name); j++;
            CONFD_SET_TAG_NOEXISTS(&tv[j], hw_alias); j++;
            CONFD_SET_TAG_NOEXISTS(&tv[j], hw_asset_id); j++;
            CONFD_SET_TAG_NOEXISTS(&tv[j], hw_is_fru); j++;
            CONFD_SET_TAG_NOEXISTS(&tv[j], hw_mfg_date); j++;
            CONFD_SET_TAG_NOEXISTS(&tv[j], hw_uri); j++;
            CONFD_SET_TAG_NOEXISTS(&tv[j], hw_uuid); j++;
            if ((ret = maapi_get_values(maapisock, *th, &tv[0], j,
                                    "/hw:hardware/hw:component{%s}",
                                    &(oldname[0]))) != CONFD_OK) {
              confd_fatal("maapi_get_values() failed");
            }
            if ((ret = maapi_set_values(maapisock, *th, &tv[0], j,
                            "/hw:hardware/hw:component{%s}", name))
                != CONFD_OK) {
              confd_fatal("maapi_set_values() failed");
            }
            for(cid = component_ids; cid != NULL; cid = cid->next) {
              if(strcmp(&(cid->parent_name[0]), &(oldname[0])) == 0) {
                strncpy(&(cid->parent_name[0]), name, NAMESIZ);
                maapi_set_elem2(maapisock, *th, name,
                             "/hw:hardware/hw:component{%s}/parent",
                                &(cid->name[0]));
              }
            }
            maapi_delete(maapisock, *th,
                         "/hw:hardware/hw:component{%s}",
                        &(oldname[0]));
          }
          //print_tag_value_array(&val[pos], n, NULL, 0);
          if ((ret = maapi_set_values(maapisock, *th, &val[pos], n,
                                      "/hw:hardware")) != CONFD_OK) {
            confd_fatal("maapi_set_values() failed");
          }
          getdatetime(&datetime);
          CONFD_SET_TAG_DATETIME(val, hw_last_change, datetime);
          if ((ret = maapi_set_values(maapisock, *th, val, 1,
                                      "/hw:hardware")) != CONFD_OK) {
            confd_fatal("maapi_set_values() failed");
          }
          pthread_t tid;
          pthread_create(&tid, NULL, apply_trans, (void *)th);
        } /* else modifications will not affect the operational state */
        mod = SKIP;
        cid = NULL;
        name = NULL;
        class.ns = 0;
        class.id = 0;
        if (free_parent == 1) {
          free(parent_name);
          free_parent = 0;
        }
        parent_name = NULL;
        parent_rel_pos = -1;
      }
      break;
    case C_XMLTAG:
      break;
    case C_NOEXISTS:
      break;
    default:
      if (mod == MODIFY) {
        n++;
        switch (CONFD_GET_TAG_TAG(&val[i])) {
        case hw_name:
          name = (char *)CONFD_GET_BUFPTR(CONFD_GET_TAG_VALUE(&val[i]));
          break;
        case hw_class:
          class = CONFD_GET_IDENTITYREF(CONFD_GET_TAG_VALUE(&val[i]));
          break;
        case hw_parent:
          parent_name = (char *)CONFD_GET_BUFPTR(
            CONFD_GET_TAG_VALUE(&val[i]));
          break;
        case hw_parent_rel_pos:
          parent_rel_pos = CONFD_GET_INT32(CONFD_GET_TAG_VALUE(&val[i]));
          break;
        default:
          break;
        }
      }
      break;
    }
  }
}

static void register_system(int sock) {
  int th, bufsiz = NAMESIZ;
  struct maapi_cursor mc;
  struct component_id *cid;
  char *parent_name, *name;

  maapi_attach_init(sock, &th);

  maapi_init_cursor(sock, th, &mc, "/hw:hardware/hw:component");
  maapi_get_next(&mc);
  while (mc.n != 0) {
    cid = (struct component_id *) malloc(sizeof(struct component_id));
    memset(cid, 0, sizeof(struct component_id));
    maapi_get_buf_elem(sock, th, (unsigned char **) &name,
                       &bufsiz, "/hw:hardware/hw:component{%x}/hw:name",
                       &mc.keys[0]);
    strncpy(&(cid->name[0]), name, NAMESIZ);
    free(name);
    maapi_get_identityref_elem(sock, th, &(cid->class),
                               "/hw:hardware/hw:component{%x}/hw:class",
                               &mc.keys[0]);
    if (maapi_exists(sock, th, "/hw:hardware/hw:component{%x}/hw:parent",
                     &mc.keys[0])) {
      maapi_get_buf_elem(sock, th, (unsigned char **) &parent_name,
                         &bufsiz, "/hw:hardware/hw:component{%x}/hw:parent",
                         &mc.keys[0]);
      strncpy(&(cid->parent_name[0]), parent_name, NAMESIZ);
      free(parent_name);
    } else {
      cid->parent_name[0] = '\0';
    }
    maapi_get_int32_elem(sock, th, &(cid->parent_rel_pos),
                         "/hw:hardware/hw:component{%x}/hw:parent-rel-pos",
                         &mc.keys[0]);
    COMPONENT_ADD(&component_ids, cid);
    maapi_get_next(&mc);
  }
  maapi_destroy_cursor(&mc);
}

void shutdown_sc() {
  fprintf(stderr, "\nshutdown system\n");
  confd_notification_flush(live_ctx);
  maapi_stop(maapisock, 1);
  exit(0);
}

int main(int argc, char **argv)
{
  struct sockaddr_in addr;
  int c, ret, spoint[2];
  struct confd_notification_stream_cbs ncb;
  int debuglevel = CONFD_TRACE;
  struct confd_ip ip;
  const char *groups[] = { "admin" };
  char *context = "system";

  while ((c = getopt(argc, argv, "dpts")) != EOF) {
    switch(c) {
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

  /* Initialize the ConfD library */
  confd_init("scc", stderr, debuglevel);

  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  addr.sin_family = AF_INET;
  addr.sin_port = htons(CONFD_PORT);

  if (confd_load_schemas((struct sockaddr*)&addr, sizeof (struct sockaddr_in))
      != CONFD_OK) {
    confd_fatal("failed to load schemas from confd\n");
  }

  /* Register the system */
  if((ret = maapi_socket(&maapisock, &addr)) != CONFD_OK) {
    confd_fatal("Failed to connect to ConfD MAAPI\n");
  }
  register_system(maapisock);

  if ((ret = maapi_start_phase(maapisock, 1, 1)) != CONFD_OK) {
    confd_fatal("Failed to go to start phase 1\n");
  }

  /* Start a maapi session */
  ip.af = AF_INET;
  inet_pton(AF_INET, "127.0.0.1", &ip.ip.v4);
  if ((maapi_start_user_session(maapisock, "admin", context,groups,
                                sizeof(groups) / sizeof(*groups),
                                &ip,
                                CONFD_PROTO_TCP) != CONFD_OK)) {
    confd_fatal("failed to start user session");
  }

  /* Start a CDB session towards the CDB running/intended datastore */
  if ((cdbsock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    confd_fatal("Failed to create the CDB socket\n");
  }
  if ((ret = cdb_connect(cdbsock, CDB_DATA_SOCKET, (struct sockaddr *)&addr,
                         sizeof(struct sockaddr_in))) != CONFD_OK) {
    confd_fatal("Failed to connect to ConfD CDB\n");
  }
  /* Only read from when the transaction lock is taken, therefore lockless */
  if ((ret = cdb_start_session2(cdbsock, CDB_RUNNING, 0)) != CONFD_OK) {
    confd_fatal("Failed to start a CDB running session\n");
  }

  /* Start a CDB session towards the CDB operational datastore */
  if ((cdbopersock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    confd_fatal("Failed to create the CDB socket\n");
  }
  if ((ret = cdb_connect(cdbopersock, CDB_DATA_SOCKET,
                         (struct sockaddr *)&addr, sizeof(struct sockaddr_in)))
      != CONFD_OK) {
    confd_fatal("Failed to connect to ConfD CDB\n");
  }
  if ((ret = cdb_start_session(cdbopersock, CDB_OPERATIONAL)) != CONFD_OK) {
    confd_fatal("Failed to start a CDB oper session\n");
  }

  /* Setting up notifications */
  if ((dctx = confd_init_daemon("mydaemon")) == NULL) {
    confd_fatal("Failed to initialize confd\n");
  }
  if ((ctlsock = socket(PF_INET, SOCK_STREAM, 0)) < 0 ) {
    confd_fatal("Failed to open ctlsocket\n");
  }
  if (confd_connect(dctx, ctlsock, CONTROL_SOCKET,
                    (struct sockaddr*)&addr, sizeof (struct sockaddr_in)) < 0) {
    confd_fatal("Failed to confd_connect() to confd \n");
  }
  if ((workersock = socket(PF_INET, SOCK_STREAM, 0)) < 0 ) {
    confd_fatal("Failed to open workersocket\n");
  }
  if ((ret = confd_connect(dctx, workersock, WORKER_SOCKET,
                           (struct sockaddr*)&addr,
                           sizeof (struct sockaddr_in))) != CONFD_OK) {
    confd_fatal("Failed to confd_connect() to ConfD \n");
  }

  memset(&ncb, 0, sizeof(ncb));
  ncb.fd = workersock;
  ncb.get_log_times = NULL;
  ncb.replay = NULL;
  strcpy(ncb.streamname, "hardware_state");
  ncb.cb_opaque = NULL;
  if (confd_register_notification_stream(dctx, &ncb, &live_ctx) != CONFD_OK) {
    confd_fatal("Couldn't register stream %s\n", ncb.streamname);
  }
  if (confd_register_done(dctx) != CONFD_OK) {
    confd_fatal("Failed to complete registration \n");
  }

  /* Setting up subscriptions */
  if ((subsock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    confd_fatal("Failed to open socket");
  }

  if (cdb_connect(subsock, CDB_SUBSCRIPTION_SOCKET, (struct sockaddr*) &addr,
                  sizeof(struct sockaddr_in)) < 0) {
    confd_fatal("Failed to cdb_connect() to confd");
  }

  if ((ret = cdb_subscribe(subsock, 3, hw__ns, &spoint[0],
                           "/hw:hardware/component")) != CONFD_OK) {
    confd_fatal("Failed to make subscription");
  }
  if ((ret = cdb_oper_subscribe(subsock, hw__ns, &spoint[1],
                                "/hw:hardware/last-change")) != CONFD_OK)
  {
    confd_fatal("Failed to make operational subscription");
  }
  if ((ret = cdb_subscribe_done(subsock)) != CONFD_OK) {
    confd_fatal("cdb_subscribe_done() failed");
  }

  while (1) {
    struct pollfd set[3];

    set[0].fd = subsock;
    set[0].events = POLLIN;
    set[0].revents = 0;

    set[1].fd = ctlsock;
    set[1].events = POLLIN;
    set[1].revents = 0;

    if (poll(&set[0], 2, -1) < 0) {
      confd_fatal("Poll failed, terminating");
    }
    if (set[0].revents & POLLIN) { /* subsock */
      int *sub_points;
      int reslen;
      enum cdb_sub_notification type;
      int flags;

      if (CONFD_OK != cdb_read_subscription_socket2(subsock, &type, &flags,
                                                    &sub_points, &reslen)) {
        confd_fatal("Failed to read subscription socket!");
      }
      if (reslen > 0) {
        if (type == CDB_SUB_OPER) {
          send_hardware_state_change(&live_ctx);
          if ((ret = cdb_sync_subscription_socket(subsock,
                                                  CDB_DONE_OPERATIONAL))
              != CONFD_OK) {
            confd_fatal("Failed to sync oper subscription socket");
          }
        } else if (type == CDB_SUB_COMMIT) {
          int i, j;
          confd_tag_value_t *tv;
          int tv_cnt;
          int flags = CDB_GET_MODS_INCLUDE_LISTS;

          for (i = 0; i < reslen; i++) {
            if ((ret = cdb_get_modifications(subsock, *sub_points, flags,
                                             &tv, &tv_cnt, "/hw:hardware"))
                != CONFD_OK) {
              confd_fatal("cdb_get_modifications() failed");
            }
            //print_tag_value_array(&tv[0], tv_cnt, NULL, 0);
            handle_modifications(&tv[0], tv_cnt);
            for (j = 0; j < tv_cnt; j++) {
              confd_free_value(CONFD_GET_TAG_VALUE(&tv[j]));
            }
            free(tv);
          }
          if ((ret = cdb_sync_subscription_socket(subsock, CDB_DONE_PRIORITY))
              != CONFD_OK) {
            confd_fatal("Failed to sync subscription socket");
          }
        }
      }
      free(sub_points);
    }
    if (set[1].revents & POLLIN) { /* ctlsock */
      if ((ret = confd_fd_ready(dctx, ctlsock)) == CONFD_EOF) {
        confd_fatal("Control socket closed\n");
      } else if (ret == CONFD_ERR &&
                 confd_errno != CONFD_ERR_EXTERNAL) {
        confd_fatal("Error on control socket request: "
                    "%s (%d): %s\n", confd_strerror(confd_errno),
                    confd_errno, confd_lasterr());
      }
    }
  }
}
