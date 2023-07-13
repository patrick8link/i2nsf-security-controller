/*********************************************************************
 * IETF Hardware NMDA example
 *
 * (C) 2021 Tail-f Systems
 * Permission to use this code as a starting point hereby granted
 *
 * See the README file for more information
 ********************************************************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>

#include <confd_lib.h>
#include <confd_cdb.h>
#include <confd_maapi.h>
#include "ietf-hardware.h"
#include "iana-hardware.h"
#include "ietf-origin.h"

#define DEFAULT_CARD_NAME "dummycard"
#define DEFAULT_MANUFACTRURER_NAME "dummymfg"
#define DEFAULT_FIRMWARE_REV "0"
#define DEFAULT_SERIAL_NUMBER "0"
#define DEFAULT_RACK 0
#define DEFAULT_SUBRACK 0
#define DEFAULT_SLOT 0
#define DEFAULT_PORT 0
#define NAMESIZ 128
#define CONFD_IP "127.0.0.1"

static int cdbsock, subsock, maapisock;
struct sockaddr_in confd_addr;

struct component_id {
  char name[NAMESIZ];
  struct confd_identityref class;
  char parent_name[NAMESIZ];
  int parent_rel_pos;
};

static struct component_id card_id;
static struct component_id port_id;

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
             confd_ns2prefix(CONFD_GET_TAG_NS(tag_val)),
    tag_str);
    *indent += INDENT_SIZE;
    break;
    // start a container/list entry creation/modification based on index
    case C_CDBBEGIN:
    snprintf(buff, sizeof(buff), "%*s<%s:%s>\n", *indent, INDENT_STR,
             confd_ns2prefix(CONFD_GET_TAG_NS(tag_val)),
    tag_str);
    *indent += INDENT_SIZE;
    break;
    // exit from a processing of container/list entry creation/modification
    case C_XMLEND:
    *indent -= INDENT_SIZE;
    snprintf(buff, sizeof(buff), "%*s</%s:%s>\n", *indent, INDENT_STR,
             confd_ns2prefix(CONFD_GET_TAG_NS(tag_val)),
    tag_str);
    break;
    // deletion of a leaf
    case C_NOEXISTS:
    snprintf(buff, sizeof(buff), "%*s<%s:%s operation=\"noexists\">\n",
    *indent, INDENT_STR, confd_ns2prefix(CONFD_GET_TAG_NS(tag_val)), tag_str);
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
    snprintf(buff, sizeof(buff), "%*s<%s:%s>%s</%s:%s>\n", *indent, INDENT_STR,
             confd_ns2prefix(CONFD_GET_TAG_NS(tag_val)), tag_str, value_buff,
             confd_ns2prefix(CONFD_GET_TAG_NS(tag_val)), tag_str);
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

typedef enum {MODIFY, SKIP} modification_type;

static void handle_modifications(confd_tag_value_t *val, int nvals)
{
  char *name = NULL, *parent_name = NULL, emmpty_parent_name = '\0';
  struct confd_identityref class = {.ns = 0, .id = 0};
  int parent_rel_pos = -1;
  int bufsiz = NAMESIZ;
  int i, j, n, ret, found, pos = 0, free_parent = 0, th;
  modification_type mod = SKIP;
  struct confd_datetime datetime;
  char oldname[NAMESIZ];
  //confd_value_t tokey;
  confd_tag_value_t tv[100];
  confd_value_t origin;
  struct confd_identityref origin_idref = {.ns = or__ns, .id = or_intended};

  for (i = 0; i < nvals; i++) {
    switch (CONFD_GET_TAG_VALUE(&val[i])->type) {
      case C_XMLBEGIN:
        /* Check if the component match this card at C_XMLEND */
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
          found = 0;
          if (class.ns == card_id.class.ns && class.id == card_id.class.id
              && strcmp(parent_name, card_id.parent_name) == 0
              && parent_rel_pos == card_id.parent_rel_pos) {
            if(strncmp(card_id.name, name, NAMESIZ) != 0) {
              strncpy(&oldname[0], &(card_id.name[0]), NAMESIZ);
              strncpy(&(card_id.name[0]), name, NAMESIZ);
              found = 2;
            } else {
              found = 1;
            }
          } else if (class.ns == port_id.class.ns
                     && class.id == port_id.class.id
                     && strcmp(parent_name, port_id.parent_name) == 0
                     && parent_rel_pos == port_id.parent_rel_pos) {
            if(strncmp(port_id.name, name, NAMESIZ) != 0) {
              strncpy(&oldname[0], &(port_id.name[0]), NAMESIZ);
              strncpy(&(port_id.name[0]), name, NAMESIZ);
              found = 2;
            } else {
              found = 1;
            }
          } else {
            found = 0;
          }
          if (found) {
            n++;
            if ((th = maapi_start_trans(maapisock, CONFD_OPERATIONAL,
                                        CONFD_READ_WRITE)) < 0) {
                confd_fatal("Failed to start trans\n");
            }
            if (found == 2) {
              /* move list entry */
              //CONFD_SET_STR(&tokey, name);
              //maapi_move(maapisock, th, &tokey, 1,
              //           "/hw:hardware/hw:component{%s}",
              //           oldname);
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
              if ((ret = maapi_get_values(maapisock, th, &tv[0], j,
                   "/hw:hardware/hw:component{%s}", oldname))
                  != CONFD_OK) {
                confd_fatal("maapi_get_values() failed");
              }
              if ((ret = maapi_set_values(maapisock, th, &tv[0], j,
                                   "/hw:hardware/hw:component{%s}",
                                   name)) != CONFD_OK) {
                confd_fatal("maapi_set_values() failed");
              }
              if(strcmp(&(port_id.parent_name[0]), &(oldname[0])) == 0) {
                strncpy(&(port_id.parent_name[0]), name, NAMESIZ);
                maapi_set_elem2(maapisock, th, name,
                  "/hw:hardware/hw:component{%s}/parent",
                &(port_id.name[0]));
              }
              maapi_delete(maapisock, th,
                           "/hw:hardware/hw:component{%s}",
                           oldname);
            }
            if ((ret = maapi_set_values(maapisock, th, &val[pos], n,
                                        "/hw:hardware")) != CONFD_OK) {
              confd_fatal("maapi_set_values() failed");
            }
            /* Set origin */
            CONFD_SET_IDENTITYREF(&origin, origin_idref);
            maapi_set_attr(maapisock, th, CONFD_ATTR_ORIGIN, &origin,
              "/hw:hardware/hw:component{%s}", name);
            /* Set hardware last change time */
            getdatetime(&datetime);
            CONFD_SET_TAG_DATETIME(val, hw_last_change, datetime);
            if ((ret = maapi_set_values(maapisock, th, val, 1,
                                        "/hw:hardware")) != CONFD_OK) {
              confd_fatal("maapi_set_values() failed");
            }
            if ((ret = maapi_apply_trans(maapisock, th, 0)) < 0) {
                confd_fatal("maapi_apply_trans() failed");
            }
            maapi_finish_trans(maapisock, th);
          } /* else modifications will not affect the operational state of the
               card */
          mod = SKIP;
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
              parent_name =
                         (char *)CONFD_GET_BUFPTR(CONFD_GET_TAG_VALUE(&val[i]));
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

static void register_card(char *card_name, char *firmware_rev,
                          char *serial_number, char *mfg_name, char *slot_name,
                          char *port_name, int port, int slot_rel_pos,
                          int card_rel_pos)
{
  int i = 0, ret, th;
  struct confd_datetime datetime;
  confd_value_t component_list[1];
  confd_tag_value_t tv[100];
  struct confd_identityref state_class = { .ns = ianahw__ns,
                                           .id = ianahw_module };
  confd_value_t origin;
  struct confd_identityref origin_idref = {.ns = or__ns, .id = or_system};

  /* Register with slot */
  CONFD_SET_TAG_XMLBEGIN(&tv[i], hw_component, hw__ns); i++;
  CONFD_SET_TAG_STR(&tv[i], hw_name, slot_name); i++;
  CONFD_SET_STR(&component_list[0], card_name);
  CONFD_SET_TAG_XMLEND(&tv[i], hw_component, hw__ns); i++;

  /* Register card */
  CONFD_SET_TAG_XMLBEGIN(&tv[i], hw_component, hw__ns); i++;
  CONFD_SET_TAG_STR(&tv[i], hw_name, card_name); i++;
  strncpy(&(card_id.name[0]), card_name, sizeof(card_id.name));
  CONFD_SET_TAG_IDENTITYREF(&tv[i], hw_class, state_class); i++;
  memcpy(&(card_id.class), &state_class, sizeof(struct confd_identityref));
  CONFD_SET_TAG_STR(&tv[i], hw_parent, slot_name); i++;
  strncpy(&(card_id.parent_name[0]), slot_name, sizeof(card_id.parent_name));
  CONFD_SET_TAG_INT32(&tv[i], hw_parent_rel_pos, slot_rel_pos); i++;
  card_id.parent_rel_pos = slot_rel_pos;
  if (port > -1) {
    CONFD_SET_STR(&component_list[0], port_name);
  }
  CONFD_SET_TAG_STR(&tv[i], hw_firmware_rev, firmware_rev); i++;
  CONFD_SET_TAG_STR(&tv[i], hw_serial_num, serial_number); i++;
  CONFD_SET_TAG_STR(&tv[i], hw_mfg_name, mfg_name); i++;

  CONFD_SET_TAG_XMLEND(&tv[i], hw_component, hw__ns); i++;

  if (port > -1) {
    /* Register port */
    CONFD_SET_TAG_XMLBEGIN(&tv[i], hw_component, hw__ns); i++;
    CONFD_SET_TAG_STR(&tv[i], hw_name, port_name); i++;
    strncpy(&(port_id.name[0]), port_name, sizeof(port_id.name));
    state_class.id = ianahw_port;
    CONFD_SET_TAG_IDENTITYREF(&tv[i], hw_class, state_class); i++;
    memcpy(&(port_id.class), &state_class, sizeof(struct confd_identityref));
    CONFD_SET_TAG_STR(&tv[i], hw_parent, card_name); i++;
    strncpy(&(port_id.parent_name[0]), card_name, sizeof(port_id.parent_name));
    CONFD_SET_TAG_INT32(&tv[i], hw_parent_rel_pos, card_rel_pos); i++;
    port_id.parent_rel_pos = card_rel_pos;
    CONFD_SET_TAG_STR(&tv[i], hw_mfg_name, mfg_name); i++;
    CONFD_SET_TAG_XMLEND(&tv[i], hw_component, hw__ns); i++;
  }

  if ((th = maapi_start_trans(maapisock, CONFD_OPERATIONAL,
                              CONFD_READ_WRITE)) < 0) {
      confd_fatal("Failed to start trans\n");
  }
  if ((ret = maapi_set_values(maapisock, th, tv, i, "/hw:hardware"))
      != CONFD_OK) {
    confd_fatal("maapi_set_values() failed");
  }

  /* Set origin to "system" */
  CONFD_SET_IDENTITYREF(&origin, origin_idref);
  maapi_set_attr(maapisock, th, CONFD_ATTR_ORIGIN, &origin,
    "/hw:hardware/hw:component{%s}", card_name);
  maapi_set_attr(maapisock, th, CONFD_ATTR_ORIGIN, &origin,
    "/hw:hardware/hw:component{%s}", port_name);

  /* Set hardware last change time */
  i = 0;
  getdatetime(&datetime);
  CONFD_SET_TAG_DATETIME(&tv[i], hw_last_change, datetime); i++;
  if ((ret = maapi_set_values(maapisock, th, tv, i, "/hw:hardware"))
      != CONFD_OK) {
    confd_fatal("maapi_set_values() failed");
  }
  if ((ret = maapi_apply_trans(maapisock, th, 0)) < 0) {
    confd_fatal("maapi_apply_trans() failed");
  }
  maapi_finish_trans(maapisock, th);
}

void shutdown_card()
{
  struct confd_datetime datetime;
  confd_tag_value_t tv;
  int ret, th;

  fprintf(stderr, "\nshutdown card\n");
  if ((th = maapi_start_trans(maapisock, CONFD_OPERATIONAL,
                              CONFD_READ_WRITE)) < 0) {
      confd_fatal("Failed to start trans\n");
  }
  maapi_delete(maapisock, th, "/hw:hardware/hw:component{%s}",
             port_id.name);
  maapi_delete(maapisock, th, "/hw:hardware/hw:component{%s}",
             card_id.name);
  getdatetime(&datetime);
  CONFD_SET_TAG_DATETIME(&tv, hw_last_change, datetime);
  if ((ret = maapi_set_values(maapisock, th, &tv, 1, "/hw:hardware"))
      != CONFD_OK) {
    confd_fatal("cdb_set_values() failed");
  }
  if ((ret = maapi_apply_trans(maapisock, th, 0)) < 0) {
    confd_fatal("maapi_apply_trans() failed");
  }
  maapi_finish_trans(maapisock, th);
  exit(0);
}

void *trigger_subscription(void *sub_points)
{
  int sock, ret;
  if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    confd_fatal("Failed to create the CDB socket\n");
  }
  if (cdb_connect(sock, CDB_DATA_SOCKET, (struct sockaddr *)&confd_addr,
                         sizeof(struct sockaddr_in)) != CONFD_OK) {
    confd_fatal("Failed to connect to ConfD CDB\n");
  }
  /* Must take a lock to avoid that the synthetic trigger of the subscriber
     conflict with an ongoing transaction */
  while ((ret = maapi_lock(maapisock, CONFD_RUNNING)) == CONFD_ERR) {
   sleep(1);
  }
  if (cdb_trigger_subscriptions(sock, (int *)sub_points, 1)
      != CONFD_OK) {
    confd_fatal("cdb_trigger_subscriptions() failed");
  }
  maapi_unlock(maapisock, CONFD_RUNNING);
  close(sock);
  return NULL;
}

int main(int argc, char *argv[])
{
  int debuglevel = CONFD_TRACE;
  char card_name[NAMESIZ];
  char mfg_name[NAMESIZ];
  char firmware_rev[NAMESIZ];
  char serial_number[NAMESIZ];
  int rack = DEFAULT_RACK;
  int subrack = DEFAULT_SUBRACK;
  int slot = DEFAULT_SLOT;
  int port = DEFAULT_PORT;
  char port_name[NAMESIZ+20];
  char slot_name[NAMESIZ];
  int slot_rel_pos, card_rel_pos;
  int c, ret;
  int sub_points[1];
  int start = 0;
  struct confd_ip ip;
  const char *groups[] = { "admin" };
  char *context = "system";
  pthread_t tid;

  snprintf(&card_name[0], sizeof(card_name), DEFAULT_CARD_NAME);
  snprintf(&mfg_name[0], sizeof(mfg_name), DEFAULT_MANUFACTRURER_NAME);
  snprintf(&firmware_rev[0], sizeof(firmware_rev), DEFAULT_FIRMWARE_REV);
  snprintf(&serial_number[0], sizeof(serial_number), DEFAULT_SERIAL_NUMBER);

  while ((c = getopt(argc, argv, "c:a:n:m:r:u:l:o:idpts")) != EOF) {
    switch(c) {
      case 'c':
      strncpy(&card_name[0], optarg, sizeof(card_name));
      break;
      case 'a':
      strncpy(&firmware_rev[0], optarg, sizeof(firmware_rev));
      break;
      case 'n':
      strncpy(&serial_number[0], optarg, sizeof(serial_number));
      break;
      case 'm':
      strncpy(&mfg_name[0], optarg, sizeof(mfg_name));
      case 'r':
      rack = atoi(optarg);
      break;
      case 'u':
      subrack = atoi(optarg);
      break;
      case 'l':
      slot = atoi(optarg);
      break;
      case 'o':
      port = atoi(optarg);
      break;
      case 'i':
      start = 1;
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

  /* Initialize the ConfD library */
  confd_init(&card_name[0], stderr, debuglevel);

  confd_addr.sin_addr.s_addr = inet_addr(CONFD_IP);
  confd_addr.sin_family = AF_INET;
  confd_addr.sin_port = htons(CONFD_PORT);

  if (confd_load_schemas((struct sockaddr*)&confd_addr,
                          sizeof (struct sockaddr_in))
      != CONFD_OK) {
    confd_fatal("failed to load schemas from confd\n");
  }

  /* Start a CDB session towards the CDB running/intended datastore */
  if ((cdbsock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    confd_fatal("Failed to create the CDB socket\n");
  }
  if ((ret = cdb_connect(cdbsock, CDB_DATA_SOCKET,
                         (struct sockaddr *)&confd_addr,
                         sizeof(struct sockaddr_in))) != CONFD_OK) {
    confd_fatal("Failed to connect to ConfD CDB\n");
  }

  /* Only read from CDB running when the transaction lock is taken from here
     on, therefore lockless */
  if ((ret = cdb_start_session2(cdbsock, CDB_RUNNING, 0)) != CONFD_OK) {
    confd_fatal("Failed to start a CDB running session\n");
  }

  /* Start a subscriber listening to card components running config changes */
  if ((subsock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    confd_fatal("Failed to open socket\n");
  }
  if (cdb_connect(subsock, CDB_SUBSCRIPTION_SOCKET,
                  (struct sockaddr*) &confd_addr,
                  sizeof(struct sockaddr_in)) < 0) {
    confd_fatal("Failed to connect to ConfD CDB\n");
  }
  if ((ret = cdb_subscribe(subsock, 3, hw__ns, &sub_points[0],
                           "/hw:hardware/hw:component")) != CONFD_OK)  {
    confd_fatal("Failed to subscribe\n");
  }
  if ((ret = cdb_subscribe_done(subsock)) != CONFD_OK) {
    confd_fatal("cdb_subscribe_done() failed\n");
  }
  if((ret = maapi_socket(&maapisock, &confd_addr)) != CONFD_OK) {
    confd_fatal("Failed to connect to ConfD MAAPI\n");
  }

  /* Start a maapi session */
  ip.af = AF_INET;
  inet_pton(AF_INET, CONFD_IP, &ip.ip.v4);
  if ((maapi_start_user_session(maapisock, "admin", context,groups,
                                sizeof(groups) / sizeof(*groups),
                                &ip,
                                CONFD_PROTO_TCP) != CONFD_OK)) {
      confd_fatal("failed to start user session");
  }

  snprintf(&slot_name[0], sizeof(slot_name), "slot-%d-%d-%d", rack, subrack,
           slot);
  snprintf(&port_name[0], sizeof(port_name), "%s-port-%d", card_name, port);
  slot_rel_pos = 1000000 * rack + 10000 * subrack + 100 * slot;
  card_rel_pos = 1000000 * rack + 10000 * subrack + 100 * slot + port;

  /* Register card with the operational state */
  register_card(&card_name[0], firmware_rev, serial_number, &mfg_name[0],
                &slot_name[0], &port_name[0], port, slot_rel_pos, card_rel_pos);

  if (start) {
    if ((ret = maapi_start_phase(maapisock, 2, 1)) != CONFD_OK) {
      confd_fatal("Failed to go to start phase 2\n");
    }
  } else {
    /* Trigger the card config change subscriber to initialize the operational
       state with the current intended configuration */
    pthread_create(&tid, NULL, trigger_subscription, (void *)&sub_points[0]);
  }

  while (1) {
    int status;
    struct pollfd set[2];

    set[0].fd = subsock;
    set[0].events = POLLIN;
    set[0].revents = 0;

    if (poll(&set[0], 1, -1) < 0) {
      confd_fatal("Poll failed, terminating");
    }
    if (set[0].revents & POLLIN) {
      int reslen;
      if ((status = cdb_read_subscription_socket(subsock, &sub_points[0],
                                                 &reslen)) != CONFD_OK) {
        confd_fatal("terminate sub_read: %d\n", status);
      }
      if (reslen > 0) {
        int i, j;
        confd_tag_value_t *tv;
        int tv_cnt;
        int flags = CDB_GET_MODS_INCLUDE_LISTS;

        for (i = 0; i < reslen; i++) {
          if ((ret = cdb_get_modifications(subsock, sub_points[0], flags, &tv,
                                           &tv_cnt, "/hw:hardware"))
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
        if ((status = cdb_sync_subscription_socket(subsock, CDB_DONE_PRIORITY))
            != CONFD_OK) {
          confd_fatal("failed to sync subscription: %d\n", status);
        }
      }
    }
  }
}
