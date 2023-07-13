/*
 * Copyright 2005-2011 Tail-F Systems AB
 */

#ifndef _CONFD_HA_H
#define _CONFD_HA_H 1

#ifdef __cplusplus
extern "C" {
#endif

/* a node can be in either of four states */
enum confd_ha_status_state {
    CONFD_HA_STATE_NONE = 1,
    CONFD_HA_STATE_SECONDARY = 2,
    CONFD_HA_STATE_PRIMARY = 3,
    CONFD_HA_STATE_SECONDARY_RELAY = 4,

    /* backward compatibility, will be removed */
    CONFD_HA_STATE_SLAVE = 2,
    CONFD_HA_STATE_MASTER = 3,
    CONFD_HA_STATE_SLAVE_RELAY = 4
};

struct confd_ha_status {
    enum confd_ha_status_state state;
    /* if state is PRIMARY, we also have a list of secondaries */
    /* if state is SECONDARY, then nodes[0] contains the primary */
    /* if state is RELAY_SECONDARY, then nodes[0] contains the primary,
       and following entries contain the "sub-secondaries" */
    /* if state is NONE, we have no nodes at all */
    struct confd_ha_node nodes[255];
    int num_nodes;
};

extern int confd_ha_connect(int sock, const struct sockaddr* srv,
                            int srv_sz, const char *token);

extern int confd_ha_beprimary(int sock, confd_value_t *mynodeid);

extern int confd_ha_besecondary(int sock, confd_value_t *mynodeid,
                                struct confd_ha_node *primary, int waitreply);

extern int confd_ha_berelay(int sock);

extern int confd_ha_benone(int sock);

extern int confd_ha_get_status(int sock, struct confd_ha_status *stat);

extern int confd_ha_secondary_dead(int sock, confd_value_t *nodeid);

/* backward compatibility */
#define confd_ha_status(sock, stat) confd_ha_get_status((sock), (stat))
#define confd_ha_bemaster(sock, mynodeid) confd_ha_beprimary((sock), (mynodeid))
#define confd_ha_beslave(sock, mynodeid, master, waitreply) \
  confd_ha_besecondary((sock), (mynodeid), (master), (waitreply))
#define confd_ha_slave_dead(sock, nodeid) \
  confd_ha_secondary_dead((sock), (nodeid))

#ifdef __cplusplus
}
#endif
#endif
