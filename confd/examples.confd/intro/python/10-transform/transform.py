""" ConfD example - intro / transformation

    (C) 2018 Tail-f Systems
    Permission to use this code as a starting point hereby granted.
    This is ConfD Sample Code.

    See the README file for more information.
"""
import select
import socket
import sys
import traceback

import _confd
import confd
import _confd.dp as dp
import _confd.maapi as maapi

from user_folders_ns import ns as ns_folders
from user_storage_ns import ns as ns_storage

debug_level = confd.DEBUG
daemon_name = "transform"

dest_ip = '127.0.0.1'
dest_port = confd.CONFD_PORT

maapi_socket = None

# string separator used when creating/parsing the low level storage-id
STORAGE_ID_SEPARATOR = '||'

# keypath prefixes defined by the managed low-level YANG model
ROOT_PATH = '/'
USER_PATH = '/user-storage/user'
STORAGE_PATH = '/user-storage/storage'
OWNER_PATH = '/user-storage/ownership'


# set of procedures to build low level keypath strings
def kp_user(v_user_id):
    return USER_PATH + '{' + str(v_user_id) + '}'


def kp_storage(v_storage_id):
    return STORAGE_PATH + '{' + str(v_storage_id) + '}'


def kp_ownership(v_user_id, v_storage_id):
    return OWNER_PATH + '{' + str(v_user_id) + ' ' + str(v_storage_id) + '}'


def kp_auth_type(v_user_id):
    return kp_user(v_user_id) + '/auth-info/auth-type'


def kp_content_type(v_user_id, v_folder_id):
    v_storage_id = concat_storage_id_value(v_user_id, v_folder_id)
    return kp_ownership(v_user_id, v_storage_id) + '/content-type'


def kp_auth_password(v_user_id):
    return kp_user(v_user_id) + '/auth-info/password'


def kp_auth_key(v_user_id):
    return kp_user(v_user_id) + '/auth-info/key'


def parse_folder_id_value(v_storage_id):
    """ Extract high level value to be used as:
            "/folder-user{}/managed-folder{}/folder-id"
        from the input low level:
            "/user-storage/storage{}/storage-id"

        Example:
            storage-id == "123||home-dif" --> folder-id == "home-dir"
    """
    folder_id = str(v_storage_id).split(STORAGE_ID_SEPARATOR)[1]
    return confd.Value(folder_id, confd.C_BUF)


# Low level storage id is a concatenation of user-id + folder-id;
# This allows two different users to have a storage with same name.
def concat_storage_id_value(v_user_id, v_folder_id):
    """ Retrieve the key value of "/user-storage/storage{}" record
        that corresponds to a specific user's managed-folder.
    """
    storage_id = str(v_user_id) + STORAGE_ID_SEPARATOR + str(v_folder_id)
    return confd.Value(storage_id, confd.C_BUF)


def is_users_storage(v_user_id, v_storage_id):
    """ Check whether storage-id has a text pattern
        enforced by our transformation.
    """
    str_to_match = str(v_user_id) + STORAGE_ID_SEPARATOR
    return str_to_match in str(v_storage_id)


def optional_get_elem(sock, thandle, path):
    """ Wrapper for the maapi.get_elem() call.
        Returns 'None' if leaf does not exist.
        (instead of throwing an exception)
    """
    try:
        return maapi.get_elem(sock, thandle, path)
    except _confd.error.Error as ex:
        if ex.confd_errno == confd.ERR_NOEXISTS:
            return None
        raise

# list of high level enums
ct_enums_list = [
    ns_folders.folders_media,
    ns_folders.folders_document,
    ns_folders.folders_archive
]

# list of low level bits level
ct_bits_list = [ns_storage.storage__bm_content_type_media,
                ns_storage.storage__bm_content_type_document,
                ns_storage.storage__bm_content_type_archive]

# transformation mapping for "content-type":
#   - bit-mask in low-level YANG
#   - leaf-list of enums in high-level YANG
ct_enum_to_bits = dict(zip(ct_enums_list, ct_bits_list))

# and it's reverse mapping
ct_bits_to_enum = dict(zip(ct_bits_list, ct_enums_list))

# transformation mapping for "auth-type":
#   - enum in low level
#   - tag name in high level (case statement)
at_enum_to_tags = {
    ns_storage.storage_at_none: ns_folders.folders_none,
    ns_storage.storage_at_key: ns_folders.folders_key,
    ns_storage.storage_at_password: ns_folders.folders_password,
}
# and it's reverse mapping
at_tags_to_enum = {v: k for k, v in at_enum_to_tags.items()}


class TransactionCallbackImpl(object):
    """ Callback for handling the ConfD transformation transactions.
    """

    def __init__(self, worker_socket):
        self._worker_socket = worker_socket

    def cb_init(self, tctx):
        maapi.attach(maapi_socket, ns_storage.hash, tctx)
        dp.trans_set_fd(tctx, self._worker_socket)
        return confd.CONFD_OK

    def cb_finish(self, tctx):
        maapi.detach(maapi_socket, tctx)
        return confd.CONFD_OK


class TransformDataHelper(object):
    """ Helper class to group operations on transaction handle
        to be executed by transformation callbacks.
    """

    def __init__(self, thandle):
        self.th = thandle

    def get_user_id_value(self, v_username):
        """ Retrieve value of "/user-storage/user{}/user-id" that has
            the specific unique username set as a non-key element.
        """
        found_names = []

        def user_id_iter(kp, value):
            found_names.append(value)
            # due to target YANG model, only one value can exist
            # (unique "username"; in YANG model)
            return confd.ITER_STOP

        xpath_expr = '{0}[username="{1}"]/user-id'.format(USER_PATH,
                                                          v_username)
        maapi.xpath_eval(sock=maapi_socket,
                         thandle=self.th,
                         expr=xpath_expr,
                         result=user_id_iter,
                         path=ROOT_PATH,
                         trace=None)

        return found_names[0] if found_names else None

    def get_auth_type_value(self, v_user_id):
        """ Retrieve user's authentication type from low level YANG.
        """
        return optional_get_elem(maapi_socket, self.th,
                                 kp_auth_type(v_user_id))

    def set_auth_type(self, v_user_id, tag):
        """ Set user's low level authentication type to a specific value.
        """
        val = confd.Value(tag, confd.C_ENUM_VALUE)
        maapi.set_elem(maapi_socket, self.th, val, kp_auth_type(v_user_id))


class TransformCallbackImpl(object):
    """ Implementation of the transformation itself.
    """

    def __init__(self):
        # state tracking for get_next() calls
        self.get_next_cursors = {}

    def cb_exists_optional(self, tctx, kp):
        helper = TransformDataHelper(tctx.th)

        def _check_leaf_exists(keypath):
            """ Implements existence check for high level leaves.
            """
            leaf_tag = keypath[0].tag
            if ns_folders.folders_auth_none == leaf_tag:
                # /folder-user{bob}/auth-none
                v_user_id = helper.get_user_id_value(keypath[1][0])
                v_auth_type = helper.get_auth_type_value(v_user_id)
                return ns_storage.storage_at_none == v_auth_type
            else:
                raise NotImplementedError

        def _check_entry_exists(keypath):
            """ Implements existence check for high level leaf-list entries.
            """
            list_tag = keypath[1].tag

            if ns_folders.folders_content_type == list_tag:
                # /folder-user{bob}/managed-folder{home}content-type{archive}
                v_user_id = helper.get_user_id_value(keypath[-2][0])
                v_bits_set = optional_get_elem(maapi_socket, helper.th,
                                               kp_content_type(v_user_id,
                                                               keypath[-4][0])
                                               )
                if v_bits_set is not None:
                    bits_set = int(v_bits_set)
                    bit_to_check = ct_enum_to_bits[int(keypath[0][0])]
                    return bool(bits_set & bit_to_check)
                return False
            else:
                raise NotImplementedError

        query_exists = (_check_leaf_exists(kp) if isinstance(kp[0],
                                                             confd.XmlTag)
                        else _check_entry_exists(kp))

        (dp.data_reply_found(tctx) if query_exists
         else dp.data_reply_not_found(tctx))
        return confd.CONFD_OK

    def cb_get_case(self, tctx, kp, choice):
        helper = TransformDataHelper(tctx.th)

        v_user_id = helper.get_user_id_value(kp[-2][0])
        if v_user_id is None:
            dp.data_reply_not_found(tctx)
            return confd.CONFD_OK

        v_auth_type = helper.get_auth_type_value(v_user_id)
        tag = at_enum_to_tags[int(v_auth_type)]
        dp.data_reply_value(tctx,
                            confd.Value((tag, ns_folders.hash),
                                        confd.C_XMLTAG)
                            )
        return confd.CONFD_OK

    def cb_get_elem(self, tctx, kp):
        helper = TransformDataHelper(tctx.th)

        v_result = None

        v_username = kp[-2][0]
        v_user_id = helper.get_user_id_value(v_username)

        list_tag = kp[2].tag

        if ns_folders.folders_managed_folder == list_tag:
            v_folder_id = kp[1][0]
            v_storage_id = concat_storage_id_value(v_user_id, v_folder_id)
        else:
            v_folder_id = None
            v_storage_id = None

        leaf_tag = kp[0].tag

        if ns_folders.folders_username == leaf_tag:

            # user with specific username actually does exists - as we got
            # his user_id in the previous step via storage-id retrieval
            if v_user_id is not None:
                v_result = v_username

        elif ns_folders.folders_auth_password == leaf_tag:

            v_auth_type = helper.get_auth_type_value(v_user_id)
            if ns_storage.storage_at_password == v_auth_type:
                v_result = optional_get_elem(maapi_socket, helper.th,
                                             kp_auth_password(v_user_id))

        elif ns_folders.folders_auth_key == leaf_tag:

            v_auth_type = helper.get_auth_type_value(v_user_id)
            if ns_storage.storage_at_key == v_auth_type:
                v_result = optional_get_elem(maapi_socket, helper.th,
                                             kp_auth_key(v_user_id))

        elif ns_folders.folders_folder_id == leaf_tag:

            if (v_storage_id is not None and
                    maapi.exists(maapi_socket, helper.th,
                                 kp_storage(v_storage_id))):
                # existence verified in low level, return value from keypath
                # - it saves the need to extract storage-id substring again...
                v_result = v_folder_id

        else:
            raise NotImplementedError

        (dp.data_reply_value(tctx, v_result) if v_result is not None
         else dp.data_reply_not_found(tctx))
        return confd.CONFD_OK

    def cb_get_next(self, tctx, kp, next):
        helper = TransformDataHelper(tctx.th)

        def _get_next_folder(keypath, next_counter, folder_cursor):
            """ Retrieve next "/folder-user{}/managed-folder{}" record that
                belongs to the user from the "/user-storage/ownership{}".
            """
            v_username = keypath[-2][0]
            v_user_id = helper.get_user_id_value(v_username)

            if -1 == next_counter:
                keys = maapi.find_next(mc=folder_cursor, type=confd.FIND_NEXT,
                                       inkeys=[v_user_id])
            else:
                keys = maapi.get_next(folder_cursor)

            if keys:
                # second key of the "ownership" list is our storage name
                v_storage_id = keys[1]
                if is_users_storage(v_user_id, v_storage_id):
                    return parse_folder_id_value(v_storage_id)

            return None

        def _get_next_user(user_cursor):
            """ Retrieve next "/folder-user{}" from the "/user-storage/user".
            """
            keys = maapi.get_next(user_cursor)
            if keys:
                v_username = maapi.get_elem(maapi_socket, helper.th,
                                            kp_user(keys[0]) + '/username')
                return v_username
            return None

        def _get_list_cursor(tctx, next_counter, path, cursors):
            """ Return MAAPI cursor for iterating the YANG list
                depending on the "next" value and request keypath.
                CDB path string is used as cursor identifier to simplify API.
            """
            key = (tctx.traversal_id, path)
            if -1 == next_counter:
                if key in cursors:
                    maapi.destroy_cursor(cursors[key])
                cursors[key] = maapi.init_cursor(maapi_socket, helper.th, path)
            else:
                if key not in cursors:
                    raise ValueError("Jumping into uninitialized iteration!")
            return cursors[key]

        def _del_list_cursor(tctx, path, cursors):
            key = (tctx.traversal_id, path)
            if key in cursors:
                maapi.destroy_cursor(cursors[key])
                del cursors[key]

        def _get_next_content_type(keypath, next_counter):
            """ Return next content-type value from the low level bit-field
                "/user-storage/ownership{}/content-type".
            """
            v_user_id = helper.get_user_id_value(keypath[-2][0])
            if v_user_id is None:
                return None
            v_bitmask = optional_get_elem(maapi_socket, helper.th,
                                          kp_content_type(v_user_id,
                                                          keypath[1][0]))
            if v_bitmask is None:
                return None
            bitmask_int = int(v_bitmask)
            # get all the bits that are set in the low level value
            bits_set = [bit for bit in ct_bits_list if
                        bool(bitmask_int & bit)]
            # return N-th bit from the set depending on the "next"
            if next_counter + 1 < len(bits_set):
                mapping_index = bits_set[next_counter + 1]
                return confd.Value(ct_bits_to_enum[mapping_index],
                                   confd.C_ENUM_VALUE)
            else:
                return None

        list_tag = kp[0].tag

        # our transformed model has only one key in any of the lists,
        # thus no array here, only 1 item as a "next_key"
        if ns_folders.folders_folder_user == list_tag:
            cursor = _get_list_cursor(tctx, next, USER_PATH,
                                      self.get_next_cursors)
            next_key = _get_next_user(cursor)
        elif ns_folders.folders_managed_folder == list_tag:
            cursor = _get_list_cursor(tctx, next, OWNER_PATH,
                                      self.get_next_cursors)
            next_key = _get_next_folder(kp, next, cursor)
        elif ns_folders.folders_content_type == list_tag:
            next_key = _get_next_content_type(kp, next)
        else:
            raise NotImplementedError

        if next_key is None:
            if ns_folders.folders_folder_user == list_tag:
                _del_list_cursor(tctx, USER_PATH, self.get_next_cursors)
            elif ns_folders.folders_managed_folder == list_tag:
                _del_list_cursor(tctx, OWNER_PATH, self.get_next_cursors)

            dp.data_reply_next_key(tctx, keys=None, next=-1)
        else:
            dp.data_reply_next_key(tctx, keys=[next_key], next=next + 1)
        return confd.CONFD_OK

    def cb_set_elem(self, tctx, kp, newval):
        helper = TransformDataHelper(tctx.th)

        v_user_id = helper.get_user_id_value(kp[-2][0])

        leaf_tag = kp[0].tag
        if ns_folders.folders_auth_key == leaf_tag:
            helper.set_auth_type(v_user_id, ns_storage.storage_at_key)
            maapi.set_elem(maapi_socket, helper.th, newval,
                           kp_auth_key(v_user_id))
        elif ns_folders.folders_auth_password == leaf_tag:
            helper.set_auth_type(v_user_id, ns_storage.storage_at_password)
            maapi.set_elem(maapi_socket, helper.th, newval,
                           kp_auth_password(v_user_id))
        else:
            raise NotImplementedError
        return confd.CONFD_OK

    def cb_create(self, tctx, kp):
        helper = TransformDataHelper(tctx.th)

        def _create_type_empty(keypath):
            """ Handles the creation of a "/folder-user{}/auth-none".
            """
            leaf_tag = keypath[0].tag
            if ns_folders.folders_auth_none == leaf_tag:
                user_id_v = helper.get_user_id_value(keypath[1][0])
                helper.set_auth_type(user_id_v, ns_storage.storage_at_none)
            else:
                raise NotImplementedError

        def _create_folder_user(v_username):
            """ Handles steps needed for the creation of "/folder-user{}".
            """
            # integer is used as initial "user-id" to be assigned to any newly
            # created users; every new user will get the last used user-id +1;
            # see further/usage of macro for details;
            # each new creation can become "slow" due to reading all the ids;
            # for non-example case, this must be done in an efficient!
            init_user_id = 100

            def _get_unused_user_id():
                """ Return "free" (hopefully) user-id that can be used for
                    new user in the "user-storage.yang" configuration.
                """
                cursor = maapi.init_cursor(maapi_socket, helper.th, USER_PATH)
                keys = maapi.get_next(cursor)

                last_user_id = init_user_id
                while keys:
                    last_user_id = int(keys[0])
                    keys = maapi.get_next(cursor)
                maapi.destroy_cursor(cursor)
                return last_user_id + 1

            new_user_id = _get_unused_user_id()
            # new table record in /user-storage/user{}
            maapi.create(maapi_socket, helper.th, kp_user(new_user_id))
            # and username in "/user-storage/user{}/username"
            maapi.set_elem(maapi_socket, helper.th, v_username,
                           kp_user(new_user_id) + '/username')
            return confd.CONFD_OK

        def _create_managed_folder(user_id_v, folder_id_v):
            """ Handle all steps needed for creation of
                "/folder-user{}/managed-folder{}" record.
            """
            v_storage_id = concat_storage_id_value(user_id_v, folder_id_v)

            paths_to_create = [kp_storage(v_storage_id),
                               kp_ownership(user_id_v, v_storage_id)]

            for path in paths_to_create:
                maapi.create(maapi_socket, helper.th, path)

            # + set an artificial mount-point that is not shown in high-level
            # YANG; For example case here, use a string prefix:
            #   "/mnt/user-id/storage-id".
            mountpoint_str = '/mnt/user-storages/{0}/{1}'.format(user_id_v,
                                                                 folder_id_v)
            val = confd.Value(mountpoint_str, confd.C_BUF)
            maapi.set_elem(maapi_socket, helper.th, val,
                           kp_storage(v_storage_id) + '/mountpoint')

            return confd.CONFD_OK

        def _update_content_type(user_id_v, folder_id_v, content_v):
            """ Add the specific content-type to the low-level bitmask.
            """
            path = kp_content_type(user_id_v, folder_id_v)
            bit_to_add = ct_enum_to_bits[int(content_v)]
            # /folder-user{bob}/managed-folder{myhome}/content-type{archive}
            v_bits_set = optional_get_elem(maapi_socket, helper.th,
                                           kp_content_type(user_id_v,
                                                           folder_id_v))
            if v_bits_set is not None:
                bits_set = int(v_bits_set)
                if not bool(bits_set & bit_to_add):
                    new_bitmask = confd.Value(bits_set + bit_to_add,
                                              confd.C_BIT32)
                    maapi.set_elem(maapi_socket, helper.th, new_bitmask, path)
            else:
                new_bitmask = confd.Value(bit_to_add, confd.C_BIT32)
                maapi.set_elem(maapi_socket, helper.th, new_bitmask, path)
            return confd.CONFD_OK

        if isinstance(kp[0], confd.XmlTag):
            return _create_type_empty(kp)

        list_tag = kp[1].tag
        if ns_folders.folders_folder_user == list_tag:
            # /folder-user{bob}
            return _create_folder_user(kp[-2][0])
        elif ns_folders.folders_managed_folder == list_tag:
            # /folder-user{bob}/managed-folder{myhome}
            v_user_id = helper.get_user_id_value(kp[-2][0])
            return _create_managed_folder(v_user_id, kp[0][0])
        elif ns_folders.folders_content_type == list_tag:
            # /folder-user{bob}/managed-folder{myhome}/content-type{archive}
            v_user_id = helper.get_user_id_value(kp[-2][0])
            return _update_content_type(v_user_id, kp[-4][0], kp[0][0])
        else:
            raise NotImplementedError

    def cb_remove(self, tctx, kp):
        helper = TransformDataHelper(tctx.th)

        def _remove_specific_leaf(keypath):
            """ Handle deletion of a specific transformed leaf.
            """
            tag_mapping = {
                ns_folders.folders_auth_none: None,
                ns_folders.folders_auth_key: '/auth-info/key',
                ns_folders.folders_auth_password: '/auth-info/password'
            }

            leaf_tag = keypath[0].tag
            sub_path = tag_mapping[leaf_tag]
            if sub_path is None:
                # nothing to be deleted for "none"
                return confd.CONFD_OK

            username_v = kp[-2][0] if len(kp) > 2 else None
            user_id_v = helper.get_user_id_value(username_v)

            maapi.delete(maapi_socket, helper.th,
                         kp_user(user_id_v) + sub_path)
            return confd.CONFD_OK

        def _remove_ownerships(user_id_v):
            """ Remove all the data related to specific user's owned folders.
            """
            def _ownership_iter(keypath, value):
                """ XPath iteration for "batch" deletion of ownership records.
                """
                _remove_storage_data(keypath[1][1])
                return confd.ITER_CONTINUE

            # find all the user's ownerships - that have specific user-id
            xpath_expr = '{0}[user-id="{1}"]/user-id'.format(OWNER_PATH,
                                                             user_id_v)
            return maapi.xpath_eval(sock=maapi_socket, thandle=helper.th,
                                    expr=xpath_expr, result=_ownership_iter,
                                    trace=None, path=ROOT_PATH)

        def _remove_folder_user(user_id_val):
            """ Remove all the data related to specific user.
            """
            _remove_ownerships(user_id_val)
            maapi.delete(maapi_socket, helper.th, kp_user(user_id_val))

        def _remove_storage_data(storage_id_val):
            """ Remove all the data related to specific managed folder.
            """
            str_uid = str(storage_id_val).split(STORAGE_ID_SEPARATOR)[0]

            paths_to_delete = [kp_storage(storage_id_val),
                               kp_ownership(str_uid, storage_id_val)]

            for path in paths_to_delete:
                maapi.delete(maapi_socket, helper.th, path)

        def _remove_content_type(user_id_v, folder_id_v, content_v):
            """ Remove specific content-type from low-level bitmask.
            """
            path = kp_content_type(user_id_v, folder_id_v)
            bit_to_remove = ct_enum_to_bits[int(content_v)]

            # /folder-user{bob}/managed-folder{myhome}/content-type{archive}
            v_bits_set = optional_get_elem(maapi_socket, helper.th,
                                           kp_content_type(user_id_v,
                                                           folder_id_v))
            if v_bits_set is not None:
                bits_set = int(v_bits_set)
                if bool(bits_set & bit_to_remove):
                    if bits_set == bit_to_remove:
                        maapi.delete(maapi_socket, helper.th, path)
                    else:
                        new_bitmask = confd.Value(bits_set - bit_to_remove,
                                                  confd.C_BIT32)
                        maapi.set_elem(maapi_socket, helper.th, new_bitmask,
                                       path)

        if isinstance(kp[0], confd.XmlTag):
            return _remove_specific_leaf(kp)

        list_tag = kp[1].tag

        if ns_folders.folders_folder_user == list_tag:

            v_user_id = helper.get_user_id_value(kp[0][0])
            return _remove_folder_user(v_user_id)

        elif ns_folders.folders_managed_folder == list_tag:

            v_user_id = helper.get_user_id_value(kp[2][0])
            v_storage_id = concat_storage_id_value(v_user_id, kp[0][0])
            return _remove_storage_data(v_storage_id)

        elif ns_folders.folders_content_type == list_tag:

            v_user_id = helper.get_user_id_value(kp[-2][0])
            return _remove_content_type(v_user_id, kp[-4][0], kp[0][0])

        else:
            raise NotImplementedError


def main():
    """ Main execution of the transformer daemon.
    """
    global maapi_socket

    _confd.set_debug(debug_level, sys.stderr)

    daemon_ctx = dp.init_daemon(daemon_name)

    maapi_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    worker_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

    try:
        maapi.connect(maapi_socket, dest_ip, dest_port, path=ROOT_PATH)
        maapi.load_schemas(maapi_socket)

        dp.connect(daemon_ctx, control_sock, dp.CONTROL_SOCKET,
                   dest_ip, dest_port, path=ROOT_PATH)

        dp.connect(daemon_ctx, worker_sock, dp.WORKER_SOCKET,
                   dest_ip, dest_port, path=ROOT_PATH)

        transaction_cb = TransactionCallbackImpl(worker_sock)
        dp.register_trans_cb(daemon_ctx, transaction_cb)

        transform_cb = TransformCallbackImpl()
        dp.register_data_cb(daemon_ctx,
                            ns_folders.callpoint_transcp,
                            transform_cb)

        dp.register_done(daemon_ctx)

        try:
            read_list = [control_sock, worker_sock]
            write_list = []
            error_list = []

            fd_map = {
                control_sock.fileno(): control_sock,
                worker_sock.fileno(): worker_sock
            }

            print('entering poll loop')
            while True:
                read_socks = select.select(read_list, write_list,
                                           error_list, 1)[0]
                for rs in read_socks:
                    sock = fd_map[rs.fileno()]
                    try:
                        dp.fd_ready(daemon_ctx, sock)
                    except _confd.error.Error as ex:
                        traceback.print_exc()
                        if ex.confd_errno is not confd.ERR_EXTERNAL:
                            raise ex

        except KeyboardInterrupt:
            print("Ctrl-C pressed\n")
    finally:
        control_sock.close()
        worker_sock.close()
        dp.release_daemon(daemon_ctx)


if __name__ == '__main__':
    main()
