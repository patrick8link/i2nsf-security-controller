#!/bin/sh

# Script demonstrating simple external authentication
#
# Expected input (on stdin): "[<username>;<password>;]\n"
#
# Expected output: "accept $groups $uid $gid $supplementary_gids $HOME\n"
# o $groups is a space separated list of the group names the user is a member
#   of.
# o $uid is the UNIX integer user id ConfD should use as default when
#   executing commands for this user.
# o $gid is the UNIX integer group id ConfD should use as default when executing
#   commands for this user.
# o $supplementary_gids is a (possibly empty) space separated list of additional
#   UNIX group ids the user is also a member of.
# o $HOME is the directory which should be used as HOME for this user when ConfD
#   executes commands on behalf of this user.
#

read -r input
user0=${input%%;*}
user=${user0#[}
pass0=${input#*;}
pass=${pass0%;]}

case "$user:$pass" in
    alice:alice)
        echo "accept 9000 20 'homes/alice'"
        ;;
    bob:bob)
        echo "accept 9000 20 'homes/bob'"
        ;;
    *)
        echo "reject 'permission denied'"
        ;;
esac