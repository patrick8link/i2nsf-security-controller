#!/usr/bin/env bash

WAIT='wait -n'
if uname | grep -q Darwin
then
    # "wait -n" not supported on Darwin
    WAIT='wait'
fi

function stats_loop {
    local interval=$1
    while sleep $interval
    do
        arp -an |
            (echo '<arpentries xmlns="http://tail-f.com/ns/example/arpe">'
             while read line
             do
                 echo "$line" | tr \  \\n | update_stats_commands
             done
             echo '</arpentries>') |
            confd_load -O -l -r
    done
}

function subscriber {
    local interval=$(confd_cmd -c "mget /arpe-config/interval")
    stats_loop $interval &
    while read cli_line
    do
        # the subscriber sent a value, read into interval
        if [[ "$cli_line" =~ ^arpe-config\ interval\ ([0-9]+)$ ]]
        then
            interval=${BASH_REMATCH[1]}
        elif [[ "$cli_line" =~ ^no\ arpe-config ]]
        then
            # deletion - use the default value
            interval=10
        else
            # some garbage, ignore
            continue
        fi
        echo using push interval $interval
        # restart stats_loop
        kill %1
        ${WAIT}
        stats_loop $interval &
        continue
    done
    echo read failed, exiting
    kill %1
}

function update_stats_commands {
    local hwaddr ip4 ifname perm=false pub=false
    local value
    read # ?
    read value
    ip4=$(echo $value | tr -d '()')
    read # at
    read hwaddr # may be <incomplete> or the like
    read value
    while [ "${value}" != on ]
    do
        case $value in
            PERM) perm=true;;
            PUB) pub=true;;
        esac
        read value
    done
    read ifname
    while read value
    do
        case $value in
            permanent) perm=true;;
            published) pub=true;;
        esac
    done
    cat | sed 's/<incomplete>/incomplete/' <<EOF
<arpe>
  <ip>$ip4</ip>
  <ifname>$ifname</ifname>
  <hwaddr>$hwaddr</hwaddr>
  <permanent>$perm</permanent>
  <published>$pub</published>
</arpe>
EOF
}

confd_cmd -c 'get_cli 1 /arpe-config/interval 10 1000' |
    subscriber
