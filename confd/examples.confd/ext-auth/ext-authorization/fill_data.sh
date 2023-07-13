#!/bin/bash

echo_items() {
    echo "<example-$1 xmlns=\"http://tail-f.com/ns/example/datamodel\">"
    for (( i=1; i<=$2; i++ ))
    do
        echo "<items><name>item-$i</name><value>$i</value></items>"
    done
    echo "</example-$1>"

}

if [ "$1" = "state" ]; then
(
    echo_items $1 $2
) | confd_load -O -l -m
elif [ "$1" = "config" ]; then
(
    echo  "<edit-config><target><running/></target><config>"
    echo_items $1 $2
    echo "</config></edit-config>"
) |  netconf-console --rpc=-
else
    echo "Usage fill_data.sh state|config num"
    exit 1
fi
