#!/bin/sh
ecode=1; while [ $ecode -ne 0 ]; do sleep .5; confd_cmd -o -c "mget /tfcm:confd-state/tfcm:internal/tfcm:cdb/tfcm:client{1}/tfcm:name" > /dev/null; ecode=$?; done;
