#!/bin/bash
SDIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir ~/yang/
mkdir ~/yang/modules

cp DataModel/ietf-i2nsf-capability.yang ~/yang/modules/.
cp DataModel/ietf-inet-types.yang ~/yang/modules/.

PYBINDPLUGIN=`/usr/bin/env python3 -c 'import pyangbind; import os; print ("%s/plugin" % os.path.dirname(pyangbind.__file__))'`
pyang --plugindir $PYBINDPLUGIN -f pybind --build-rpcs --split-class-dir $SDIR/rbindings DataModel/ietf-i2nsf-registration-interface.yang

echo "Bindings successfully generated!"
