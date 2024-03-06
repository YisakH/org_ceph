#!/bin/bash

cd /ceph/org_ceph/build

ninja vstart

../src/stop.sh

../src/vstart.sh --debug --new -x --localhost --bluestore

./bin/ceph mgr module enable rgw
./bin/radosgw ./ceph.conf
