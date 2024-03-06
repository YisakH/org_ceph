#!/bin/bash

# RADOS Gateway 프로세스 찾기
radosgw_pid=$(ps -ef | grep 'radosgw' | grep -v 'grep' | awk '{print $2}')

# 프로세스가 실행 중이면 종료
if [ ! -z "$radosgw_pid" ]; then
    echo "Killing existing radosgw process (PID: $radosgw_pid)"
    kill -9 $radosgw_pid
fi

# RADOS Gateway 시작
echo "Starting radosgw..."
/ceph/org_ceph/build/bin/radosgw /ceph/org_ceph/build/ceph.conf

echo "radosgw started"

