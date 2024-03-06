#!/bin/bash

# 'radosgw' 프로세스의 PID를 찾습니다.
radosgw_pid=$(ps -ef | grep 'radosgw' | grep -v 'grep' | awk '{print $2}')

# PID가 존재하는지 확인합니다.
if [ -z "$radosgw_pid" ]; then
    echo "radosgw 프로세스를 찾을 수 없습니다."
    exit 1
fi

# gdbserver를 시작하여 radosgw 프로세스에 연결합니다.
echo "radosgw 프로세스($radosgw_pid)에 gdbserver를 연결합니다."
gdbserver :9091 --attach $radosgw_pid

