#!/bin/bash

# 현재 작업 디렉토리 저장
CURRENT_DIR=$(pwd)

# Ceph 빌드 디렉토리로 이동
CEPH_BUILD_DIR="/ceph/org_ceph/build"
cd "$CEPH_BUILD_DIR" || exit

# vstart.sh 스크립트 실행
./../src/vstart.sh --debug --new -x --localhost --bluestore

# mgr 모듈 활성화
./bin/ceph mgr module enable rgw

# radosgw 실행
./bin/radosgw ceph.conf

# 스크립트 실행 후 현재 작업 디렉토리로 복귀
cd "$CURRENT_DIR" || exit

