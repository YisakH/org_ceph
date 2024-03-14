#!/bin/bash

users=("root" "president" "dean1" "dean2" "dean3" "chair1" "chair2" "chair3" "chair4" "chair5" "chair6" "chair7" "student1" "student2" "student3" "student4" "student5" "student6")

cd /ceph/org_ceph/build/
# Loop through users array to create each user
for uid in "${users[@]}"; do
    /ceph/org_ceph/build/bin/radosgw-admin user create --uid="$uid" --display-name="$uid" --access-key="$uid" --secret-key="$uid"
done


# aws --endpoint-url http://localhost:7480 s3 mb s3://test-bucket

