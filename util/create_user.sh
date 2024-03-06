#!/bin/bash

/ceph/org_ceph/build/bin/radosgw-admin user create --uid="root" --display-name="root" --access-key="root" --secret-key="root"
/ceph/org_ceph/build/bin/radosgw-admin user create --uid="test-user" --display-name="test-user" --access-key="qwer" --secret-key="qwer"


