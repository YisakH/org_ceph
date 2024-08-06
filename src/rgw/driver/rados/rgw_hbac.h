#pragma once

#include "driver/rados/rgw_bucket.h"
 
class RGWHBACCtl : public RGWBucketCtl{

  struct Svc {
    RGWSI_Zone *zone{nullptr};
    RGWSI_Bucket *bucket{nullptr};
    RGWSI_Bucket_Sync *bucket_sync{nullptr};
    RGWSI_BucketIndex *bi{nullptr};
    RGWSI_User* user = nullptr;
    RGWSI_HBAC_SObj *hbac{nullptr};
  } svc;

    int store_hbac_info(const rgw_bucket& bucket,
                                    RGWBucketEntryPoint& info,
                                    optional_yield y,
                                    const DoutPrefixProvider *dpp,
                                    const Bucket::PutParams& params = {});

}