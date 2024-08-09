
#pragma once

#include "rgw_hbac.h"

int RGWHBACCtl::store_hbac_info(const rgw_bucket& bucket,
                                               RGWBucketEntryPoint& info,
                                               optional_yield y,
                                               const DoutPrefixProvider *dpp,
                                               const Bucket::PutParams& params)
{
  return bm_handler->call([&](RGWSI_Bucket_EP_Ctx& ctx) {
    return svc.hbac->store_hbac_info(ctx,
                                                    RGWSI_Bucket::get_entrypoint_meta_key(bucket),
                                                    info,
                                                    params.exclusive,
                                                    params.mtime,
                                                    params.attrs,
                                                    params.objv_tracker,
                                                    y,
                                                    dpp);
  });
}

RGWHBACCtl::RGWHBACCtl(RGWSI_Zone *zone_svc,
                           RGWSI_Bucket *bucket_svc,
                           RGWSI_Bucket_Sync *bucket_sync_svc,
                           RGWSI_BucketIndex *bi_svc,
                           RGWSI_User* user_svc)
  : cct(zone_svc->ctx())
{
  svc.zone = zone_svc;
  svc.bucket = bucket_svc;
  svc.bucket_sync = bucket_sync_svc;
  svc.bi = bi_svc;
  svc.user = user_svc;
}

RGWHBACCtl::store_hbac(const DoutPrefixProvider *dpp,
                       optional_yield y,
                       const PutParams& params)
{
  be_handler
}