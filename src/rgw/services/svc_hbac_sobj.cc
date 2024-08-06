#pragma once

#include "svc_hbac_sobj.h"
#include "svc_meta_be_sobj.h"
#include "svc_zone.h"

RGWSI_HBAC_SObj::RGWSI_HBAC_SObj(CephContext *cct): RGWSI_User_RADOS(cct) {
}

RGWSI_HBAC_SObj::~RGWSI_HBAC_SObj() {
}


int RGWSI_HBAC_SObj::store_hbac_info(RGWSI_MetaBackend::Context *ctx,
                                const string& key,
                                const RGWUserInfo& info,
                                RGWUserInfo *old_info,
                                RGWObjVersionTracker *objv_tracker,
                                const real_time& mtime,
                                bool exclusive,
                                map<string, bufferlist> *attrs,
                                optional_yield y,
                                const DoutPrefixProvider *dpp)
{
  bufferlist bl;
  encode(info, bl);

  RGWSI_MBSObj_PutParams params(bl, attrs, mtime, exclusive);

  int ret = svc.meta_be->put(ctx, key, params, objv_tracker, y, dpp);
  if (ret < 0) {
    return ret;
  }

  return ret;
}


int RGWSI_HBAC_SObj::read_hbac_info(RGWSI_MetaBackend::Context *ctx,
                               const string& key,
                               RGWUserInfo *info,
                               RGWObjVersionTracker * const objv_tracker,
                               real_time * const pmtime,
                               rgw_cache_entry_info * const cache_info,
                               map<string, bufferlist> * const pattrs,
                               optional_yield y,
                               const DoutPrefixProvider *dpp)
{
  
}