#pragma once

#include "svc_hbac_sobj.h"

int RGWSI_HBAC_SObj::put_data(RGWSI_Bucket_EP_Ctx& ctx,
                              const string& key,
                              RGWBucketEntryPoint& info,
                              bool exclusive,
                              real_time mtime,
                              const map<string, bufferlist> *pattrs,
                              RGWObjVersionTracker *objv_tracker,
                              optional_yield y,
                              const DoutPrefixProvider *dpp){

    bufferlist bl;
    encode(info, bl);
    RGWSI_MBSObj_PutParams params(bl, pattrs, mtime, exclusive);

    int ret = svc.meta_be->put(ctx.get(), key, params, objv_tracker, y, dpp);

    return ret;
}

void RGWSI_HBAC_SObj::init(
    RGWSI_Zone *_zone_svc, 
    RGWSI_SysObj *_sysobj_svc,
    RGWSI_SysObj_Cache *_cache_svc, 
    RGWSI_Meta *_meta_svc,
    RGWSI_MetaBackend *_meta_be_svc,
    RGWSI_SyncModules *_sync_modules){
}

int RGWSI_HBAC_SObj::::store_user_info(RGWSI_MetaBackend::Context *ctx,
                                const RGWUserInfo& info,
                                RGWUserInfo *old_info,
                                RGWObjVersionTracker *objv_tracker,
                                const real_time& mtime,
                                bool exclusive,
                                map<string, bufferlist> *attrs,
                                optional_yield y,
                                const DoutPrefixProvider *dpp){
                                    
                                }