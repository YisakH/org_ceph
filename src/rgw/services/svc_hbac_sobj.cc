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