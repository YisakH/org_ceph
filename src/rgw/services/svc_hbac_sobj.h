#pragma once

#include <string>
#include "rgw_service.h"

#include "svc_meta_be.h"
#include "svc_bucket_types.h"
#include "svc_meta_be_sobj.h"

using namespace std;

class RGWSI_HBAC_SObj : public RGWServiceInstance
{
public:
    struct Svc {
        RGWSI_Bucket_SObj *bucket{nullptr};
        RGWSI_BucketIndex *bi{nullptr};
        RGWSI_Zone *zone{nullptr};
        RGWSI_SysObj *sysobj{nullptr};
        RGWSI_SysObj_Cache *cache{nullptr};
        RGWSI_Meta *meta{nullptr};
        RGWSI_MetaBackend *meta_be{nullptr};
        RGWSI_SyncModules *sync_modules{nullptr};
        RGWSI_Bucket_Sync *bucket_sync{nullptr};
    } svc;

    RGWSI_HBAC_SObj(CephContext *cct) : RGWServiceInstance(cct) {};
    virtual ~RGWSI_HBAC_SObj() {}

    int put_data(RGWSI_Bucket_EP_Ctx& ctx,
                 const string& key,
                 RGWBucketEntryPoint& info,
                 bool exclusive,
                 real_time mtime,
                 const map<string, bufferlist> *pattrs,
                 RGWObjVersionTracker *objv_tracker,
                 optional_yield y,
                 const DoutPrefixProvider *dpp);
};