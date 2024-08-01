#pragma once

#include <string>
#include "rgw_service.h"

#include "svc_hbac.h"
#include "svc_meta_be.h"
#include "svc_bucket_types.h"
#include "svc_meta_be_sobj.h"

using namespace std;

class RGWSI_HBAC_SObj : public RGWSI_HBAC
{
public:
    librados::Rados* rados{nullptr};
    struct Svc {
        RGWSI_User_RADOS *user{nullptr};
        RGWSI_Zone *zone{nullptr};
        RGWSI_SysObj *sysobj{nullptr};
        RGWSI_SysObj_Cache *cache{nullptr};
        RGWSI_Meta *meta{nullptr};
        RGWSI_MetaBackend *meta_be{nullptr};
        RGWSI_SyncModules *sync_modules{nullptr};
    } svc;

    RGWSI_HBAC_SObj(CephContext *cct);
    ~RGWSI_HBAC_SObj() {};
    
    void init(
        RGWSI_Zone *_zone_svc, 
        RGWSI_SysObj *_sysobj_svc,
        RGWSI_SysObj_Cache *_cache_svc, 
        RGWSI_Meta *_meta_svc,
        RGWSI_MetaBackend *_meta_be_svc,
        RGWSI_SyncModules *_sync_modules);

    int store_user_info(RGWSI_MetaBackend::Context *ctx,
                    const RGWUserInfo& info,
                    RGWUserInfo *old_info,
                    RGWObjVersionTracker *objv_tracker,
                    const real_time& mtime,
                    bool exclusive,
                    std::map<std::string, bufferlist> *attrs,
                    optional_yield y,
                    const DoutPrefixProvider *dpp) override;
};