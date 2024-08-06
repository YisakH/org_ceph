#pragma once

#include "svc_user_rados.h"

using namespace std;

class RGWSI_HBAC_SObj : public RGWSI_User_RADOS
{
public:

  struct Svc {
    RGWSI_Zone *zone{nullptr};
    RGWSI_SysObj *sysobj{nullptr};
    RGWSI_SysObj_Cache *cache{nullptr};
    RGWSI_Meta *meta{nullptr};
    RGWSI_MetaBackend *meta_be{nullptr};
    RGWSI_SyncModules *sync_modules{nullptr};
  } svc;

    RGWSI_HBAC_SObj(CephContext *cct);
    ~RGWSI_HBAC_SObj();

  int store_hbac_info(RGWSI_MetaBackend::Context *ctx,
                                const string& key,
                                const RGWUserInfo& info,
                                RGWUserInfo *old_info,
                                RGWObjVersionTracker *objv_tracker,
                                const real_time& mtime,
                                bool exclusive,
                                map<string, bufferlist> *attrs,
                                optional_yield y,
                                const DoutPrefixProvider *dpp);

    int read_hbac_info(RGWSI_MetaBackend::Context *ctx,
                       const string& key,
                       RGWUserInfo *info,
                       RGWObjVersionTracker * const objv_tracker,
                       real_time * const pmtime,
                       rgw_cache_entry_info * const cache_info,
                       std::map<std::string, bufferlist> * const pattrs,
                       optional_yield y,
                       const DoutPrefixProvider *dpp);
};