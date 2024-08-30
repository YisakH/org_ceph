#pragma once

#include "rgw_service.h"
#include "svc_meta_be.h"

#define RGW_BUCKETS_OBJ_SUFFIX ".buckets"

using namespace std;

struct rgw_cache_entry_info;
template <class T> class RGWChainedCacheImpl;
class RGWSI_Zone;
class RGWSI_SysObj;
class RGWSI_SysObj_Cache;
class RGWSI_Meta;
class RGWSI_SyncModules;
class RGWSI_MetaBackend_Handler;
class RGWSI_MBSObj_Handler_Module;

class RGWSI_HBAC_SObj : public RGWServiceInstance {
  RGWSI_MetaBackend_Handler *be_handler;
  std::unique_ptr<RGWSI_MetaBackend::Module> be_module;

public:
  librados::Rados *rados{nullptr};

  struct Svc {
    RGWSI_Zone *zone{nullptr};
    RGWSI_SysObj *sysobj{nullptr};
    RGWSI_SysObj_Cache *cache{nullptr};
    RGWSI_Meta *meta{nullptr};
    RGWSI_MetaBackend *meta_be{nullptr};
    RGWSI_SyncModules *sync_modules{nullptr};
    RGWSI_HBAC_SObj *hbac{nullptr};
  } svc;

  struct hbac_info_cache_entry {
    RGWHbacInfo info;
    RGWObjVersionTracker objv_tracker;
    real_time mtime;
  };

  static std::string get_meta_key(const RGWHbacInfo &info) {
    return info.to_str();
  }

  using RGWChainedCacheImpl_hbac_info_cache_entry =
      RGWChainedCacheImpl<hbac_info_cache_entry>;
  std::unique_ptr<RGWChainedCacheImpl_hbac_info_cache_entry> hbac_info_cache;

  RGWSI_HBAC_SObj(CephContext *cct);
  ~RGWSI_HBAC_SObj();

  void init(librados::Rados *rados_, RGWSI_Zone *_zone_svc,
            RGWSI_SysObj *_sysobj_svc, RGWSI_SysObj_Cache *_cache_svc,
            RGWSI_Meta *_meta_svc, RGWSI_MetaBackend *_meta_be_svc,
            RGWSI_SyncModules *_sync_modules_svc) {
    svc.hbac = this;
    rados = rados_;
    svc.zone = _zone_svc;
    svc.sysobj = _sysobj_svc;
    svc.cache = _cache_svc;
    svc.meta = _meta_svc;
    svc.meta_be = _meta_be_svc;
    svc.sync_modules = _sync_modules_svc;
  }
  RGWSI_MetaBackend_Handler *get_be_handler() { return be_handler; }
  int do_start(optional_yield y, const DoutPrefixProvider *dpp) override;

  int store_hbac_info(RGWSI_MetaBackend::Context *ctx, const RGWHbacInfo &info,
                      RGWObjVersionTracker *objv_tracker,
                      const real_time &mtime, bool exclusive,
                      map<string, bufferlist> *attrs, optional_yield y,
                      const DoutPrefixProvider *dpp);

  int read_hbac_info(RGWSI_MetaBackend::Context *ctx, RGWHbacInfo &info,
                     RGWObjVersionTracker *const objv_tracker,
                     real_time *const pmtime,
                     rgw_cache_entry_info *const cache_info,
                     std::map<std::string, bufferlist> *const pattrs,
                     optional_yield y, const DoutPrefixProvider *dpp);

  int remove_hbac_info(RGWSI_MetaBackend::Context *ctx, RGWHbacInfo &info,
                       RGWObjVersionTracker *objv_tracker, optional_yield y,
                       const DoutPrefixProvider *dpp);

  int store_hierarchy_info(RGWSI_MetaBackend::Context *ctx,
                           const HbacUserHierarchy &hierarchy,
                           RGWObjVersionTracker *objv_tracker,
                           const real_time &mtime, bool exclusive,
                           map<string, bufferlist> *attrs, optional_yield y,
                           const DoutPrefixProvider *dpp);

  int read_hierarchy_info(RGWSI_MetaBackend::Context *ctx,
                          HbacUserHierarchy &hierarchy,
                          RGWObjVersionTracker *const objv_tracker,
                          real_time *const pmtime,
                          rgw_cache_entry_info *const cache_info,
                          std::map<std::string, bufferlist> *const pattrs,
                          optional_yield y, const DoutPrefixProvider *dpp);

  int remove_hierarchy_info(RGWSI_MetaBackend::Context *ctx,
                            HbacUserHierarchy &hierarchy,
                            RGWObjVersionTracker *objv_tracker,
                            optional_yield y, const DoutPrefixProvider *dpp);
};