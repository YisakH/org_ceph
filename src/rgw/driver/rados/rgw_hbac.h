#pragma once

#include <string>
#include <boost/algorithm/string.hpp>
#include "include/ceph_assert.h"

#include "include/types.h"
#include "rgw_common.h"
#include "rgw_tools.h"

#include "rgw_string.h"

#include "common/Formatter.h"
#include "rgw_formats.h"
#include "rgw_metadata.h"
#include "rgw_sal_fwd.h"
#include "rgw_common.h"
#include "rgw_sal.h"
#include "svc_hbac_sobj.h"

class RGWHbacCtl{

  struct Svc {
    RGWSI_Zone *zone{nullptr};
    RGWSI_HBAC_SObj *hbac{nullptr};
  } svc;
  RGWSI_MetaBackend_Handler *be_handler{nullptr};

public:
  RGWHbacCtl(RGWSI_Zone *zone_svc,
             RGWSI_HBAC_SObj *hbac_svc) {
    svc.zone = zone_svc;
    svc.hbac = hbac_svc;
  }

  void init(RGWBucketCtl *bucket_ctl) {
    //ctl.bucket = bucket_ctl;
  }

  //RGWBucketCtl *get_bucket_ctl() {
    //return ctl.bucket;
  //}

  struct GetParams {
    RGWObjVersionTracker *objv_tracker{nullptr};
    ceph::real_time *mtime{nullptr};
    rgw_cache_entry_info *cache_info{nullptr};
    std::map<std::string, bufferlist> *attrs{nullptr};

    GetParams() {}

    GetParams& set_objv_tracker(RGWObjVersionTracker *_objv_tracker) {
      objv_tracker = _objv_tracker;
      return *this;
    }

    GetParams& set_mtime(ceph::real_time *_mtime) {
      mtime = _mtime;
      return *this;
    }

    GetParams& set_cache_info(rgw_cache_entry_info *_cache_info) {
      cache_info = _cache_info;
      return *this;
    }

    GetParams& set_attrs(std::map<std::string, bufferlist> *_attrs) {
      attrs = _attrs;
      return *this;
    }
  };

  struct PutParams {
    RGWUserInfo *old_info{nullptr};
    RGWObjVersionTracker *objv_tracker{nullptr};
    ceph::real_time mtime;
    bool exclusive{false};
    std::map<std::string, bufferlist> *attrs{nullptr};

    PutParams() {}

    PutParams& set_old_info(RGWUserInfo *_info) {
      old_info = _info;
      return *this;
    }

    PutParams& set_objv_tracker(RGWObjVersionTracker *_objv_tracker) {
      objv_tracker = _objv_tracker;
      return *this;
    }

    PutParams& set_mtime(const ceph::real_time& _mtime) {
      mtime = _mtime;
      return *this;
    }

    PutParams& set_exclusive(bool _exclusive) {
      exclusive = _exclusive;
      return *this;
    }

    PutParams& set_attrs(std::map<std::string, bufferlist> *_attrs) {
      attrs = _attrs;
      return *this;
    }
  };

  struct RemoveParams {
    RGWObjVersionTracker *objv_tracker{nullptr};

    RemoveParams() {}

    RemoveParams& set_objv_tracker(RGWObjVersionTracker *_objv_tracker) {
      objv_tracker = _objv_tracker;
      return *this;
    }
  };

  int store_hbac(const DoutPrefixProvider *dpp,
                 optional_yield y,
                 RGWHbacInfo& info,
                 const PutParams& params = {});

  int read_hbac(const DoutPrefixProvider *dpp,
                optional_yield y,
                RGWHbacInfo& info,
                const GetParams& params = {});
  
  int remove_hbac(const DoutPrefixProvider *dpp,
                  optional_yield y,
                  RGWHbacInfo& info,
                  const RemoveParams& params = {});

};

class RGWHbacMetadataHandlerBase : public RGWMetadataHandler_GenericMetaBE{
public:
  virtual ~RGWHbacMetadataHandlerBase();
  virtual void init(RGWSI_HBAC_SObj *hbac_svc,
                    RGWHbacCtl *hbac_ctl);
};


class RGWHbacMetaHandlerAllocator{
  public:
  static RGWMetadataHandler *alloc(RGWSI_HBAC_SObj *hbac);
};