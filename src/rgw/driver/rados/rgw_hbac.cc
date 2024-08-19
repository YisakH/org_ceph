
#include "rgw_hbac.h"

int RGWHbacCtl::store_hbac(const DoutPrefixProvider *dpp,
                 optional_yield y,
                 RGWHbacInfo& info,
                 const PutParams& params)
{
  return be_handler->call([&](RGWSI_MetaBackend_Handler::Op *op) {
    return svc.hbac->store_hbac_info(op->ctx(), "key",
                                      info,
                                     params.objv_tracker,
                                     params.mtime,
                                     params.exclusive,
                                     params.attrs,
                                     y,
                                     dpp);
  });
}

int RGWHbacCtl::read_hbac(const DoutPrefixProvider *dpp,
                optional_yield y,
                RGWHbacInfo& info,
                const GetParams& params)
{
  return be_handler->call([&](RGWSI_MetaBackend_Handler::Op *op) {
    return svc.hbac->read_hbac_info(op->ctx(), "key",
                                    info,
                                    params.objv_tracker,
                                    params.mtime,
                                    params.cache_info,
                                    params.attrs,
                                    y,
                                    dpp);
  });
}

class RGWHbacMetadataHandler : public RGWMetadataHandler_GenericMetaBE{
  public:
  struct Svc {
    RGWSI_HBAC_SObj *hbac{nullptr};
  } svc;

  struct Ctl {
    RGWHbacCtl *hbac{nullptr};
  } ctl;

  RGWHbacMetadataHandler(RGWSI_HBAC_SObj *sobj) {
    base_init(sobj->ctx(), sobj->get_be_handler());
    svc.hbac = sobj;
  };

  ~RGWHbacMetadataHandler() {}

  void init(RGWSI_HBAC_SObj *hbac_svc,
            RGWHbacCtl *hbac_ctl) {
    base_init(hbac_svc->ctx(), hbac_svc->get_be_handler());
    svc.hbac = hbac_svc;
    ctl.hbac = hbac_ctl;
  }

  string get_type() override {
    return "hbac";
  }

  int do_get(RGWSI_MetaBackend_Handler::Op *op, string& entry, RGWMetadataObject **obj, optional_yield y, const DoutPrefixProvider *dpp) override {};
  RGWMetadataObject *get_meta_obj(JSONObj *jo, const obj_version& objv, const ceph::real_time& mtime) override {};
  int do_put(RGWSI_MetaBackend_Handler::Op *op, string& entry,
             RGWMetadataObject *obj,
             RGWObjVersionTracker& objv_tracker,
             optional_yield y, const DoutPrefixProvider *dpp,
             RGWMDLogSyncType type, bool from_remote_zone) override {};
  int do_remove(RGWSI_MetaBackend_Handler::Op *op, string& entry, RGWObjVersionTracker& objv_tracker,
                optional_yield y, const DoutPrefixProvider *dpp) override {};
};

RGWMetadataHandler* RGWHbacMetaHandlerAllocator::alloc(RGWSI_HBAC_SObj *hbac){
  return new RGWHbacMetadataHandler(hbac);
}