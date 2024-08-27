
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

int RGWHbacCtl::remove_hbac(const DoutPrefixProvider *dpp,
                  optional_yield y,
                  RGWHbacInfo& info,
                  const RemoveParams& params)
{
  return be_handler->call([&](RGWSI_MetaBackend_Handler::Op *op) {
    return svc.hbac->remove_hbac_info(op->ctx(), "key",
                                      info,
                                      params.objv_tracker,
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
    std::ofstream out("/tmp/RWGHbacMetadataHandler_constructor_log.txt");
    out << "hbac_svc be_handler value is:" << sobj->get_be_handler() << std::endl;
    out.close();
    svc.hbac = sobj;
  };

  ~RGWHbacMetadataHandler() {}

  void init(RGWSI_HBAC_SObj *hbac_svc,
            RGWHbacCtl *hbac_ctl) {
    base_init(hbac_svc->ctx(), hbac_svc->get_be_handler());
    std::ofstream out("/tmp/hbac_metadata_handler_log.txt");
    out << "hbac_svc be_handler value is:" << hbac_svc->get_be_handler() << std::endl; // 호출되지 않음.
    out.close();
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

RGWHbacCtl::RGWHbacCtl(RGWSI_Zone *zone_svc,
            RGWSI_HBAC_SObj *hbac_svc,
            RGWHbacMetadataHandler *_hmhandler) : hmhandler(_hmhandler) {
    svc.zone = zone_svc;
    svc.hbac = hbac_svc;
    be_handler = hmhandler->get_be_handler();

    std::ofstream out("/tmp/be_handler_log.txt");
    // be_handler에 저장된 값이 0x0이거나 0x3인지 검사
    if (be_handler == nullptr){
      // /tmp에 로그 파일을 만들고 출력
      
      out << "be_handler is nullptr" << std::endl;

    } else if(be_handler == (void*)0x3){
      // /tmp에 로그 파일을 만들고 출력
      out << "be_handler is 0x3" << std::endl;
    } else{
      out << "be_handler value is:" << be_handler << std::endl;
    }

    // 로그 닫기
    out.close();
  }