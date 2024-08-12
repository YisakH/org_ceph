
#include "rgw_hbac.h"

int RGWHBACCtl::store_hbac(const DoutPrefixProvider *dpp,
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

int RGWHBACCtl::read_hbac(const DoutPrefixProvider *dpp,
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