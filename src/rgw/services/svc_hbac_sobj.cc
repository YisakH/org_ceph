#include "svc_hbac_sobj.h"
#include "svc_meta_be_sobj.h"
#include "svc_zone.h"
#include "svc_meta.h"
#include "svc_sys_obj_cache.h"

RGWSI_HBAC_SObj::RGWSI_HBAC_SObj(CephContext *cct): RGWSI_User_RADOS(cct) {
}

RGWSI_HBAC_SObj::~RGWSI_HBAC_SObj() {
}

int RGWSI_HBAC_SObj::do_start(optional_yield y, const DoutPrefixProvider *dpp) {
  hbac_info_cache.reset(new RGWChainedCacheImpl<hbac_info_cache_entry>);
  hbac_info_cache->init(svc.cache);
  
  int r = svc.meta->create_be_handler(RGWSI_MetaBackend::Type::MDBE_SOBJ, &be_handler);
  std::ofstream out("/tmp/RGWSI_HBAC_SObj_do_start_log.txt");
  out << "be_handler value is:" << be_handler << std::endl; // 값 잘 나옴
  out.close();
  if (r < 0){
    ldpp_dout(dpp, 0) << "ERROR: failed to create meta backend handler(RGWSI_HBAC_SObj::do_start()):" << r << dendl;
    return r;
  }
  return 0;
}

int RGWSI_HBAC_SObj::store_hbac_info(RGWSI_MetaBackend::Context *ctx,
                                const string& key,
                                const RGWHbacInfo& info,
                                RGWObjVersionTracker *objv_tracker,
                                const real_time& mtime,
                                bool exclusive,
                                map<string, bufferlist> *attrs,
                                optional_yield y,
                                const DoutPrefixProvider *dpp)
{
  bufferlist bl;
  encode(info, bl);

  RGWSI_MBSObj_PutParams params(bl, attrs, mtime, exclusive);

  int ret = svc.meta_be->put(ctx, key, params, objv_tracker, y, dpp);
  if (ret < 0) {
    return ret;
  }

  return ret;
}


int RGWSI_HBAC_SObj::read_hbac_info(RGWSI_MetaBackend::Context *ctx,
                                    const string& key,
                                    RGWHbacInfo &info,
                                    RGWObjVersionTracker * const objv_tracker,
                                    real_time * const pmtime,
                                    rgw_cache_entry_info * const cache_info,
                                    map<string, bufferlist> * const pattrs,
                                    optional_yield y,
                                    const DoutPrefixProvider *dpp)
{
    bufferlist bl;

    // RGWSI_MBSObj_GetParams 인스턴스를 생성하고 필요 시 추가 정보를 설정
    RGWSI_MBSObj_GetParams params(&bl, pattrs, pmtime);
    params.set_cache_info(cache_info);

    // get_entry 호출로 HBAC 정보를 읽어옴
    int ret = svc.meta_be->get_entry(ctx, key, params, objv_tracker, y, dpp);
    if (ret < 0) {
        // 만약 실패하면, 오류 코드를 반환
        return ret;
    }

    // bufferlist를 사용하여 데이터를 디코딩
    auto iter = bl.cbegin();
    try {
        // RGWHbacInfo 객체를 디코딩
        decode(info, iter);

    } catch (buffer::error& err) {
        // 디코딩 실패 시, 오류 로그 출력 후 오류 코드 반환
        ldpp_dout(dpp, 0) << "ERROR: failed to decode HBAC info, caught buffer::error" << dendl;
        return -EIO;
    }

    // 성공적으로 정보를 읽어왔으면 0 반환
    return 0;
}

int RGWSI_HBAC_SObj::remove_hbac_info(RGWSI_MetaBackend::Context *ctx,
                                      const string& key,
                                      RGWObjVersionTracker *objv_tracker,
                                      optional_yield y,
                                      const DoutPrefixProvider *dpp)
{
    // HBAC 정보를 삭제하기 위해 remove_entry 호출

    RGWSI_MBSObj_RemoveParams remove_params;
    int ret = svc.meta_be->remove_entry(dpp, ctx, key, remove_params, objv_tracker, y);
    if (ret < 0) {
        // 만약 실패하면, 오류 코드를 반환
        return ret;
    }

    // 성공적으로 정보를 삭제했으면 0 반환
    return 0;
}
