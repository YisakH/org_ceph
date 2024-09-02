#include "svc_hbac_sobj.h"
#include "svc_meta.h"
#include "svc_meta_be_sobj.h"
#include "svc_sync_modules.h"
#include "svc_sys_obj.h"
#include "svc_sys_obj_cache.h"
#include "svc_zone.h"

#include "rgw_bucket.h"
#include "rgw_rados.h"
#include "rgw_tools.h"
#include "rgw_user.h"
#include "rgw_zone.h"

#define RGW_HBAC_HIERARCHY_OBJ "hbac_hierarchy"

class RGWSI_Hbac_Module : public RGWSI_MBSObj_Handler_Module {
  RGWSI_HBAC_SObj::Svc &svc;
  const string prefix;

public:
  RGWSI_Hbac_Module(RGWSI_HBAC_SObj::Svc &_svc)
      : RGWSI_MBSObj_Handler_Module("hbac"), svc(_svc) {}
  void get_pool_and_oid(const string &key, rgw_pool *pool,
                        string *oid) override {
    if (pool) {
      *pool = svc.zone->get_zone_params().user_uid_pool;
    }
    if (oid) {
      *oid = key;
    }
  }

  const string &get_oid_prefix() override { return prefix; }

  bool is_valid_oid(const string &oid) override {
    // filter out the user.buckets objects
    return !boost::algorithm::ends_with(oid, RGW_BUCKETS_OBJ_SUFFIX);
  }

  string key_to_oid(const string &key) override { return key; }

  string oid_to_key(const string &oid) override { return oid; }
};

RGWSI_HBAC_SObj::RGWSI_HBAC_SObj(CephContext *cct) : RGWServiceInstance(cct) {}

RGWSI_HBAC_SObj::~RGWSI_HBAC_SObj() {}

int RGWSI_HBAC_SObj::do_start(optional_yield y, const DoutPrefixProvider *dpp) {
  hbac_info_cache.reset(new RGWChainedCacheImpl<hbac_info_cache_entry>);
  hbac_info_cache->init(svc.cache);

  int r = svc.meta->create_be_handler(RGWSI_MetaBackend::Type::MDBE_SOBJ,
                                      &be_handler);
  std::ofstream out("/tmp/RGWSI_HBAC_SObj_do_start_log.txt");
  out << "be_handler value is:" << be_handler << std::endl; // 값 잘 나옴
  out.close();
  if (r < 0) {
    ldpp_dout(dpp, 0) << "ERROR: failed to create meta backend "
                         "handler(RGWSI_HBAC_SObj::do_start()):"
                      << r << dendl;
    return r;
  }

  RGWSI_MetaBackend_Handler_SObj *bh =
      static_cast<RGWSI_MetaBackend_Handler_SObj *>(be_handler);

  auto module = new RGWSI_Hbac_Module(svc);
  be_module.reset(module);
  bh->set_module(module);
  return 0;
}

int RGWSI_HBAC_SObj::store_hbac_info(RGWSI_MetaBackend::Context *ctx,
                                     const RGWHbacInfo &info,
                                     RGWObjVersionTracker *objv_tracker,
                                     const real_time &mtime, bool exclusive,
                                     map<string, bufferlist> *attrs,
                                     optional_yield y,
                                     const DoutPrefixProvider *dpp) {
  bufferlist bl;
  encode(info, bl);

  RGWSI_MBSObj_PutParams params(bl, attrs, mtime, exclusive);

  int ret =
      svc.meta_be->put(ctx, get_meta_key(info), params, objv_tracker, y, dpp);
  if (ret < 0) {
    return ret;
  }

  return ret;
}

int RGWSI_HBAC_SObj::read_hbac_info(RGWSI_MetaBackend::Context *ctx,
                                    RGWHbacInfo &info,
                                    RGWObjVersionTracker *const objv_tracker,
                                    real_time *const pmtime,
                                    rgw_cache_entry_info *const cache_info,
                                    map<string, bufferlist> *const pattrs,
                                    optional_yield y,
                                    const DoutPrefixProvider *dpp) {
  bufferlist bl;

  // RGWSI_MBSObj_GetParams 인스턴스를 생성하고 필요 시 추가 정보를 설정
  RGWSI_MBSObj_GetParams params(&bl, pattrs, pmtime);
  params.set_cache_info(cache_info);

  // get_entry 호출로 HBAC 정보를 읽어옴
  int ret =
      svc.meta_be->get(ctx, get_meta_key(info), params, objv_tracker, y, dpp);
  if (ret < 0) {
    // 만약 실패하면, 오류 코드를 반환
    return ret;
  }

  // bufferlist를 사용하여 데이터를 디코딩
  auto iter = bl.cbegin();
  try {
    // RGWHbacInfo 객체를 디코딩
    decode(info, iter);

  } catch (buffer::error &err) {
    // 디코딩 실패 시, 오류 로그 출력 후 오류 코드 반환
    ldpp_dout(dpp, 0)
        << "ERROR: failed to decode HBAC info, caught buffer::error" << dendl;
    return -EIO;
  }

  // 성공적으로 정보를 읽어왔으면 0 반환
  return 0;
}

int RGWSI_HBAC_SObj::remove_hbac_info(RGWSI_MetaBackend::Context *ctx,
                                      RGWHbacInfo &info,
                                      RGWObjVersionTracker *objv_tracker,
                                      optional_yield y,
                                      const DoutPrefixProvider *dpp) {
  // HBAC 정보를 삭제하기 위해 remove_entry 호출

  RGWSI_MBSObj_RemoveParams remove_params;
  int ret = svc.meta_be->remove(ctx, get_meta_key(info), remove_params,
                                objv_tracker, y, dpp);
  if (ret < 0) {
    // 만약 실패하면, 오류 코드를 반환
    return ret;
  }

  // 성공적으로 정보를 삭제했으면 0 반환
  return 0;
}

int RGWSI_HBAC_SObj::read_hierarchy_info(
    RGWSI_MetaBackend::Context *ctx, HbacUserHierarchy &hierarchy,
    RGWObjVersionTracker *const objv_tracker, real_time *const pmtime,
    rgw_cache_entry_info *const cache_info,
    std::map<std::string, bufferlist> *const pattrs, optional_yield y,
    const DoutPrefixProvider *dpp) {
  bufferlist bl;

  RGWSI_MBSObj_GetParams params(&bl, pattrs, pmtime);
  params.set_cache_info(cache_info);

  int ret = svc.meta_be->get(ctx, RGW_HBAC_HIERARCHY_OBJ, params, objv_tracker,
                             y, dpp);

  if (ret < 0) {
    return RGW_HBAC_KEY_NOT_FOUND;
  }

  auto iter = bl.cbegin();
  try {
    decode(hierarchy, iter);
  } catch (buffer::error &err) {
    ldpp_dout(dpp, 0)
        << "ERROR: failed to decode HBAC hierarchy, caught buffer::error"
        << dendl;
    return -EIO;
  }

  return ret;
}

int RGWSI_HBAC_SObj::store_hierarchy_info(
    RGWSI_MetaBackend::Context *ctx, const HbacUserHierarchy &hierarchy,
    RGWObjVersionTracker *objv_tracker, const real_time &mtime, bool exclusive,
    map<string, bufferlist> *attrs, optional_yield y,
    const DoutPrefixProvider *dpp) {
  bufferlist bl;
  encode(hierarchy, bl);

  RGWSI_MBSObj_PutParams params(bl, attrs, mtime, exclusive);

  int ret = svc.meta_be->put(ctx, RGW_HBAC_HIERARCHY_OBJ, params, objv_tracker,
                             y, dpp);
  return ret;
}