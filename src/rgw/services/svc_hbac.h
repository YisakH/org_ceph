

#pragma once

#include "svc_meta_be.h"

#include "rgw_service.h"
#include "rgw_sal_fwd.h"

class RGWSI_HBAC : public RGWServiceInstance
{
    RGWSI_HBAC(CephContext *cct);
    virtual ~RGWSI_HBAC();
};