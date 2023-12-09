//
// Created by root on 12/8/23.
//

#include "rgw_common.h"

#include "rgw_org.h"

using namespace std;

int get_org(const DoutPrefixProvider* dpp, req_state * const s){
    RGWAccessControlPolicy user_acl = s->user_acl;
    rgw_user uid = user_acl.get_owner().id;

    std::string uid_id = uid.id;

    return 0;
}

int create_org(const DoutPrefixProvider* dpp, req_state * const s, std::string org_name){
    return 0;
}


int verify_org_permission(const DoutPrefixProvider* dpp, req_state * const s, const int perm)
{
    // get org information
    // org tier = tier_func(dpp, s)
    // check

    return 0;
}