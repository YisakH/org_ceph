//
// Created by root on 23. 12. 29.
//
#include "rgw_org.h"
#include "../rocksdb/include/rocksdb/db.h"
#include <sstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <openssl/hmac.h>
#include <openssl/sha.h>

// TierDB RGWOrgTier::tierDb;
bool OrgPermission::operator<=(const OrgPermission& other) const {
    return (!other.r || r) &&
           (!other.w || w) &&
           (!other.g || g) &&
           (!other.x || x);
}

int DBManager::getData(const std::string &key, std::string &value)
{
    status = db->Get(rocksdb::ReadOptions(), key, &value);
    if (status.ok())
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

int DBManager::putData(const std::string &key, const std::string &value)
{
    std::string exiting_value;
    if(db == nullptr){
        return -1;
    }
    rocksdb::Status s = db->Get(rocksdb::ReadOptions(), key, &exiting_value);
    if (s.ok())
    {
        return 2;
    }
    status = db->Put(rocksdb::WriteOptions(), key, value);
    if (status.ok())
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

int DBManager::deleteData(const std::string &key)
{
    status = db->Delete(rocksdb::WriteOptions(), key);
    if (status.ok())
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

int RGWOrg::putRGWOrg(DBManager &dbManager)
{// 여기서 orgPermission이 그냥 기본으로 들어오는 문제 발생.
    std::string key = user + ":" + orgPermission->path;
    std::string value = authorizer + " " + std::to_string(tier) + " " + std::to_string(orgPermission->r) + " " + std::to_string(orgPermission->w) + " " + std::to_string(orgPermission->x) + " " + std::to_string(orgPermission->g);
    return dbManager.putData(key, value);
}

int RGWOrg::deleteRGWOrg(aclDB &aclDB, std::string key)
{
    return aclDB.deleteData(key);
}

int RGWOrg::getPartialMatchRgwOrg(aclDB &aclDB, std::string user, std::string path, RGWOrg *rgwOrg)
{
    std::istringstream iss(path);
    std::string segment;
    std::string accumulatedPath;
    std::string key;
    int ret = -1;
    while (std::getline(iss, segment, '/'))
    {
        if (!segment.empty())
        { // Skip empty segments (like the one before the first /)
            accumulatedPath += "/";

            accumulatedPath += segment;
            key = user + ":" + accumulatedPath;
            int cur_ret = getFullMatchRGWOrg(aclDB, key, rgwOrg);
            if (cur_ret == 0)
            {
                ret = 0;
            }
        }
    }
    return ret;
}

int RGWOrg::getFullMatchRGWOrg(aclDB &aclDB, std::string key, RGWOrg *rgwOrg)
{
    std::string value;
    int ret = aclDB.getData(key, value);
    if (ret < 0)
    {
        // key 존재하지 않음
        return ret;
    }

    rgwOrg->orgPermission = new OrgPermission();

    std::istringstream iss(key);
    std::string token;

    std::getline(iss, token, ':');
    rgwOrg->user = token;
    std::getline(iss, token, ':');
    rgwOrg->orgPermission->path = token;

    std::istringstream iss2(value);
    std::string token2;
    try
    {
        std::getline(iss2, token2, ' ');
        rgwOrg->authorizer = token2;
        std::getline(iss2, token2, ' ');
        rgwOrg->tier = std::stoi(token2);
        std::getline(iss2, token2, ' ');
        rgwOrg->orgPermission->r = std::stoi(token2) != 0; // 문자열을 bool로 변환
        std::getline(iss2, token2, ' ');
        rgwOrg->orgPermission->w = std::stoi(token2) != 0; // 문자열을 bool로 변환
        std::getline(iss2, token2, ' ');
        rgwOrg->orgPermission->x = std::stoi(token2) != 0; // 문자열을 bool로 변환
        std::getline(iss2, token2, ' ');
        rgwOrg->orgPermission->g = std::stoi(token2) != 0; // 문자열을 bool로 변환
    }
    catch (const std::invalid_argument &e)
    {
        // 오류 처리 (예: 로그 출력, 오류 코드 반환 등)
        return -1; // 또는 다른 오류 코드
    }
    catch (const std::out_of_range &e)
    {
        // 오류 처리
        return -1; // 또는 다른 오류 코드
    }
    return ret;
}

RGWOrg *getAcl(const std::string &user, const std::string &path, bool isFullMatch)
{
    auto &dbm = aclDB::getInstance();
    if (!dbm.getStatus().ok() && !dbm.getStatus().IsNotFound())
    {
        dbm.reOpenDB();
        return nullptr;
    }
    RGWOrg *rgwOrg = new RGWOrg();
    int ret;
    if (isFullMatch)
        ret = RGWOrg::getFullMatchRGWOrg(dbm, user + ":" + path, rgwOrg);
    else{
        ret = RGWOrg::getPartialMatchRgwOrg(dbm, user, path, rgwOrg);
    }
    if (ret < 0)
    {
        return nullptr;
    }
    else
    {
        return rgwOrg;
    }
}

int putAcl(const std::string &user, const std::string &path, const std::string &authorizer, int tier, bool r, bool w, bool x, bool g)
{
    auto &dbm = aclDB::getInstance();
    RGWOrg *rgwOrg;
    if (!dbm.getStatus().ok() && !dbm.getStatus().IsNotFound())
    {
        dbm.reOpenDB();
        return -1;
    }

    rgwOrg = new RGWOrg();
    rgwOrg->setUser(user);
    rgwOrg->setAuthorizer(authorizer);
    rgwOrg->setTier(tier);
    OrgPermission *orgPermission = new OrgPermission(r, w, x, g, path);
    rgwOrg->setOrgPermission(*orgPermission);

    int ret = rgwOrg->putRGWOrg(dbm);
    if (ret < 0)
    {
        return -1;
    }
    else
    {
        return 0;
    }
}

int deleteAcl(const std::string &user, const std::string &path)
{
    auto &dbm = aclDB::getInstance();
    RGWOrg *rgwOrg;
    if (!dbm.getStatus().ok() && !dbm.getStatus().IsNotFound())
    {
        dbm.reOpenDB();
        return -1;
    }

    std::string key = user + ":" + path;
    int ret = rgwOrg->deleteRGWOrg(dbm, key);
    if (ret < 0)
    {
        return -1;
    }
    else
    {
        return 0;
    }
}

int getTier(const std::string &user, int *tier)
{
    int ret = RGWOrgTier::getUserTier(user, tier);
    return ret;
}

int putTier(const std::string &user, int tier)
{
    int ret = RGWOrgTier::putUserTier(user, tier);
    return ret;
}

int deleteTier(const std::string &user)
{
    int ret = RGWOrgTier::deleteUserTier(user);
    return ret;
}


int getAnc(const std::string &user, std::string *anc)
{
    int ret = RGWOrgAnc::getAnc(user, anc);
    return ret;
}

int putAnc(const std::string &user, const std::string &anc)
{
    int ret = RGWOrgAnc::putAnc(user, anc);
    if(ret < 0){
        return ret;
    }
    int anc_tier;
    ret = getTier(anc, &anc_tier);
    if(ret < 0){
        return ret;
    }
    ret = putTier(user, anc_tier + 1);
    return ret;
}

int deleteAnc(const std::string &user)
{
    int ret = RGWOrgAnc::deleteAnc(user);
    return ret;
}


int checkAclWrite(const std::string& request_user, const std::string& target_user, const std::string& path, const std::string& authorizer, int tier, bool r, bool w, bool x, bool g){
    int request_user_tier, target_user_tier;
    int ret;
    ret = RGWOrgTier::getUserTier(request_user, &request_user_tier);
    if(ret < 0){ // request user의 tier가 존재하지 않음
        return -1;
    }
    ret = RGWOrgTier::getUserTier(target_user, &target_user_tier);
    if(ret < 0){
        return -1;
    }

    if(request_user_tier > target_user_tier){
        return RGW_ORG_TIER_NOT_ALLOWED;
    }


    OrgPermission orgPermission(r, w, x, g, path);
    std::string anc_user;
    ret = getAnc(target_user, &anc_user);
    RGWOrg *rgwOrg = getAcl(anc_user, path);
    OrgPermission *ancPermission = rgwOrg->getOrgPermission();

    if(ancPermission != nullptr && orgPermission <= *ancPermission){
        return RGW_ORG_PERMISSION_NOT_ALLOWED;
    }

    int authorizor_user_tier;
    ret = getTier(rgwOrg->getAuthorizer(), &authorizor_user_tier);

    if(authorizor_user_tier < request_user_tier){
        return RGW_ORG_TIER_NOT_ALLOWED;
    }
    
    return RGW_ORG_PERMISSION_ALLOWED;
}

std::string to_hex(const unsigned char *data, int len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < len; ++i) {
        ss << std::setw(2) << (unsigned int)data[i];
    }
    return ss.str();
}

std::string hmac_sha256(const std::string &key, const std::string &data) {
    unsigned char* digest = HMAC(EVP_sha256(), key.c_str(), key.length(), 
                                 reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), NULL, NULL);
    return to_hex(digest, SHA256_DIGEST_LENGTH);
}

std::string getSignature(const std::string &secret_key, const std::string &date, const std::string &region, 
                         const std::string &service, const std::string &string_to_sign) {
    std::string dateKey = hmac_sha256("AWS4" + secret_key, date);
    std::string dateRegionKey = hmac_sha256(dateKey, region);
    std::string dateRegionServiceKey = hmac_sha256(dateRegionKey, service);
    std::string signingKey = hmac_sha256(dateRegionServiceKey, "aws4_request");
    return hmac_sha256(signingKey, string_to_sign);
}