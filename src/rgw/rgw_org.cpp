//
// Created by root on 23. 12. 29.
//
#include "rgw_org.h"
#include "../rocksdb/include/rocksdb/db.h"
#include <sstream>

//TierDB RGWOrgTier::tierDb;

int DBManager::getData(const std::string& key, std::string &value){
    status = db->Get(rocksdb::ReadOptions(), key, &value);
    if(status.ok()){
        return 0;
    }
    else{
        return -1;
    }
}

int DBManager::putData(const std::string& key, const std::string& value){
    std::string exiting_value;
    rocksdb::Status s = db->Get(rocksdb::ReadOptions(), key, &exiting_value);
    if(s.ok()){
        return 2;
    }
    status = db->Put(rocksdb::WriteOptions(), key, value);
    if(status.ok()){
        return 0;
    }
    else{
        return -1;
    }
}

int DBManager::deleteData(const std::string& key){
    status = db->Delete(rocksdb::WriteOptions(), key);
    if(status.ok()){
        return 0;
    }
    else{
        return -1;
    }
}



int RGWOrg::putRGWOrg(DBManager& dbManager){
    std::string key = user + ":" + orgPermission->path;
    std::string value = authorizer + " "+ std::to_string(tier) + " " + std::to_string(orgPermission->r) + " " 
                        + std::to_string(orgPermission->w) + " " + std::to_string(orgPermission->x) + " " + std::to_string(orgPermission->g);
    return dbManager.putData(key, value);
}

int RGWOrg::deleteRGWOrg(aclDB& aclDB, std::string key){
    return aclDB.deleteData(key);
}

int RGWOrg::getFullMatchRgwOrg(aclDB &aclDB, std::string user, std::string path, RGWOrg *rgwOrg) {
    std::istringstream iss(path);
    std::string segment;
    std::string accumulatedPath;
    std::string key;
    int ret = -1;
    while (std::getline(iss, segment, '/')) {
        if (!segment.empty()) { // Skip empty segments (like the one before the first /)
            accumulatedPath += "/";
            
            accumulatedPath += segment;
            key = user + ":" + accumulatedPath;
            int cur_ret = getRGWOrg(aclDB,key, rgwOrg);
            if(cur_ret == 0){
                ret = 0;
            }
        }
    }
    return ret;
}

int RGWOrg::getRGWOrg(aclDB &aclDB, std::string key, RGWOrg *rgwOrg) {
    std::string value;
    int ret = aclDB.getData(key, value);
    if(ret < 0){
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
    try {
        std::getline(iss2, token2, ' ');
        rgwOrg->authorizer = token2;
        std::getline(iss2, token2, ' ');
        rgwOrg->tier = std::stoi(token2);
        std::getline(iss2, token2, ' ');
        rgwOrg->orgPermission->r = std::stoi(token2) != 0;  // 문자열을 bool로 변환
        std::getline(iss2, token2, ' ');
        rgwOrg->orgPermission->w = std::stoi(token2) != 0;  // 문자열을 bool로 변환
        std::getline(iss2, token2, ' ');
        rgwOrg->orgPermission->x = std::stoi(token2) != 0;  // 문자열을 bool로 변환
        std::getline(iss2, token2, ' ');
        rgwOrg->orgPermission->g = std::stoi(token2) != 0;  // 문자열을 bool로 변환
    } catch (const std::invalid_argument &e) {
        // 오류 처리 (예: 로그 출력, 오류 코드 반환 등)
        return -1;  // 또는 다른 오류 코드
    } catch (const std::out_of_range &e) {
        // 오류 처리
        return -1;  // 또는 다른 오류 코드
    }
    return ret;
}
