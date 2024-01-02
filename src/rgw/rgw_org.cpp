//
// Created by root on 23. 12. 29.
//
#include "rgw_org.h"
#include "../rocksdb/include/rocksdb/db.h"
#include <sstream>


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
    std::string value = authorizer + " "+ std::to_string(tier) + " " + std::to_string(orgPermission->r) + " " 
                        + std::to_string(orgPermission->w) + " " + std::to_string(orgPermission->x) + " " + std::to_string(orgPermission->g);
    return dbManager.putData(user, value);
}

int RGWOrg::getRGWOrg(DBManager &dbManager, std::string user, RGWOrg *rgwOrg) {
    std::string value;
    int ret = dbManager.getData(user, value);
    if (ret == 0) {
        std::istringstream iss(value);
        std::string token;

        try {
            std::getline(iss, token, ' ');
            rgwOrg->authorizer = token;
            std::getline(iss, token, ' ');
            rgwOrg->tier = std::stoi(token);
            std::getline(iss, token, ' ');
            rgwOrg->orgPermission->r = std::stoi(token) != 0;  // 문자열을 bool로 변환
            std::getline(iss, token, ' ');
            rgwOrg->orgPermission->w = std::stoi(token) != 0;  // 문자열을 bool로 변환
            std::getline(iss, token, ' ');
            rgwOrg->orgPermission->x = std::stoi(token) != 0;  // 문자열을 bool로 변환
            std::getline(iss, token, ' ');
            rgwOrg->orgPermission->g = std::stoi(token) != 0;  // 문자열을 bool로 변환
        } catch (const std::invalid_argument &e) {
            // 오류 처리 (예: 로그 출력, 오류 코드 반환 등)
            return -1;  // 또는 다른 오류 코드
        } catch (const std::out_of_range &e) {
            // 오류 처리
            return -1;  // 또는 다른 오류 코드
        }
    }
    return ret;
}
