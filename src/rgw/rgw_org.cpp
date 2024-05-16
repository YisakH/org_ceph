//
// Created by root on 23. 12. 29.
//
#include "rgw_org.h"
#include <sstream>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <string>
#include <utility>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <queue>

// TierDB RGWOrgTier::tierDb;
bool OrgPermissionFlags::operator<=(const OrgPermissionFlags& other) const {
    return (get <= other.get) &&
           (put <= other.put) &&
           (gra <= other.gra) &&
           (del <= other.del);
}

bool OrgPermissionFlags::operator<(const OrgPermissionFlags& other) const {
    bool isStrictlyLess = false; // 진부분집합 여부를 판단하기 위한 변수
    if ((!other.get || get) && (!other.put || put) &&
        (!other.gra || gra) && (!other.del || del)) {
        // 모든 권한이 other에 포함되는지 확인
        isStrictlyLess = (get != other.get) || (put != other.put) ||
                         (gra != other.gra) || (del != other.del);
        // 적어도 하나의 권한이 other와 다르다면, 즉 진부분집합이라면 true
    }
    return isStrictlyLess;
}
OrgPermissionFlags::OrgPermissionFlags(){
    get = false;
    put = false;
    del = false;
    gra = false;
    path = "/";
}

// Helper function to trim slashes at the start and end of a string
std::string trimSlashes(const std::string& str) {
    size_t start = str.find_first_not_of('/');
    if (start == std::string::npos) return ""; // String consists only of slashes

    size_t end = str.find_last_not_of('/');
    return str.substr(start, end - start + 1);
}


std::string getObjectPath(const std::string& bucket_name, const std::string& object_name) {
    std::string trimmed_bucket = trimSlashes(bucket_name);
    std::string trimmed_object = trimSlashes(object_name);

    return "/" + trimmed_bucket + "/" + trimmed_object;
}

nlohmann::json RGWOrg::toJson() {
    nlohmann::json j;
    j["user"] = user;
    j["authorizer"] = authorizer;
    j["tier"] = tier;
    j["get"] = orgPermissionFlags->get;
    j["put"] = orgPermissionFlags->put;
    j["del"] = orgPermissionFlags->del;
    j["gra"] = orgPermissionFlags->gra;
    j["path"] = orgPermissionFlags->path;
    return j;
}

RGWOrg::RGWOrg(const std::string &user, const std::string &authorizer){
    this->user = user;
    this->authorizer = authorizer;

    RGWOrgTier::getUserTier(user, &this->tier);
    orgPermissionFlags = new OrgPermissionFlags();
}                                   

int DBManager::getData(const std::string &key, std::string &value)
{
    if(db == nullptr){
        reOpenDB();
    }
    
    status = db->Get(rocksdb::ReadOptions(), key, &value);
    std::string tmp = status.ToString();

    if (status.ok()){
        return 0;
    }
    else if (status.IsNotFound()){
        return -RGW_ORG_KEY_NOT_FOUND;
    }
    else{
        return -1;
    }
}

// DB에서 prefix로 시작하는 모든 데이터를 가져오는 함수
int DBManager::getAllPartialMatchData(const std::string& prefix, std::vector<std::pair<std::string, std::string>> &values){
    auto iter = db->NewIterator(rocksdb::ReadOptions());
    rocksdb::Status status;

    for (iter->Seek(prefix); iter->Valid() && iter->key().starts_with(prefix); iter->Next()) {
        values.push_back(std::make_pair(iter->key().ToString(), iter->value().ToString()));
        status = iter->status();
        if (!status.ok()) {
            //delete iter;
            return -RGW_DB_ERROR;
        }
    }
    //delete iter;

    if(values.size() > 0){
        return 0;
    }
    else{
        return -RGW_ORG_KEY_NOT_FOUND;
    }
}

int DBManager::putData(const std::string &key, const std::string &value)
{
    std::string exiting_value;
    if(db == nullptr){
        return -RGW_DB_ERROR;
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

int RGWOrgAnc::putAnc(std::string user, std::string anc)
{
    AncDB &ancDB = AncDB::getInstance();
    ancDB.putData(user, anc);

    if (ancDB.status.ok())
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

int RGWOrgAnc::getAnc(const std::string &user, std::string *anc)
{
    std::string value;
    AncDB &ancDB = AncDB::getInstance();

    ancDB.getData(user, value);

    if (ancDB.status.ok())
    {
        *anc = value;
        return 0;
    }
    else if (ancDB.status.IsNotFound())
    {
        return -RGW_ORG_KEY_NOT_FOUND;
    }
    else
    {
        return -1;
    }
}

int toRGWOrg(const std::string &key, const std::string &value, RGWOrg *rgwOrg)
{
    rgwOrg->orgPermissionFlags = new OrgPermissionFlags();

    std::istringstream iss(key);
    std::string token;

    std::getline(iss, token, ':');
    rgwOrg->user = token;
    std::getline(iss, token, ':');
    rgwOrg->orgPermissionFlags->path = token;

    std::istringstream iss2(value);
    std::string token2;
    try
    {
        std::getline(iss2, token2, ' ');
        rgwOrg->authorizer = token2;
        std::getline(iss2, token2, ' ');
        rgwOrg->tier = std::stoi(token2);
        std::getline(iss2, token2, ' ');
        rgwOrg->orgPermissionFlags->get = std::stoi(token2) != 0; // 문자열을 bool로 변환
        std::getline(iss2, token2, ' ');
        rgwOrg->orgPermissionFlags->put = std::stoi(token2) != 0; // 문자열을 bool로 변환
        std::getline(iss2, token2, ' ');
        rgwOrg->orgPermissionFlags->del = std::stoi(token2) != 0; // 문자열을 bool로 변환
        std::getline(iss2, token2, ' ');
        rgwOrg->orgPermissionFlags->gra = std::stoi(token2) != 0; // 문자열을 bool로 변환
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
    return 0;
}

int RGWOrg::putRGWOrg()
{// 여기서 orgPermission이 그냥 기본으로 들어오는 문제 발생.
    std::string key = user + ":" + orgPermissionFlags->path;
    std::string value = authorizer + " " + std::to_string(tier) + " " + std::to_string(orgPermissionFlags->get) + " " + std::to_string(orgPermissionFlags->put) + " " + std::to_string(orgPermissionFlags->del) + " " + std::to_string(orgPermissionFlags->gra);
    AclDB &aclDB = AclDB::getInstance();
    return aclDB.putData(key, value);
}

int RGWOrg::deleteRGWOrg(AclDB &aclDB, const std::string& key)
{
    return aclDB.deleteData(key);
}

int RGWOrg::getPartialMatchRgwOrg(const std::string& user, const std::string& path, RGWOrg *rgwOrg)
{ // TODO: 조금 더 효율적인 방법으로 수정 필요. 예를 들어 ret를 설정하지 말고 바로 return 해도 됨
    std::istringstream iss(path);
    std::string segment;
    std::string accumulatedPath = "/";
    std::string key = user + ":" + accumulatedPath;
    int ret = -1;

    // Check if the path is root "/" and handle it explicitly
    if (getFullMatchRGWOrg(key, rgwOrg) == 0) {
        ret = 0;
    }

    while (std::getline(iss, segment, '/'))
    {
        if (!segment.empty())
        {
            accumulatedPath += segment;
            key = user + ":" + accumulatedPath;
            int cur_ret = getFullMatchRGWOrg(key, rgwOrg);
            if (cur_ret == 0)
            {
                ret = 0;
                // Optionally break here if you only need the first match
                // break;
            }
            accumulatedPath += "/"; // 다음 세그먼트를 위해 '/' 추가
        }
    }
    return ret;
}


int RGWOrg::getFullMatchRGWOrg(const std::string& key, RGWOrg *rgwOrg)
{
    std::string value;
    AclDB &aclDB = AclDB::getInstance();
    std::string tmp = aclDB.getStatus().ToString();
    int ret = aclDB.getData(key, value);
    if (ret < 0)
    {
        // key 존재하지 않음
        return ret;
    }

    ret = toRGWOrg(key, value, rgwOrg);
    return ret;
}

// acl을 받아 오는 함수
// isFullMatch = true: 정확하게 일치하는 acl을 받아옴
// isFullMatch = false: 가장 근사하게 일치하는 acl을 받아옴 (path가 가장 긴 acl)
RGWOrg *getAcl(const std::string &user, const std::string &path, bool isFullMatch)
{
    auto *rgwOrg = new RGWOrg();
    int ret;
    if (isFullMatch)
        ret = RGWOrg::getFullMatchRGWOrg(user + ":" + path, rgwOrg);
    else{
        ret = RGWOrg::getPartialMatchRgwOrg(user, path, rgwOrg);
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

int putAcl(const std::string &user, const std::string &path, const std::string &authorizer, int tier, bool get, bool put, bool del, bool gra) {
    if (user == authorizer) {
        return 0; // Authorizer와 user가 같으면 권한 설정 불필요
    }

    auto &aclDB = AclDB::getInstance();
    if (!aclDB.getStatus().ok() && !aclDB.getStatus().IsNotFound()) {
        int ret = aclDB.reOpenDB();
        if (ret < 0) {
            return ret;
        }
    }

    auto rgwOrg = std::make_unique<RGWOrg>(user, authorizer, tier);
    auto orgPermission = std::make_unique<OrgPermissionFlags>(get, put, del, gra, path);
    rgwOrg->setOrgPermission(*orgPermission);

    RGWOrg *existingRgwOrg = getAcl(user, path);
    if (existingRgwOrg != nullptr) {
        if (existingRgwOrg->getTier() < tier) {
            delete existingRgwOrg;
            return -1; // 기존 권한의 티어가 더 낮으면 실패
        }
        delete existingRgwOrg;
    }

    // 기존 상위 경로에 대한 권한
    std::vector<std::pair<std::string, RGWOrg>> existingUpperPerms;
    AclDB::getSuperPathsForPrefix(user + ":" + path, existingUpperPerms);

    if (!existingUpperPerms.empty()) {
        if (existingUpperPerms[0].second.getTier() < tier) {
            return -RGW_ORG_TIER_NOT_ALLOWED; // 상위 권한의 티어가 더 낮으면 실패
        } else {
            aclDB.deleteData(existingUpperPerms[0].first); // 상위 권한 삭제
        }
    } else {
        // 기존 권한을 포함하는 경우
        int ret = aclDB.existPrefixAcl(user + ":" + path);
        if (ret != 0) {
            return ret; // 권한이 존재하지 않으면 반환
        }
    }

    std::string anc;
    getAnc(user, &anc);
    if (!anc.empty()) {
        // anc의 권한 조회
        RGWOrg *ancRgwOrg = getAcl(anc, path);
        if (ancRgwOrg != nullptr) {
            if (*orgPermission <= *ancRgwOrg->getOrgPermission()) {
                // 상위 유저의 권한이 충분하면 putAcl 수행하지 않음
            } else { // 상위 유저가 충분한 권한이 없는 경우
                int ret = putAcl(anc, path, authorizer, tier, get, put, del, gra);
                if (ret < 0) {
                    delete ancRgwOrg;
                    return ret;
                }
            }
            delete ancRgwOrg;
        } else {
            int ret = putAcl(anc, path, authorizer, tier, get, put, del, gra);
            if (ret < 0) {
                return ret;
            }
        }
    }

    int ret = rgwOrg->putRGWOrg();
    if (ret < 0) {
        return ret;
    }

    return 0;
}

int putAcl(RGWOrg &rgwOrg)
{
    return putAcl(
        rgwOrg.getUser(), 
        rgwOrg.getOrgPermission()->path, 
        rgwOrg.getAuthorizer(), 
        rgwOrg.getTier(), 
        rgwOrg.getOrgPermission()->get, 
        rgwOrg.getOrgPermission()->put, 
        rgwOrg.getOrgPermission()->del, 
        rgwOrg.getOrgPermission()->gra
    );
}

int deleteAcl(const std::string &request_user, const std::string &user, const std::string &path) {
    auto &dbm = AclDB::getInstance();

    // Check and re-open the database if necessary
    auto status = dbm.getStatus();
    if (!status.ok() && !status.IsNotFound()) {
        dbm.reOpenDB();
        status = dbm.getStatus();
        if (!status.ok()) {
            return -1; // Failed to re-open the database
        }
    }

    std::string key = user + ":" + path;
    RGWOrg *rgwOrg = getAcl(user, path, true);
    if (rgwOrg == nullptr) {
        return -RGW_ORG_KEY_NOT_FOUND;
    }

    int permTier = rgwOrg->getTier();
    int requestTier = 0;
    
    int ret = RGWOrgTier::getUserTier(request_user, &requestTier);
    if (ret == 0) {
        if (permTier <= requestTier) {
            return -RGW_ORG_TIER_NOT_ALLOWED;
        }
    } else {
        return -1; // Failed to get user tier
    }

    ret = dbm.deleteData(key);
    if (ret < 0) {
        return -1; // Failed to delete data
    } else {
        return 0; // Success
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

    RGWOrgTier::updateUserTier(user);

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
    if(ret == -RGW_ORG_KEY_NOT_FOUND){
        anc_tier = 0;
    }
    else if(ret < 0){
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

int RGWOrgDec::appendDecEdge(const std::string& user, const std::string& dec){
    std::vector<std::string> dec_list(1, dec);

    return appendDecEdge(user, dec_list);
}

int RGWOrgDec::appendDecEdge(const std::string& user, const std::vector<std::string>& dec_list){
    std::vector<std::string> existing_dec_list;
    int ret = getDec(user, &existing_dec_list);

    if(ret == -RGW_ORG_KEY_NOT_FOUND){
        ret = putDec(user, dec_list);
        if (ret < 0){
            return ret;
        }
    }
    else if(ret < 0){
        return ret;
    }
    else{
        for(const auto& dec : dec_list){
            // std::find를 사용하여 existing_dec_list 내에서 dec를 검색
            if(std::find(existing_dec_list.begin(), existing_dec_list.end(), dec) == existing_dec_list.end()){
                existing_dec_list.push_back(dec);
            }
        }
        ret = putDec(user, existing_dec_list);
    }
    return ret;
}


bool RGWOrgDec::existDecEdge(const std::string& user, const std::string& dec){
    std::vector<std::string> existing_dec_list;
    int ret = getDec(user, &existing_dec_list);

    if(ret == -RGW_ORG_KEY_NOT_FOUND){
        return false;
    }

    if (std::find(existing_dec_list.begin(), existing_dec_list.end(), dec) == existing_dec_list.end()) {
            // New user is not a descendant yet, add to the list.
            return false;
    }
    return true;
}

int RGWOrgDec::deleteDecEdge(const std::string& user, const std::string& dec){
    std::vector<std::string> existing_dec_list;
    int ret = getDec(user, &existing_dec_list);

    if(ret < 0){
        // 오류 처리: 키를 찾을 수 없거나 다른 오류가 발생한 경우
        return ret;
    }

    // dec가 존재하는지 확인
    auto it = std::find(existing_dec_list.begin(), existing_dec_list.end(), dec);
    if(it == existing_dec_list.end()){
        // dec가 리스트에 없음
        return -RGW_ORG_KEY_NOT_FOUND;
    }

    // dec를 리스트에서 제거
    existing_dec_list.erase(it);

    // 업데이트된 리스트를 데이터베이스에 저장
    ret = putDec(user, existing_dec_list);
    return ret; // 성공적으로 제거되었거나 발생한 오류를 반환
}

std::string RGWOrg::toString() {
    return "user: " + user + ", authorizer: " + authorizer + ", tier: " + std::to_string(tier) + ", get: " + std::to_string(orgPermissionFlags->get) + ", put: " + std::to_string(orgPermissionFlags->put) + ", del: " + std::to_string(orgPermissionFlags->del) + ", gra: " + std::to_string(orgPermissionFlags->gra) + ", path: " + orgPermissionFlags->path;
};


int RGWOrgDec::decListToString(std::vector<std::string> &dec_list, std::string *dec_list_str){
    *dec_list_str = "";
    for (size_t i = 0; i < dec_list.size(); ++i){
        *dec_list_str += dec_list[i];
        if (i < dec_list.size() - 1){
            *dec_list_str += ",";
        }
    }
    return 0;
}

int RGWOrgDec::getDec(const std::string& user, std::vector<std::string> *dec_list){
    std::string value = "";
    DecDB &decDB = DecDB::getInstance();

    decDB.getData(user, value);

    if(value == ""){
       return -RGW_ORG_KEY_NOT_FOUND; 
    }
    else if(decDB.status.ok()){
        *dec_list = str_split_to_vec(value);
        return 0;
    } else if(decDB.status.IsNotFound()){
        return -RGW_ORG_KEY_NOT_FOUND;
    }
    else{
        return -1;
    }
}

int RGWOrgDec::putDec(std::string user, std::vector<std::string> dec_list){
    DecDB &decDB = DecDB::getInstance();
    TierDB &tierDB = TierDB::getInstance();

    std::string dec_list_string = str_join(dec_list);

    int ret = decDB.putData(user, dec_list_string);
    if(ret < 0){
        return ret;
    }

    int tier;
    ret = tierDB.getData(user, tier);
    if(ret < 0){
        return ret;
    }

    for (auto dec : dec_list){
        tierDB.putData(dec, tier + 1);
    }
    return 0;
}

int RGWOrgDec::deleteAllDec(std::string user){
    DecDB &decDB = DecDB::getInstance();
    decDB.deleteData(user);

    if(decDB.status.ok()){
        return 0;
    }
    else{
        return -1;
    }
}

int RGWOrgDec::updateDec(std::string user, std::vector<std::string> dec_list){
    DecDB &decDB = DecDB::getInstance();
    std::string dec_list_string = str_join(dec_list);

    decDB.deleteData(user);
    if(!decDB.status.ok()){
        return -1;
    }

    decDB.putData(user, dec_list_string);

    if(decDB.status.ok()){
        return 0;
    }
    else{
        return -1;
    }
}

int checkAclRead(const std::string& request_user, const std::string& target_user)
{
    if(request_user == "root"){
        return -RGW_ORG_PERMISSION_ALLOWED;
    }
    int request_user_tier = -1, target_user_tier = -1;
    int ret = -1;
    ret = RGWOrgTier::getUserTier(request_user, &request_user_tier);
    if(ret < 0){ // request user의 tier가 존재하지 않음
        return -1;
    }
    ret = RGWOrgTier::getUserTier(target_user, &target_user_tier);
    if(ret < 0){
        return -1;
    }

    if(request_user_tier > target_user_tier){
        return -RGW_ORG_TIER_NOT_ALLOWED;
    }

    return -RGW_ORG_PERMISSION_ALLOWED;
}

int checkAclWrite(const std::string& request_user, const std::string& target_user, const std::string& path, const std::string& authorizer, int tier, bool get, bool put, bool del, bool gra){
    int request_user_tier = -1, target_user_tier = -1;
    int ret = -1;
    ret = RGWOrgTier::getUserTier(request_user, &request_user_tier);
    if(ret < 0){ // request user의 tier가 존재하지 않음
        return -RGW_ORG_KEY_NOT_FOUND;
    }
    ret = RGWOrgTier::getUserTier(target_user, &target_user_tier);
    if(ret < 0){
        return -RGW_ORG_KEY_NOT_FOUND;
    }

    if(request_user_tier > target_user_tier){
        return -RGW_ORG_TIER_NOT_ALLOWED;
    }

    RGWOrg * request_user_org = getAcl(request_user, path);
    //std::string tmp = request_user_org->toString();
    if(request_user_org == nullptr || !request_user_org->getOrgPermission()->gra){ // grant 권한이 없는 경우
        return -RGW_ORG_PERMISSION_NOT_ALLOWED;
    }


    OrgPermissionFlags orgPermission(get, put, del, gra, path);
    std::string anc_user;
    ret = getAnc(target_user, &anc_user);

    if(anc_user == request_user){
        return -RGW_ORG_PERMISSION_ALLOWED;
    }

    RGWOrg *rgwOrg = getAcl(anc_user, path);

    if(rgwOrg != nullptr){
        OrgPermissionFlags *ancPermission = rgwOrg->getOrgPermission();

        if(ancPermission != nullptr && orgPermission < *ancPermission){ // anc의 권한이 요청한 권한을 포함하지 못하는 경우
            return -RGW_ORG_PERMISSION_NOT_ALLOWED;
        }

        int authorizer_user_tier;
        ret = getTier(rgwOrg->getAuthorizer(), &authorizer_user_tier);

        if(authorizer_user_tier < request_user_tier){
            return -RGW_ORG_TIER_NOT_ALLOWED;
        }
    }
    
    return -RGW_ORG_PERMISSION_ALLOWED;
}

int checkHAclObjRead(const std::string& request_user, const std::string& bucket_name, const std::string& object_name){
    const std::string path = getObjectPath(bucket_name, object_name);
    RGWOrg *rgwOrg = getAcl(request_user, path, false);
    if(rgwOrg == nullptr){
        return -RGW_ORG_PERMISSION_ALLOWED;
    }
    
    if(rgwOrg->getOrgPermission()->get){
        return -RGW_ORG_PERMISSION_ALLOWED;
    }
    else{
        return -RGW_ORG_PERMISSION_NOT_ALLOWED;
    }
}

int checkHAclObjWrite(const std::string& request_user, const std::string& bucket_name, const std::string& object_name){
    const std::string path = getObjectPath(bucket_name, object_name);
    RGWOrg *rgwOrg = getAcl(request_user, path, false);
    if(rgwOrg == nullptr){
        return -RGW_ORG_KEY_NOT_FOUND;
    }
    
    if(rgwOrg->getOrgPermission()->put){
        return -RGW_ORG_PERMISSION_ALLOWED;
    }
    else{
        return -RGW_ORG_PERMISSION_NOT_ALLOWED;
    }

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
    return to_hex(digest, 32);
}

std::string getSignature(const std::string &secret_key, const std::string &date, const std::string &region, 
                         const std::string &service, const std::string &string_to_sign) {
    std::string dateKey = hmac_sha256("AWS4" + secret_key, date);
    std::string dateRegionKey = hmac_sha256(dateKey, region);
    std::string dateRegionServiceKey = hmac_sha256(dateRegionKey, service);
    std::string signingKey = hmac_sha256(dateRegionServiceKey, "aws4_request");
    return hmac_sha256(signingKey, string_to_sign);
}

std::string sha256_hex(const std::string &data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for(unsigned char i : hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)i;
    }
    return ss.str();
}

std::string generateCanonicalHeaders(const std::string &hostHeader, const std::string &amzDate) {
    std::string canonicalHeaders = "host:" + hostHeader + "\n" + "del-amz-content-sha256:" + sha256_hex("") + "\n" + "del-amz-date:" + amzDate + "\n";
    return canonicalHeaders;
}

std::string generatePayloadHash(const std::string &payload) {
    return sha256_hex(payload); // If the payload is empty, sha256_hex("") will be called.
}

std::string getAuthHeader(const std::string &access_key, const std::string &secret_key, const std::string &host, const std::string &method, const std::string &canonicalUri, const std::string &canonicalQueryString, 
                        const std::string &signedHeaders){
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);

    struct tm *parts = std::localtime(&now_c);

    std::ostringstream oss;
    oss << std::put_time(parts, "%Y%m%d");
    
    std::string date = oss.str();
    std::string region = "us-east-1";
    std::string service = "s3";

    std::string canonicalHeaders = generateCanonicalHeaders(host, date);
    std::string payloadHash = generatePayloadHash("");

    std::string string_to_sign = method + "\n" + 
                                 canonicalUri + "\n" + 
                                 canonicalQueryString + "\n" + 
                                 canonicalHeaders + "\n" + 
                                 signedHeaders + "\n" + 
                                 payloadHash;

    std::string signature = getSignature(secret_key, date, region, service, string_to_sign);

    return createAuthHeader(access_key, date, region, service, signedHeaders, signature);
}

std::string createAuthHeader(const std::string& accessKey, const std::string& date, 
                             const std::string& region, const std::string& service, 
                             const std::string& signedHeaders, const std::string& signature) {
    // Credential 구성
    std::string credential = accessKey + "/" + date + "/" + region + "/" + service + "/aws4_request";

    // 인증 헤더 구성
    std::string authHeader = "AWS4-HMAC-SHA256 Credential=" + credential + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature;
    
    return authHeader;
}

std::vector<std::string> str_split_to_vec(const std::string& s){
    std::vector<std::string> result;
    std::istringstream iss(s);
    std::string token;
    while(std::getline(iss, token, ',')){
        result.push_back(token);
    }
    return result;
}


std::string str_join(const std::vector<std::string>& v){
    std::string result;
    for(size_t i = 0; i < v.size(); i++){
        result += v[i];
        if(i != v.size() - 1){
            result += ",";
        }
    }
    return result;
}

int RGWOrgUser::putUser(std::string user, std::string anc, std::vector<std::string> dec_list){
    int ret = -1;

    ret = deleteUser(user);

    if (anc != ""){ // anc가 존재하는 경우
        int anc_tier = -1;
        ret = RGWOrgTier::getUserTier(anc, &anc_tier);
        // user -> anc 등록
        ret = putAnc(user, anc);
        if(ret < 0){
            return ret;
        }

        // anc -> user 등록
        ret = RGWOrgDec::appendDecEdge(anc, user);
        if(ret < 0){
            return ret;
        }

        // user tier 등록
        ret = RGWOrgTier::putUserTier(user, anc_tier + 1);
    }
    else{ // anc가 존재하지 않는 경우

        // user tier 등록
        ret = RGWOrgTier::putUserTier(user, 0);
        if(ret < 0){
            return ret;
        }
    }


    if(dec_list.size() > 0){
        // TODO: dec가 이미 존재하는 경우에 존재하는 dec를 찾고 user의 자손이 되도록 설정해야 할 필요 있음
        ret = RGWOrgDec::appendDecEdge(user, dec_list);
        if(ret < 0){
            return ret;
        }

        for (auto dec : dec_list){
            std::string anc_dec = "";
            ret = getAnc(dec, &anc_dec);
            if(ret == 0){
                ret = RGWOrgDec::deleteDecEdge(anc_dec, dec);
                if(ret < 0){
                    return ret;
                }
            }

            ret = putAnc(dec, user);
            if(ret < 0){
                return ret;
            }
        }

        ret = RGWOrgTier::updateUserTier(user);
    }
    //RGWOrg *blackRgwOrg = new RGWOrg(user, anc);
    //ret = putAcl(*blackRgwOrg);
    return 0;
}

int RGWOrgUser::deleteUserRelation(const std::string &user, const std::vector<std::string> &dec_list){
    std::vector<std::string> existing_dec_list;

    int ret = RGWOrgDec::getDec(user, &existing_dec_list);
    if(ret < 0){
        return ret;
    }

    for(auto dec : dec_list){
        auto it = std::find(existing_dec_list.begin(), existing_dec_list.end(), dec);
        if(it != existing_dec_list.end()){
            existing_dec_list.erase(it);
        }
    }
}

int RGWOrgUser::putUser(std::string user, std::string anc, std::string dec_list_str){
    std::vector<std::string> dec_list = str_split_to_vec(dec_list_str);
    return putUser(user, anc, dec_list);
}

int RGWOrgUser::deleteUser(const std::string &user) {
    std::string anc = "";
    int anc_ret = getAnc(user, &anc);

    std::vector<std::string> dec_list;
    int dec_ret = RGWOrgDec::getDec(user, &dec_list);

    if(anc_ret == -RGW_ORG_KEY_NOT_FOUND && dec_ret == -RGW_ORG_KEY_NOT_FOUND) {
        return deleteOnlyUser(user);
    }
    if(anc_ret == -RGW_ORG_KEY_NOT_FOUND) {
        return deleteWithDescendants(user, dec_list);
    }
    if(dec_ret == -RGW_ORG_KEY_NOT_FOUND) {
        return deleteWithAncestor(user);
    }
    return deleteWithBoth(user, anc, dec_list);
}

int RGWOrgUser::deleteOnlyUser(const std::string &user) {
    return RGWOrgTier::deleteUserTier(user);
}

int RGWOrgUser::deleteWithDescendants(const std::string &user, const std::vector<std::string> &dec_list) {
    for (const auto &dec : dec_list) {
        int ret = RGWOrgAnc::deleteAnc(dec);
        if(ret < 0) return ret;
    }
    int ret = RGWOrgDec::deleteAllDec(user);
    if(ret < 0) return ret;

    return RGWOrgTier::deleteUserTier(user);
}

int RGWOrgUser::deleteWithAncestor(const std::string &user) {
    int ret1 = RGWOrgAnc::deleteAnc(user);
    int ret2 = RGWOrgTier::deleteUserTier(user);
    if(ret1 != 0) return ret1;
    else if(ret2 != 0) return ret2;
    else return 0;
}

int RGWOrgUser::deleteWithBoth(const std::string &user, const std::string &anc, const std::vector<std::string> &dec_list) {
    for (const auto &dec : dec_list) {
        int ret = RGWOrgAnc::putAnc(dec, anc);
        if(ret < 0) return ret;
    }
    // 삭제하고자 하는 유저를 부모의 자식 목록에서 제거
    int ret = RGWOrgDec::deleteDecEdge(anc, user);
    if(ret < 0) return ret;

    // 삭제하고자 하는 유저의 자식 목록을 부모의 자식 목록에 추가
    ret = RGWOrgDec::appendDecEdge(anc, dec_list);
    if(ret < 0) return ret;

    // 여기서 에러 발생하는 것 같은데 주석처리 후 문제 없으면 지워야함
    //RGWOrgDec::putDec(anc, dec_list);
    //if(ret < 0) return ret;

    ret = RGWOrgDec::deleteAllDec(user);
    if(ret < 0) return ret;

    ret = RGWOrgAnc::deleteAnc(user);
    if(ret < 0) return ret;

    ret = RGWOrgTier::deleteUserTier(user);
    if(ret < 0) return ret;

    RGWOrgTier::updateUserTier(anc);

    return 0;
}

int TierDB::putData(const std::string& key, const int &value){
    status = db->Put(rocksdb::WriteOptions(), key, std::to_string(value));
    if (status.ok())
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

int TierDB::getData(const std::string& key, int &value){
    std::string str_value;
    status = db->Get(rocksdb::ReadOptions(), key, &str_value);
    if(status.IsNotFound()){
        return -RGW_ORG_KEY_NOT_FOUND;
    }

    value = std::stoi(str_value);
    if (status.ok())
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

int RGWOrgTier::getUserTier(std::string user, int *tier){
    int value;
    TierDB &tierDb = TierDB::getInstance();
    tierDb.getData(user, value);

    if(tierDb.status.ok()){
        *tier = value;
        return 0;
    }
    else if(tierDb.status.IsNotFound()){
        return -RGW_ORG_KEY_NOT_FOUND;
    }
    else{
        return -1;
    }
}

int RGWOrgTier::updateUserTier(const std::string &start_user){
    int start_user_tier;
    int ret = getUserTier(start_user, &start_user_tier);
    if(ret < 0){
        return ret;
    }

    std::vector<std::string> dec_list;
    ret = RGWOrgDec::getDec(start_user, &dec_list);
    if(ret < 0){
        return ret;
    }

    for(auto dec : dec_list){
        int dec_tier = start_user_tier + 1;
        
        ret = putUserTier(dec, dec_tier);
        if(ret < 0){
            return ret;
        }
        ret = updateUserTier(dec);
        if(ret < 0 && ret != RGW_ORG_KEY_NOT_FOUND){
            return ret;
        }
    }
    return 0;
}

bool validateRGWOrgPermission(std::string user, std::string path, bool get, bool put, bool del, bool gra){
    RGWOrg *rgwOrg = getAcl(user, path);
    if(rgwOrg == nullptr){
        return false;
    }
    OrgPermissionFlags *orgPermission = rgwOrg->getOrgPermission();

    // compare orgPermission and get, put, del, gra
    // if request user has more permission than input get, put, del, gra, return true
    
    if ((get && !orgPermission->get) ||
        (put && !orgPermission->put) ||
        (del && !orgPermission->del) ||
        (gra && !orgPermission->gra)) {
        return false;
    }

    return true;
}

int AclDB::existPrefixAcl(const std::string& prefix){
    std::vector<std::pair<std::string, std::string>> values;
    int ret = getAllPartialMatchData(prefix, values);
    if(ret == -1){
        return ret;
    }else if(ret == -RGW_ORG_KEY_NOT_FOUND){
        return 0;
    }
    return values.size() > 0 ? 1 : 0;
}

// 접두사 일치하는 모든 acl을 가져오는 함수
int AclDB::getAllPartialMatchAcl(const std::string& prefix, std::vector<std::pair<std::string, RGWOrg>> &values){
    std::vector<std::pair<std::string, std::string>> str_values;
    int ret = getAllPartialMatchData(prefix, str_values);
    if (ret < 0){
        return ret;
    }

    for (auto &pair : str_values) {
        std::string key = pair.first;
        std::string value = pair.second;
        RGWOrg *rgwOrg = new RGWOrg();
        ret = toRGWOrg(key, value, rgwOrg);

        values.push_back(std::make_pair(key, *rgwOrg));
    }
    return 0;
}

// getPartialMatchRgwOrg 함수와 겹치는 부분이 있는 것 같음
// TODO: getPartialMatchRgwOrg 함수와 통합
int AclDB::getSuperPathsForPrefix(const std::string& userPrefix, std::vector<std::pair<std::string, RGWOrg>> &values) {
    std::istringstream iss(userPrefix);
    std::string segment;
    std::string accumulatedPath;
    std::string userPathPrefix = userPrefix.substr(0, userPrefix.find(":") + 1); // 사용자 이름 추출 (예: "user3:")
    bool isFirstSegment = true;

    // accumulatedPath 초기화
    accumulatedPath = userPathPrefix;

    while (std::getline(iss, segment, '/')) {
        if (!isFirstSegment && !segment.empty()) {
            accumulatedPath += "/" + segment;
        }
        isFirstSegment = false;

        // 사용자 이름을 포함한 전체 경로 생성
        std::string fullPath = accumulatedPath;

        RGWOrg rgwOrg;
        //AclDB &aclDB = AclDB::getInstance();
        // 사용자 이름을 포함한 경로로 getFullMatchRGWOrg 함수 호출
        int ret = RGWOrg::getFullMatchRGWOrg(fullPath, &rgwOrg);
        if (ret == 0) {  // 성공적으로 rgwOrg 객체를 가져온 경우에만 추가
            values.push_back(std::make_pair(fullPath, rgwOrg));
        }
    }

    return values.empty() ? RGW_ORG_KEY_NOT_FOUND : 0;
}

int RGWOrgDec::getRGWOrgDecTree(const std::string &start_user, nlohmann::json &j) {
    std::queue<std::string> q;
    std::map<std::string, nlohmann::json> j_map;
    std::vector<std::string> visit_order;
    int id = 0; // 노드에 고유 ID 할당을 위한 변수

    q.push(start_user);

    while (!q.empty()) {
        std::string cur_name = q.front();
        q.pop();

        std::vector<std::string> dec_list;
        int ret = RGWOrgDec::getDec(cur_name, &dec_list);

        // 현재 노드에 대한 JSON 객체 생성
        nlohmann::json cur_j = {
            {"name", cur_name}, 
            {"id", id++}, 
            {"children", nlohmann::json::array()}, 
            {"permission", nlohmann::json::array()}
        };

        std::vector<std::pair<std::string, RGWOrg>> values;
        AclDB &acl_db = AclDB::getInstance();
        ret = acl_db.getAllPartialMatchAcl(cur_name + ":", values);

        for (auto &pair : values) {
            auto &rgwOrg = pair.second;
            cur_j["permission"].push_back(rgwOrg.toJson());
        }

        // 자식 노드 이름을 바탕으로 자식 노드의 JSON 객체를 children에 추가
        for (auto &dec : dec_list) {
            // 자식 노드에 대한 참조를 먼저 생성합니다.
            nlohmann::json child_ref = {{"name", dec}, {"id", id++}, {"children", nlohmann::json::array()}, {"permission", nlohmann::json::array()}};
            cur_j["children"].push_back(child_ref); // 자식 노드 참조를 children에 추가
            q.push(dec); // 큐에 자식 노드 이름을 추가하여 나중에 처리
        }
        j_map[cur_name] = cur_j; // 현재 노드를 맵에 추가
        visit_order.push_back(cur_name); // 방문 순서를 기록
    }

    // 노드를 역순으로 방문하며 부모 노드에 대한 참조를 추가
    for (auto it = visit_order.rbegin(); it != visit_order.rend(); ++it) {
        const std::string &cur_name = *it;
        std::vector<nlohmann::json> new_children;
        for (auto &child : j_map[cur_name]["children"]) {
            const std::string &child_name = child["name"];
            if (j_map.find(child_name) != j_map.end()) {
                new_children.push_back(j_map[child_name]);
            }
        }
        j_map[cur_name]["children"] = new_children;
    }

    // // 최종적으로 j_map의 모든 노드를 순회하며 children을 업데이트
    // for (auto &pair : j_map) {
    //     auto &node = pair.second;
    //     std::vector<nlohmann::json> new_children;
    //     for (auto &child : node["children"]) {
    //         const std::string &name = child["name"];
    //         if (j_map.find(name) != j_map.end()) {
    //             // j_map에서 찾은 노드로 new_children을 업데이트
    //             new_children.push_back(j_map[name]);
    //         }
    //     }
    //     // children을 새로운 배열로 업데이트
    //     node["children"] = new_children;
    // }

    j = j_map[start_user]; // 최종 JSON 객체를 설정
    return 0;
}

std::string makeResponse(int status){
    switch (status)
    {
    case RGW_ORG_TIER_NOT_ALLOWED:
        return "RGW_HBAC_TIER_NOT_ALLOWED";
    case RGW_ORG_PERMISSION_NOT_ALLOWED:
        return "RGW_HBAC_PERMISSION_NOT_ALLOWED";
    case RGW_ORG_PERMISSION_ALLOWED:

        return "RGW_HBAC_PERMISSION_ALLOWED";
    case RGW_ORG_KEY_NOT_FOUND:
        return "RGW_HBAC_KEY_NOT_FOUND";

    case RGW_DB_ERROR:
        return "RGW_DB_ERROR";
    default:
        return "UNKNOWN";
    }
}

// 유저가 해당 권한이 있는지 검사
int checkAclPermission(const std::string& request_user, 
                    const bool get, 
                    const bool put, 
                    const bool del, 
                    const bool gra, 
                    const std::string& path){
    RGWOrg *rgwOrg = getAcl(request_user, path);
    if(rgwOrg == nullptr){
        return -RGW_ORG_KEY_NOT_FOUND;
    }

    // 특정 권한을 요청했는데 유저가 그 권한이 없으면 에러
    if((get && !rgwOrg->getOrgPermission()->get) ||
       (put && !rgwOrg->getOrgPermission()->put) ||
       (del && !rgwOrg->getOrgPermission()->del) ||
       (gra && !rgwOrg->getOrgPermission()->gra)){
        return -RGW_HBAC_NO_PERMISSION;
    }
    return 0;
}