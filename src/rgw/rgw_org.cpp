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
    return (!other.r || r) &&
           (!other.w || w) &&
           (!other.g || g) &&
           (!other.x || x);
}
bool OrgPermissionFlags::operator<(const OrgPermissionFlags& other) const {
    bool isStrictlyLess = false; // 진부분집합 여부를 판단하기 위한 변수
    if ((!other.r || r) && (!other.w || w) &&
        (!other.g || g) && (!other.x || x)) {
        // 모든 권한이 other에 포함되는지 확인
        isStrictlyLess = (r != other.r) || (w != other.w) ||
                         (g != other.g) || (x != other.x);
        // 적어도 하나의 권한이 other와 다르다면, 즉 진부분집합이라면 true
    }
    return isStrictlyLess;
}
OrgPermissionFlags::OrgPermissionFlags(){
    r = false;
    w = false;
    x = false;
    g = false;
    path = "/";
}


std::string getObjectPath(const std::string& bucket_name, const std::string& object_name){
    return "/" + bucket_name + "/" + object_name;
}

nlohmann::json RGWOrg::toJson() {
    nlohmann::json j;
    j["user"] = user;
    j["authorizer"] = authorizer;
    j["tier"] = tier;
    j["r"] = orgPermission->r;
    j["w"] = orgPermission->w;
    j["x"] = orgPermission->x;
    j["g"] = orgPermission->g;
    j["path"] = orgPermission->path;
    return j;
}

RGWOrg::RGWOrg(const std::string &user, const std::string &authorizer){
    this->user = user;
    this->authorizer = authorizer;

    RGWOrgTier::getUserTier(user, &this->tier);
    orgPermission = new OrgPermissionFlags();
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

int DBManager::getAllPartialMatchData(const std::string& prefix, std::vector<std::pair<std::string, std::string>> &values){
    auto iter = db->NewIterator(rocksdb::ReadOptions());

    for (iter->Seek(prefix); iter->Valid() && iter->key().starts_with(prefix); iter->Next()) {
        values.push_back(std::make_pair(iter->key().ToString(), iter->value().ToString()));
    }

    if(values.size() > 0){
        return 0;
    }
    else{
        return -1;
    }
}

int DBManager::putData(const std::string &key, const std::string &value)
{
    std::string exiting_value;
    if(db == nullptr){
        return -1;
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
        return RGW_ORG_KEY_NOT_FOUND;
    }
    else
    {
        return -1;
    }
}

int toRGWOrg(const std::string &key, const std::string &value, RGWOrg *rgwOrg)
{
    rgwOrg->orgPermission = new OrgPermissionFlags();

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
    return 0;
}

int RGWOrg::putRGWOrg(DBManager &dbManager)
{// 여기서 orgPermission이 그냥 기본으로 들어오는 문제 발생.
    std::string key = user + ":" + orgPermission->path;
    std::string value = authorizer + " " + std::to_string(tier) + " " + std::to_string(orgPermission->r) + " " + std::to_string(orgPermission->w) + " " + std::to_string(orgPermission->x) + " " + std::to_string(orgPermission->g);
    return dbManager.putData(key, value);
}

int RGWOrg::deleteRGWOrg(aclDB &aclDB, const std::string& key)
{
    return aclDB.deleteData(key);
}

int RGWOrg::getPartialMatchRgwOrg(aclDB &aclDB, const std::string& user, const std::string& path, RGWOrg *rgwOrg)
{
    std::istringstream iss(path);
    std::string segment;
    std::string accumulatedPath = "/";
    std::string key = user + ":" + accumulatedPath;
    int ret = -1;

    // Check if the path is root "/" and handle it explicitly
    if (getFullMatchRGWOrg(aclDB, key, rgwOrg) == 0) {
        ret = 0;
    }

    while (std::getline(iss, segment, '/'))
    {
        if (!segment.empty())
        {
            accumulatedPath += segment;
            key = user + ":" + accumulatedPath;
            int cur_ret = getFullMatchRGWOrg(aclDB, key, rgwOrg);
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


int RGWOrg::getFullMatchRGWOrg(aclDB &aclDB, const std::string& key, RGWOrg *rgwOrg)
{
    std::string value;
    int ret = aclDB.getData(key, value);
    if (ret < 0)
    {
        // key 존재하지 않음
        return ret;
    }

    ret = toRGWOrg(key, value, rgwOrg);
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
    auto *rgwOrg = new RGWOrg();
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
    auto *orgPermission = new OrgPermissionFlags(r, w, x, g, path);
    rgwOrg->setOrgPermission(*orgPermission);

    RGWOrg *existingRgwOrg = getAcl(user, path);
    if(existingRgwOrg != nullptr){
        int defaultTier = existingRgwOrg->getTier();
        if(defaultTier < tier){ // 기존 권한이 존재하지 않거나 기존 권한의 티어가 새로운 권한의 티어보다 작은(높은) 경우
            return -1;
        }
    }

    // 기존 상위 경로에 대한 권한
    std::vector<std::pair<std::string, RGWOrg>> existingUpperPerms;
    aclDB::getSuperPathsForPrefix(user + ":" + path, existingUpperPerms);
    for (auto &perms : existingUpperPerms) {
        std::string key = perms.first;
        RGWOrg rgwOrg = perms.second;
        if(rgwOrg.getTier() < tier){
            return -1;
        }
    }

    int ret = rgwOrg->putRGWOrg(dbm);
    if (ret < 0)
    {
        return ret;
    }

    std::string anc = "";
    getAnc(user, &anc);
    if(anc != ""){
        ret = putAcl(anc, path, authorizer, tier, r, w, x, g);
        if(ret < 0){
            return ret;
        }
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
        rgwOrg.getOrgPermission()->r, 
        rgwOrg.getOrgPermission()->w, 
        rgwOrg.getOrgPermission()->x, 
        rgwOrg.getOrgPermission()->g
    );
}

int deleteAcl(const std::string &user, const std::string &path)
{
    auto &dbm = aclDB::getInstance();
    if (!dbm.getStatus().ok() && !dbm.getStatus().IsNotFound())
    {
        dbm.reOpenDB();
        return -1;
    }

    std::string key = user + ":" + path;
    int ret = RGWOrg::deleteRGWOrg(dbm, key);
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
    if(ret == RGW_ORG_KEY_NOT_FOUND){
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
    int ret = appendDecEdge(user, dec_list);
    return ret;
}

int RGWOrgDec::appendDecEdge(const std::string& user, const std::vector<std::string>& dec_list){
    std::vector<std::string> existing_dec_list;
    int ret = getDec(user, &existing_dec_list);

    if(ret == RGW_ORG_KEY_NOT_FOUND){
        ret = putDec(user, dec_list);
        if (ret < 0){
            return ret;
        }
    }
    else if(ret < 0){
        return ret;
    }
    else{
        for(auto dec : dec_list){
            if(!existDecEdge(user, dec)){
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

    if(ret == RGW_ORG_KEY_NOT_FOUND){
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
        return RGW_ORG_KEY_NOT_FOUND;
    }

    // dec를 리스트에서 제거
    existing_dec_list.erase(it);

    // 업데이트된 리스트를 데이터베이스에 저장
    ret = putDec(user, existing_dec_list);
    return ret; // 성공적으로 제거되었거나 발생한 오류를 반환
}

std::string RGWOrg::toString() {
    return "user: " + user + ", authorizer: " + authorizer + ", tier: " + std::to_string(tier) + ", r: " + std::to_string(orgPermission->r) + ", w: " + std::to_string(orgPermission->w) + ", x: " + std::to_string(orgPermission->x) + ", g: " + std::to_string(orgPermission->g) + ", path: " + orgPermission->path;
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
    std::string value;
    DecDB &decDB = DecDB::getInstance();

    decDB.getData(user, value);

    if(decDB.status.ok()){
        *dec_list = str_split_to_vec(value);
        return 0;
    } else if(decDB.status.IsNotFound()){
        return RGW_ORG_KEY_NOT_FOUND;
    }
    else{
        return -1;
    }
}

int RGWOrgDec::putDec(std::string user, std::vector<std::string> dec_list){
    DecDB &decDB = DecDB::getInstance();
    TierDB &tierDB = TierDB::getInstance();

    std::string dec_list_string = str_join(dec_list);
    decDB.putData(user, dec_list_string);

    int tier;
    tierDB.getData(user, tier);
    for (auto dec : dec_list){
        tierDB.putData(user, tier + 1);
    }

    if(decDB.status.ok()){
        return 0;
    }
    else{
        return -1;
    }
}

int RGWOrgDec::deleteDec(std::string user){
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
        return RGW_ORG_PERMISSION_ALLOWED;
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
        return RGW_ORG_TIER_NOT_ALLOWED;
    }

    return RGW_ORG_PERMISSION_ALLOWED;
}

int checkAclWrite(const std::string& request_user, const std::string& target_user, const std::string& path, const std::string& authorizer, int tier, bool r, bool w, bool x, bool g){
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
        return RGW_ORG_TIER_NOT_ALLOWED;
    }

    RGWOrg * request_user_org = getAcl(request_user, path);
    //std::string tmp = request_user_org->toString();
    if(request_user_org == nullptr || !request_user_org->getOrgPermission()->g){ // grant 권한이 없는 경우
        return RGW_ORG_PERMISSION_NOT_ALLOWED;
    }


    OrgPermissionFlags orgPermission(r, w, x, g, path);
    std::string anc_user;
    ret = getAnc(target_user, &anc_user);

    if(anc_user == request_user){
        return RGW_ORG_PERMISSION_ALLOWED;
    }

    RGWOrg *rgwOrg = getAcl(anc_user, path);

    if(rgwOrg != nullptr){
        OrgPermissionFlags *ancPermission = rgwOrg->getOrgPermission();

        if(ancPermission != nullptr && orgPermission < *ancPermission){ // anc의 권한이 요청한 권한을 포함하지 못하는 경우
            return RGW_ORG_PERMISSION_NOT_ALLOWED;
        }

        int authorizer_user_tier;
        ret = getTier(rgwOrg->getAuthorizer(), &authorizer_user_tier);

        if(authorizer_user_tier < request_user_tier){
            return RGW_ORG_TIER_NOT_ALLOWED;
        }
    }
    
    return RGW_ORG_PERMISSION_ALLOWED;
}

int checkHAclObjRead(const std::string& request_user, const std::string& bucket_name, const std::string& object_name){
    const std::string path = getObjectPath(bucket_name, object_name);
    RGWOrg *rgwOrg = getAcl(request_user, path, false);
    if(rgwOrg == nullptr){
        return RGW_ORG_PERMISSION_ALLOWED;
    }
    
    if(rgwOrg->getOrgPermission()->r){
        return RGW_ORG_PERMISSION_ALLOWED;
    }
    else{
        return RGW_ORG_PERMISSION_NOT_ALLOWED;
    }
}

int checkHAclObjWrite(const std::string& request_user, const std::string& bucket_name, const std::string& object_name){
    const std::string path = getObjectPath(bucket_name, object_name);
    RGWOrg *rgwOrg = getAcl(request_user, path, false);
    if(rgwOrg == nullptr){
        return RGW_ORG_KEY_NOT_FOUND;
    }
    
    if(rgwOrg->getOrgPermission()->w){
        return RGW_ORG_PERMISSION_ALLOWED;
    }
    else{
        return RGW_ORG_PERMISSION_NOT_ALLOWED;
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
    std::string canonicalHeaders = "host:" + hostHeader + "\n" + "x-amz-content-sha256:" + sha256_hex("") + "\n" + "x-amz-date:" + amzDate + "\n";
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

    // auto * ancAcl = getAcl(anc, "/");

    // if(ancAcl == nullptr){
    //     return -1;
    // }



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
        ret = RGWOrgDec::appendDecEdge(user, dec_list);
        if(ret < 0){
            return ret;
        }

        for (auto dec : dec_list){
            ret = putAnc(dec, user);
            if(ret < 0){
                return ret;
            }
        }

        ret = RGWOrgTier::updateUserTier(user);
    }
    RGWOrg *blackRgwOrg = new RGWOrg(user, anc);
    ret = putAcl(*blackRgwOrg);
    return 0;
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

    if(anc_ret == RGW_ORG_KEY_NOT_FOUND && dec_ret == RGW_ORG_KEY_NOT_FOUND) {
        return deleteOnlyUser(user);
    }
    if(anc_ret == RGW_ORG_KEY_NOT_FOUND) {
        return deleteWithDescendants(user, dec_list);
    }
    if(dec_ret == RGW_ORG_KEY_NOT_FOUND) {
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
    int ret = RGWOrgDec::deleteDec(user);
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
    int ret = RGWOrgDec::deleteDecEdge(anc, user);
    if(ret < 0) return ret;

    ret = RGWOrgDec::appendDecEdge(anc, dec_list);
    if(ret < 0) return ret;

    RGWOrgDec::putDec(anc, dec_list);
    if(ret < 0) return ret;

    ret = RGWOrgDec::deleteDec(user);
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
        return RGW_ORG_KEY_NOT_FOUND;
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
        return RGW_ORG_KEY_NOT_FOUND;
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

bool validateRGWOrgPermission(std::string user, std::string path, bool r, bool w, bool x, bool g){
    RGWOrg *rgwOrg = getAcl(user, path);
    if(rgwOrg == nullptr){
        return false;
    }
    OrgPermissionFlags *orgPermission = rgwOrg->getOrgPermission();

    // compare orgPermission and r, w, x, g
    // if request user has more permission than input r, w, x, g, return true
    
    if ((r && !orgPermission->r) ||
        (w && !orgPermission->w) ||
        (x && !orgPermission->x) ||
        (g && !orgPermission->g)) {
        return false;
    }

    return true;
}

int aclDB::getAllPartialMatchAcl(const std::string& prefix, std::vector<std::pair<std::string, RGWOrg>> &values){
    std::vector<std::pair<std::string, std::string>> str_values;
    int ret = getAllPartialMatchData(prefix, str_values);

    for (auto &pair : str_values) {
        std::string key = pair.first;
        std::string value = pair.second;
        RGWOrg *rgwOrg = new RGWOrg();
        ret = toRGWOrg(key, value, rgwOrg);

        values.push_back(std::make_pair(key, *rgwOrg));
    }
    return 0;
}

int aclDB::getSuperPathsForPrefix(const std::string& userPrefix, std::vector<std::pair<std::string, RGWOrg>> &values){
    std::istringstream iss(userPrefix);
    std::string segment;
    std::string accumulatedPath = "";
    std::string userPathPrefix = userPrefix.substr(0, userPrefix.find(":") + 1); // 사용자 이름 추출 (예: "user3:")
    bool isFirstSegment = true;

    while (std::getline(iss, segment, '/')) {
        if (!segment.empty() || isFirstSegment) {
            if (!isFirstSegment) {
                accumulatedPath += "/";
            } else {
                isFirstSegment = false;
            }
            accumulatedPath += segment;

            // 사용자 이름을 포함한 전체 경로 생성
            std::string fullPath = userPathPrefix + accumulatedPath;

            RGWOrg rgwOrg;
            aclDB &aclDB = aclDB::getInstance();
            // 사용자 이름을 포함한 경로로 getFullMatchRGWOrg 함수 호출
            RGWOrg::getFullMatchRGWOrg(aclDB, fullPath, &rgwOrg);
            values.push_back(std::make_pair(fullPath, rgwOrg));
        }
    }

    return values.empty() ? -1 : 0;
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
        aclDB &acl_db = aclDB::getInstance();
        ret = acl_db.getAllPartialMatchAcl(cur_name + ":", values);

        for (auto &pair : values) {
            auto &key = pair.first;
            auto &rgwOrg = pair.second;
            cur_j["permission"].push_back(rgwOrg.toJson());
        }

        if (ret == RGW_ORG_KEY_NOT_FOUND) {
            j_map[cur_name] = cur_j; // 현재 노드를 맵에 추가
            continue;
        } else if (ret < 0) {
            return ret;
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