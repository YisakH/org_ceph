#ifndef RGW_ORG_H
#define RGW_ORG_H


#include <string>
#include "rocksdb/db.h"
#include "rocksdb/options.h"
#include "rocksdb/status.h"
#include <mutex>
#include <utility>

namespace rocksdb{
  class DB;
  class Env;
  class Cache;
  class FilterPolicy;
  class Snapshot;
  class Slice;
  class WriteBatch;
  class Iterator;
  class Logger;
  class ColumnFamilyHandle;
  struct Options;
  struct BlockBasedTableOptions;
  struct DBOptions;
  struct ColumnFamilyOptions;
}


class DBManager
{
private:
    // 복사 생성자 및 할당 연산자 삭제
    DBManager(const DBManager&) = default;
    DBManager& operator=(const DBManager&) = delete;

    DBManager(std::string dbPath, const std::string &ip, std::string port)
            : DBManager(std::move(dbPath)) {
        this->ip = ip;
        this->port = std::move(port);
    }

protected:


public:
    std::string dbPath;
    std::string ip;
    std::string port;
    rocksdb::DB* db;
    rocksdb::Options options;
    rocksdb::Status status;

    ~DBManager() {
        delete db;
    }
    DBManager(std::string dbPath) : dbPath(std::move(dbPath)), db(nullptr) {
        //if(dbName == "RocksDB"){
        options.create_if_missing = true;
        status = rocksdb::DB::Open(options, dbPath, &db);
        //}
    }

    int reOpenDB() {
        delete db;
        status = rocksdb::DB::Open(options, dbPath, &db);
        if(status.ok()){
            return 0;
        }
        else{
            return -1;
        }
    }

    rocksdb::DB* getDB() const {
        return db;
    }
    rocksdb::Status getStatus() const {
        return status;
    }
    int getData(const std::string& key, std::string &value);
    int putData(const std::string& key, const std::string& value);
    int deleteData(const std::string& key);
};

// aclDB class
class aclDB : public DBManager {
public:
    static aclDB& getInstance() {
        static aclDB instance;
        return instance;
    }

private:
    aclDB() : DBManager("/tmp/org/aclDB") {}
};

// TierDB class
class TierDB : public DBManager {
public:
    static TierDB& getInstance() {
        static TierDB instance;
        return instance;
    }

private:
    TierDB() : DBManager("/tmp/org/TierDB") {}
};

// AncDB class
class AncDB : public DBManager {
public:
    static AncDB& getInstance() {
        static AncDB instance;
        return instance;
    }

private:
    AncDB() : DBManager("/tmp/org/AncDB") {}
};

class OrgPermission
{
public:
    bool r;
    bool w;
    bool x;
    bool g;
    std::string path;

OrgPermission() {
    r = false;
    w = false;
    x = false;
    g = false;
    path = "/";
    }

    OrgPermission(bool r, bool w, bool x, bool g) : r(r), w(w), x(x), g(g) {}
    OrgPermission(bool r, bool w, bool x, bool g, std::string path) : r(r), w(w), x(x), g(g), path(path){}
};

class RGWOrg
{
private:
    std::string user;
    std::string authorizer;
    uint16_t tier;
    OrgPermission* orgPermission;
public:
    RGWOrg(std::string user, const std::string &authorizer, uint16_t tier,
           OrgPermission* orgPermission) : user(std::move(user)), authorizer(authorizer), tier(tier),
                                                 orgPermission(orgPermission) {}

    RGWOrg(std::string user, const std::string &authorizer, uint16_t tier) : user(std::move(user)), authorizer(authorizer),
                                                                                     tier(tier){
                                                                                        orgPermission = new OrgPermission();
                                                                                     }
    RGWOrg(){
        
    }                                                                                 
    
    const std::string &getUser() const {
        return user;
    }

    const std::string &getAuthorizer() const {
        return authorizer;
    }

    uint16_t getTier() const {
        return tier;
    }

    OrgPermission* getOrgPermission() const {
        return orgPermission;
    }

    void setUser(const std::string &user) {
        RGWOrg::user = user;
    }

    void setAuthorizer(const std::string &authorizer) {
        RGWOrg::authorizer = authorizer;
    }

    void setTier(uint16_t tier) {
        RGWOrg::tier = tier;
    }

    void setOrgPermission(OrgPermission &orgPermission) {
        orgPermission = orgPermission;
    }

    int putRGWOrg(DBManager &dbManager);

    static int getRGWOrg(aclDB &aclDb, std::string key, RGWOrg *rgwOrg);

    static int deleteRGWOrg(aclDB &aclDB, std::string key);

    std::string toString() {
        return "user: " + user + ", authorizer: " + authorizer + ", tier: " + std::to_string(tier) + ", r: " + std::to_string(orgPermission->r) + ", w: " + std::to_string(orgPermission->w) + ", x: " + std::to_string(orgPermission->x) + ", g: " + std::to_string(orgPermission->g) + ", path: " + orgPermission->path;
    }

    static int getFullMatchRgwOrg(aclDB &aclDB, std::string user, std::string path, RGWOrg *rgwOrg);
};

class RGWOrgTier
{

public:
    // get user tier function
    static int getUserTier(std::string user, uint16_t *tier){
        std::string value;
        TierDB &tierDb = TierDB::getInstance();
        tierDb.getData(user, value);

        if(tierDb.status.ok()){
            *tier = std::stoi(value);
            return 0;
        }
        else{
            return -1;
        }
    }

    static int putUserTier(std::string user, uint16_t tier){
        std::string value = std::to_string(tier);
        TierDB &tierDb = TierDB::getInstance();
        tierDb.putData(user, value);

        if(tierDb.status.ok()){
            return 0;
        }
        else{
            return -1;
        }
    }

    static int deleteUserTier(std::string user){
        TierDB &tierDb = TierDB::getInstance();
        tierDb.deleteData(user);

        if(tierDb.status.ok()){
            return 0;
        }
        else{
            return -1;
        }
    }
};

class RGWOrgAnc
{

    public:
    static int getAnc(const std::string& user, std::string *anc){
        std::string value;
        AncDB &ancDB = AncDB::getInstance();

        ancDB.getData(user, value);

        if(ancDB.status.ok()){
            *anc = value;
            return 0;
        }
        else{
            return -1;
        }
    }

    static int putAnc(std::string user, std::string anc){
        AncDB &ancDB = AncDB::getInstance();
        ancDB.putData(user, anc);

        if(ancDB.status.ok()){
            return 0;
        }
        else{
            return -1;
        }
    }

    static int deleteAnc(std::string user){
        AncDB &ancDB = AncDB::getInstance();
        ancDB.deleteData(user);

        if(ancDB.status.ok()){
            return 0;
        }
        else{
            return -1;
        }
    }
};


RGWOrg* getAcl(const auto& user, const auto& path){
    auto& dbm = aclDB::getInstance();
    RGWOrg *rgwOrg;
    if(!dbm.getStatus().ok() && !dbm.getStatus().IsNotFound()) {
        dbm.reOpenDB();
        return nullptr;
    }
    
    rgwOrg = new RGWOrg();
    int ret = RGWOrg::getFullMatchRgwOrg(dbm, user, path, rgwOrg);

    if(ret < 0){
        return nullptr;
    }
    else{
        return rgwOrg;
    }
}

int getTier(const auto& user, uint16_t *tier){
    int ret = RGWOrgTier::getUserTier(user, tier);
    if(ret < 0){
        return -1;
    }
    else{
        return 0;
    }
}

int getAnc(const std::string& user, std::string *anc){
    int ret = RGWOrgAnc::getAnc(user, anc);
    return ret;
}

#endif