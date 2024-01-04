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

    DBManager(std::string dbName, const std::string &ip, std::string port)
            : DBManager(std::move(dbName)) {
        this->ip = ip;
        this->port = port;
    }
    DBManager(std::string dbName) : dbName(std::move(dbName)), db(nullptr) {
        //if(dbName == "RocksDB"){
            options.create_if_missing = true;
            status = rocksdb::DB::Open(options, "/tmp/testdb", &db);
        //}
    }
public:
    std::string dbName;
    std::string ip;
    std::string port;
    rocksdb::DB* db;
    rocksdb::Options options;
    rocksdb::Status status;
    ~DBManager() {
        delete db;
    }

    static DBManager& getInstance(const std::string &dbName) {
        static DBManager instance(dbName);
        return instance;
    }

    int reOpenDB() {
        delete db;
        status = rocksdb::DB::Open(options, "/tmp/testdb", &db);
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

    static int getRGWOrg(DBManager &dbManager, std::string key, RGWOrg *rgwOrg);

    static int deleteRGWOrg(DBManager &dbManager, std::string key);

    std::string toString() {
        return "user: " + user + ", authorizer: " + authorizer + ", tier: " + std::to_string(tier) + ", r: " + std::to_string(orgPermission->r) + ", w: " + std::to_string(orgPermission->w) + ", x: " + std::to_string(orgPermission->x) + ", g: " + std::to_string(orgPermission->g) + ", path: " + orgPermission->path;
    }

    static int getFullMatchRgwOrg(DBManager &dbManager, std::string user, std::string path, RGWOrg *rgwOrg);
};

#endif