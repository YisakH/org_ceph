
#include <string>
#include "rocksdb/db.h"
#include "rocksdb/options.h"
#include "rocksdb/status.h"

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
    std::string dbName;
    std::string ip;
    std::string port;
    rocksdb::DB* db;
    rocksdb::Options options;
    rocksdb::Status status;
public:

    DBManager(const std::string &dbName, const std::string &ip, const std::string &port) : dbName(dbName), ip(ip),
                                                                                           port(port) {}
    DBManager(const std::string &dbName) : dbName(dbName) {}                                                                                       

    ~DBManager() {
        delete db;
    }

    rocksdb::Status init();
    int getData(std::string key, std::string &value);
    int putData(std::string key, std::string value);
    int deleteData(std::string key);
};

class OrgPermission
{
public:
    bool r;
    bool w;
    bool x;
    bool g;

OrgPermission() {
    r = false;
    w = false;
    x = false;
    g = false;
}
};

class RGWOrg
{
private:
    std::string user;
    std::string authorizer;
    uint16_t tier;
    OrgPermission* orgPermission;
public:
    RGWOrg(const std::string &user, const std::string &authorizer, uint16_t tier,
           OrgPermission* orgPermission) : user(user), authorizer(authorizer), tier(tier),
                                                 orgPermission(orgPermission) {}

    RGWOrg(const std::string &user, const std::string &authorizer, uint16_t tier) : user(user), authorizer(authorizer),
                                                                                     tier(tier){
                                                                                        orgPermission = new OrgPermission();
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

    int getRGWOrg(DBManager &dbManager, std::string user);
};