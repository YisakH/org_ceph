#ifndef RGW_ORG_H
#define RGW_ORG_H


#include <string>
#include "rocksdb/db.h"
#include "rocksdb/options.h"
#include "rocksdb/status.h"
#include "rocksdb/slice_transform.h"
#include "rocksdb/filter_policy.h"
#include <mutex>
#include <utility>
#include <nlohmann/json.hpp>
#include <filesystem>

#define RGW_ORG_TIER_NOT_ALLOWED -2
#define RGW_ORG_PERMISSION_NOT_ALLOWED -3
#define RGW_ORG_PERMISSION_ALLOWED 0
#define RGW_ORG_KEY_NOT_FOUND -4

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

namespace fs = std::filesystem;

class DBManager;
class RGWOrg;

class OrgPermissionFlags
{
public:
    bool r;
    bool w;
    bool x;
    bool g;
    std::string path;

    OrgPermissionFlags();

    OrgPermissionFlags(bool r, bool w, bool x, bool g) : r(r), w(w), x(x), g(g) {}
    OrgPermissionFlags(bool r, bool w, bool x, bool g, std::string path) : r(r), w(w), x(x), g(g), path(path){}
    bool operator<=(const OrgPermissionFlags &other) const;
    bool operator<(const OrgPermissionFlags &other) const;
};

class DBManager
{
private:
    DBManager(std::string dbPath, const std::string &ip, std::string port)
            : DBManager(std::move(dbPath)) {
        this->ip = ip;
        this->port = std::move(port);
    }
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
    DBManager(const std::string& dbPath) : dbPath(std::move(dbPath)), db(nullptr) {
        //if(dbName == "RocksDB"){
        options.create_if_missing = true;
        options.prefix_extractor.reset(rocksdb::NewFixedPrefixTransform(1));

        if (!fs::exists(dbPath)) {
            // 폴더가 존재하지 않으면 생성
            if (!fs::create_directory(dbPath)){
                // 폴더 생성 실패 처리 해야함.
            }
        }

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
    int getAllPartialMatchData(const std::string& prefix, std::vector<std::pair<std::string, std::string>> &values);
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
    int getAllPartialMatchAcl(const std::string& prefix, std::vector<std::pair<std::string, RGWOrg>> &values);
    static int getSuperPathsForPrefix(const std::string& prefix, std::vector<std::pair<std::string, RGWOrg>> &values);

private:
    aclDB() : DBManager("/tmp/org/AclDB") {}
};

// TierDB class
class TierDB : public DBManager {
public:
    static TierDB& getInstance() {
        static TierDB instance;
        return instance;
    }

    int putData(const std::string& key, const int &value);
    int getData(const std::string& key, int &value);

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

class DecDB : public DBManager {
    public:
    static DecDB& getInstance() {
        static DecDB instance;
        return instance;
    }
    private:
    DecDB() : DBManager("/tmp/org/DecDB") {}
};


class RGWOrg
{
public:
    std::string user;
    std::string authorizer;
    int tier;
    OrgPermissionFlags* orgPermission;
    RGWOrg(std::string user, const std::string &authorizer, uint16_t tier,
           OrgPermissionFlags* orgPermission) : user(std::move(user)), authorizer(authorizer), tier(tier),
                                                orgPermission(orgPermission) {}

    RGWOrg(std::string user, const std::string &authorizer, uint16_t tier) : user(std::move(user)), authorizer(authorizer),
                                                                                     tier(tier){
                                                                                        orgPermission = new OrgPermissionFlags();
                                                                                     }
    RGWOrg(){
        orgPermission = new OrgPermissionFlags();
        user = "";
        authorizer = "";
        tier = -1;
    }                                      
    RGWOrg(const std::string &user, const std::string &authorizer);        
    
    const std::string &getUser() const {
        return user;
    }

    const std::string &getAuthorizer() const {
        return authorizer;
    }

    uint16_t getTier() const {
        return tier;
    }

    OrgPermissionFlags* getOrgPermission() const {
        return orgPermission;
    }

    void setUser(const std::string &user) {
        RGWOrg::user = user;
    }

    void setAuthorizer(const std::string &authorizer) {
        RGWOrg::authorizer = authorizer;
    }

    void setTier(int tier) {
        RGWOrg::tier = tier;
    }

    void setOrgPermission(OrgPermissionFlags &newOrgPermission) {
        orgPermission = &newOrgPermission;
    }

    int putRGWOrg(DBManager &dbManager);

    static int getFullMatchRGWOrg(aclDB &aclDB, const std::string& key, RGWOrg *rgwOrg);

    static int deleteRGWOrg(aclDB &aclDB, const std::string& key);

    std::string toString();

    nlohmann::json toJson();

    static int getPartialMatchRgwOrg(aclDB &aclDB, const std::string& user, const std::string& path, RGWOrg *rgwOrg);
};



class RGWOrgTier
{

public:
    // get user tier function
    static int getUserTier(std::string user, int *tier);

    static int putUserTier(std::string user, int tier){
        TierDB &tierDb = TierDB::getInstance();
        tierDb.putData(user, tier);

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

    static int updateUserTier(const std::string &start_user);
};

class RGWOrgAnc
{

    public:
    static int getAnc(const std::string& user, std::string *anc);

    static int putAnc(std::string user, std::string anc);

    static int deleteAnc(std::string user){
        AncDB &ancDB = AncDB::getInstance();
        ancDB.deleteData(user);

        RGWOrgTier::putUserTier(user, 0);

        if(ancDB.status.ok()){
            return 0;
        }
        else{
            return -1;
        }
    }

    static int updateAnc(std::string user, std::string anc){
        AncDB &ancDB = AncDB::getInstance();
        ancDB.putData(user, anc);

        if(ancDB.status.ok()){
            return 0;
        }
        else{
            return -1;
        }
    }
};

class RGWOrgDec
{
    public:
    static int getDec(const std::string& user, std::vector<std::string> *dec_list);
    static int putDec(std::string user, std::vector<std::string> dec_list);
    static int deleteDec(std::string user);
    static int updateDec(std::string user, std::vector<std::string> dec_list);
    static int decListToString(std::vector<std::string> &dec_list, std::string *dec_list_str);
    static int appendDecEdge(const std::string& user, const std::string& dec);
    static int appendDecEdge(const std::string& user, const std::vector<std::string>& dec_list);
    static bool existDecEdge(const std::string& user, const std::string& dec);
    static int deleteDecEdge(const std::string& user, const std::string& dec);
    static int getRGWOrgDecTree(const std::string &start_user, nlohmann::json &j);
};

class RGWOrgUser
{
public:
    static int putUser(std::string user, std::string anc = "", std::vector<std::string> dec_list = std::vector<std::string>());
    static int putUser(std::string user, std::string anc, std::string dec_list_str);
    static int deleteUser(const std::string &user);
    static int updateUser();
    
    static int deleteOnlyUser(const std::string &user);
    static int deleteWithDescendants(const std::string &user, const std::vector<std::string> &dec_list);
    static int deleteWithAncestor(const std::string &user);
    static int deleteWithBoth(const std::string &user, const std::string &anc, const std::vector<std::string> &dec_list);
};

RGWOrg* getAcl(const std::string& user, const std::string& path, bool isFullMatch = false);
int putAcl(const std::string& user, const std::string& path, const std::string& authorizer, int tier, bool r, bool w, bool x, bool g);
int deleteAcl(const std::string& user, const std::string& path);
int checkAclWrite(const std::string& request_user, const std::string& user, const std::string& path, const std::string& authorizer, int tier, bool r, bool w, bool x, bool g);
int checkAclRead(const std::string& request_user, const std::string& target_user);

int checkHAclObjRead(const std::string& request_user, const std::string& bucket_name, const std::string& object_name);
int checkHAclObjWrite(const std::string& request_user, const std::string& bucket_name, const std::string& object_name);

int getTier(const std::string& user, int *tier);
int putTier(const std::string& user, int tier);
int deleteTier(const std::string& user);

int getAnc(const std::string& user, std::string *anc);
int putAnc(const std::string& user, const std::string &anc);
int deleteAnc(const std::string& user);

std::string to_hex(const unsigned char *data, int len);

std::string hmac_sha256(const std::string &key, const std::string &data);

std::string getSignature(const std::string &secret_key, const std::string &date, const std::string &region, 
                         const std::string &service, const std::string &string_to_sign);
std::string getAuthHeader(const std::string &access_key, const std::string &secret_key, const std::string &host, const std::string &method, const std::string &canonicalUri, const std::string &canonicalQueryString, 
                        const std::string &signedHeaders);
std::string sha256_hex(const std::string &data);
std::string generateCanonicalHeaders(const std::string &hostHeader, const std::string &amzDate);
std::string generatePayloadHash(const std::string &payload);
std::string createAuthHeader(const std::string& accessKey, const std::string& date, 
                             const std::string& region, const std::string& service, 
                             const std::string& signedHeaders, const std::string& signature);

bool validateRGWOrgPermission(std::string user, std::string path, bool r = false, bool w = false, bool x = false, bool g = false);

std::vector<std::string> str_split_to_vec(const std::string& s);
std::string str_join(const std::vector<std::string>& v);

#endif