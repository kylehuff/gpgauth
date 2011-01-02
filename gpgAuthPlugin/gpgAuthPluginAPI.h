#include <string>
#include <stdarg.h>
#include <boost/weak_ptr.hpp>
#include "JSAPIAuto.h"
#include "BrowserHost.h"
#include "gpgAuthPlugin.h"

#include <gpgme.h>

#ifndef H_gpgAuthPluginAPI
#define H_gpgAuthPluginAPI

struct genKeyParams {
    std::string key_type;
    std::string key_length;
    std::string subkey_type;
    std::string subkey_length;
    std::string name_real;
    std::string name_comment;
    std::string name_email;
    std::string expire_date;
    std::string passphrase;
};

class gpgAuthPluginAPI : public FB::JSAPIAuto
{
public:
	gpgAuthPluginAPI(gpgAuthPluginPtr plugin, FB::BrowserHostPtr host);
    virtual ~gpgAuthPluginAPI();
    
    gpgAuthPluginPtr getPlugin();

    int init();

    int is_initted;
    std::string get_gpgme_version();
    std::string _gpgme_version;
    std::string get_testString();
    gpgme_ctx_t get_gpgme_ctx();
    void set_testString(const std::string& val);

    FB::variant getKeyList(const std::string& domain, int secret_only);
    FB::variant getPublicKeyList();
    FB::variant getPrivateKeyList();
    FB::variant getDomainKey(const std::string& domain);
    int verifyDomainKey(const std::string& domain, const std::string& domain_key_fpr, 
        long uid_idx, const std::string& required_sig_keyid);

    std::string get_preference(const std::string& preference);
    std::string set_preference(const std::string& preference, const std::string& pref_value);

    std::string gpgEncrypt(const std::string& data, const std::string& enc_to_keyid, 
        const std::string& enc_from_keyid=NULL, const std::string& sign=NULL);
    std::string gpgDecrypt(const std::string& data);
    std::string gpgSignUID(const std::string& keyid, long uid,
        const std::string& with_keyid, long local_only=NULL, long trust_sign=NULL, 
        long trust_level=NULL);
    std::string gpgDeleteUIDSign(const std::string& keyid, long sign_uid,
        long signature);
    std::string gpgEnableKey(const std::string& keyid);
    std::string gpgDisableKey(const std::string& keyid);
    std::string gpgGenKey(const std::string& key_type, const std::string& key_length,
            const std::string& subkey_type, const std::string& subkey_length,
            const std::string& name_real, const std::string& name_comment,
            const std::string& name_email, const std::string& expire_date,
            const std::string& passphrase);
    void threaded_gpgGenKey(genKeyParams params);
    FB::variant gpgImportKey(const std::string& ascii_key);

    std::string get_version();
    std::string gpgconf_detected();

    static void progress_cb(
        void *self, const char *what,
        int type, int current, int total
    );

    std::string gpgGenKeyWorker(const std::string& key_type, const std::string& key_length, 
        const std::string& subkey_type, const std::string& subkey_length, const std::string& name_real,
        const std::string& name_comment, const std::string& name_email, const std::string& expire_date,
        const std::string& passphrase, void* APIObj, void(*cb_status)(void *self,
                                            const char *what,
                                            int type,
                                            int current,
                                            int total
                                        )
    );

    /*
        static class method which accepts the calling object as a parameter
            so it can thread a member function
    */
    static void threadCaller(gpgAuthPluginAPI* api,
        genKeyParams params)
    {
        api->threaded_gpgGenKey(params);
    };

private:
    //FB::AutoPtr<FB::BrowserHostWrapper> m_host;
    gpgAuthPluginWeakPtr m_plugin;
    FB::BrowserHostPtr m_host;
    std::string m_testString;
};

#endif // H_gpgAuthPluginAPI
