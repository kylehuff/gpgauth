#include <string>
#include <sstream>
#include <boost/weak_ptr.hpp>
#include "JSAPIAuto.h"
#include "BrowserHost.h"
#include "gpgauth.h"
#include "gpgAuthPlugin.h"

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

    // Read/Write property ${PROPERTY.ident}
    std::string get_testString();
    void set_testString(const std::string& val);

    std::string getKeyList();
    std::string getPrivateKeyList();
    std::string getDomainKey(std::string domain);
    int verifyDomainKey(std::string domain, std::string domain_key_fpr, 
        long uid_idx, std::string required_sig_keyid);
    std::string gpgEncrypt(std::string data, std::string enc_to_keyid, 
        std::string enc_from_keyid=NULL, std::string sign=NULL);
    std::string gpgDecrypt(std::string data);
    std::string gpgSignUID(std::string keyid, long sign_uid,
        std::string with_keyid, long local_only=NULL, long trust_sign=NULL, 
        std::string trust_sign_level=NULL);
    std::string gpgDeleteUIDSign(std::string keyid, long sign_uid,
        long signature);
    std::string gpgEnableKey(std::string keyid);
    std::string gpgDisableKey(std::string keyid);
    std::string gpgGenKey(std::string key_type, std::string key_length,
            std::string subkey_type, std::string subkey_length,
            std::string name_real, std::string name_comment,
            std::string name_email, std::string expire_date,
            std::string passphrase);
    void threaded_gpgGenKey(genKeyParams params);
    std::string gpgImportKey(std::string ascii_key);

    // Read-only property ${PROPERTY.ident}
    std::string get_version();

    // Method echo
    FB::variant echo(const FB::variant& msg);

    static void progress_cb(
        void *self, const char *what,
        int type, int current, int total
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
