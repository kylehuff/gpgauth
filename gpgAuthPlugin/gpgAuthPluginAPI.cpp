#include "JSObject.h"
#include "variant_list.h"
#include "DOM/Document.h"

#include "gpgAuthPluginAPI.h"

gpgAuthPluginAPI::gpgAuthPluginAPI(gpgAuthPluginPtr plugin, FB::BrowserHostPtr host) : m_plugin(plugin), m_host(host)
{
    registerMethod("getKeyList", make_method(this, &gpgAuthPluginAPI::getKeyList));
    registerMethod("getPrivateKeyList", make_method(this, &gpgAuthPluginAPI::getPrivateKeyList));
    registerMethod("getDomainKey", make_method(this, &gpgAuthPluginAPI::getDomainKey));
    registerMethod("verifyDomainKey", make_method(this, &gpgAuthPluginAPI::verifyDomainKey));
    registerMethod("gpgEncrypt", make_method(this, &gpgAuthPluginAPI::gpgEncrypt));
    registerMethod("gpgDecrypt", make_method(this, &gpgAuthPluginAPI::gpgDecrypt));
    registerMethod("gpgSignUID", make_method(this, &gpgAuthPluginAPI::gpgSignUID));
    registerMethod("gpgEnableKey", make_method(this, &gpgAuthPluginAPI::gpgEnableKey));
    registerMethod("gpgDisableKey", make_method(this, &gpgAuthPluginAPI::gpgDisableKey));
    registerMethod("gpgDeleteUIDSign", make_method(this, &gpgAuthPluginAPI::gpgDeleteUIDSign));
    registerMethod("gpgGenKey", make_method(this, &gpgAuthPluginAPI::gpgGenKey));
    registerMethod("gpgImportKey", make_method(this, &gpgAuthPluginAPI::gpgImportKey));

    registerEvent("onkeygenprogress");
    registerEvent("onkeygencomplete");

    // Read-only property
    registerProperty("version",
                     make_property(this,
                        &gpgAuthPluginAPI::get_version));
}

gpgAuthPluginAPI::~gpgAuthPluginAPI()
{
}

gpgAuthPluginPtr gpgAuthPluginAPI::getPlugin()
{
    gpgAuthPluginPtr plugin(m_plugin.lock());
    if (!plugin) {
        throw FB::script_error("The plugin is invalid");
    }
    return plugin;
}


/*
    This method executes gpgauth.getKeyList with an empty string which
        returns all keys in the keyring.
*/
std::string gpgAuthPluginAPI::getKeyList(){
    gpgAuth gpgauth;
    return gpgauth.getKeyList("");
}

/*
    This method executes gpgauth.getKeyList with an empty string and
        secret_only=1 which returns all keys in the keyring which
        the user has the corrisponding secret key.
*/

std::string gpgAuthPluginAPI::getPrivateKeyList(){
    gpgAuth gpgauth;
    return gpgauth.getKeyList("", 1);
}

/* 
    This method just calls gpgauth.getKeyList with a domain name
        as the parameter
*/
std::string gpgAuthPluginAPI::getDomainKey(std::string domain){
    gpgAuth gpgauth;
    return gpgauth.getKeyList(domain, 0);
}

/*
    This method ensures a given UID <domain> with matching keyid
        <domain_key_fpr> has been signed by a required key
        <required_sig_keyid> and returns a GAU_trust value as the result.
        This method is intended to be called during an iteration of
        trusted key ids.
*/
int gpgAuthPluginAPI::verifyDomainKey(std::string domain, 
        std::string domain_key_fpr, long uid_idx,
        std::string required_sig_keyid)
{
    gpgAuth gpgauth;
    return gpgauth.verifyDomainKey(domain, domain_key_fpr, uid_idx, 
        required_sig_keyid);
}

/*
    This method passes a string to encrypt, a key to encrypt to and an
        optional key to encrypt from and calls gpgauth.gpgEncrypt.
        This method returns a string of the encrypted data.
*/
std::string gpgAuthPluginAPI::gpgEncrypt(std::string data, 
        std::string enc_to_keyid, std::string enc_from_keyid,
        std::string sign)
{
    gpgAuth gpgauth;
    return gpgauth.gpgEncrypt(data, enc_to_keyid, enc_from_keyid, sign);
}

std::string gpgAuthPluginAPI::gpgDecrypt(std::string data)
{
    gpgAuth gpgauth;
    return gpgauth.gpgDecrypt(data);
}

std::string gpgAuthPluginAPI::gpgSignUID(std::string keyid, long sign_uid,
    std::string with_keyid, long local_only, long trust_sign, 
    std::string trust_sign_level)
{
    gpgAuth gpgauth;
    return gpgauth.gpgSignUID(keyid, sign_uid, with_keyid, local_only, 
        trust_sign, trust_sign_level);
}

std::string gpgAuthPluginAPI::gpgEnableKey(std::string keyid)
{
    gpgAuth gpgauth;
    return gpgauth.gpgEnableKey(keyid);
}

std::string gpgAuthPluginAPI::gpgDisableKey(std::string keyid)
{
    gpgAuth gpgauth;
    return gpgauth.gpgDisableKey(keyid);
}


std::string gpgAuthPluginAPI::gpgDeleteUIDSign(std::string keyid,
    long sign_uid, long signature) {
    gpgAuth gpgauth;
    return gpgauth.gpgDeleteUIDSign(keyid, sign_uid, signature);
}

void gpgAuthPluginAPI::progress_cb(void *self, const char *what, int type, int current, int total)
{
    if (!strcmp (what, "primegen") && !current && !total
        && (type == '.' || type == '+' || type == '!'
        || type == '^' || type == '<' || type == '>')) {
        gpgAuthPluginAPI* API = (gpgAuthPluginAPI*) self;
        API->FireEvent("onkeygenprogress", FB::variant_list_of(type));
    }
    if (!strcmp (what, "complete")) {
        gpgAuthPluginAPI* API = (gpgAuthPluginAPI*) self;
        API->FireEvent("onkeygencomplete", FB::variant_list_of("complete"));
    }
}

void gpgAuthPluginAPI::threaded_gpgGenKey(genKeyParams params)
{
    gpgAuth gpgauth;
    
    string result = gpgauth.gpgGenKey(params.key_type, params.key_length,
        params.subkey_type, params.subkey_length, params.name_real,
        params.name_comment, params.name_email, params.expire_date,
        params.passphrase, this, &gpgAuthPluginAPI::progress_cb
    );

}

std::string gpgAuthPluginAPI::gpgGenKey(std::string key_type, 
        std::string key_length, std::string subkey_type, 
        std::string subkey_length, std::string name_real,
        std::string name_comment, std::string name_email, 
        std::string expire_date, std::string passphrase)
{
    gpgAuth gpgauth;

    genKeyParams params;
    
    params.key_type = key_type;
    params.key_length = key_length;
    params.subkey_type = subkey_type;
    params.subkey_length = subkey_length;
    params.name_real = name_real;
    params.name_comment = name_comment;
    params.name_email = name_email;
    params.expire_date = expire_date;
    params.passphrase = passphrase;
    
    boost::thread genkey_thread(
        boost::bind(
            &gpgAuthPluginAPI::threadCaller,
            this, params)
    );

    return "queued";
}

std::string gpgAuthPluginAPI::gpgImportKey(std::string ascii_key) {
	gpgAuth gpgauth;
	return gpgauth.gpgImportKey(ascii_key);
}

// Read-only property version
std::string gpgAuthPluginAPI::get_version()
{
    return "CURRENT_VERSION";
}
