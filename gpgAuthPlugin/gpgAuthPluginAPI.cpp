#include "BrowserObjectAPI.h"
#include "variant_list.h"
#include "DOM/JSAPI_DOMDocument.h"
#include "gpgauth.h"
#include "gpgAuthPluginAPI.h"


gpgAuthPluginAPI::gpgAuthPluginAPI(FB::BrowserHostWrapper *host) : m_host(host)
{
    registerMethod("getKeyList", make_method(this, &gpgAuthPluginAPI::getKeyList));
    registerMethod("getPrivateKeyList", make_method(this, &gpgAuthPluginAPI::getPrivateKeyList));
    registerMethod("getDomainKey", make_method(this, &gpgAuthPluginAPI::getDomainKey));
    registerMethod("verifyDomainKey", make_method(this, &gpgAuthPluginAPI::verifyDomainKey));
    registerMethod("gpgEncrypt", make_method(this, &gpgAuthPluginAPI::gpgEncrypt));
    registerMethod("gpgDecrypt", make_method(this, &gpgAuthPluginAPI::gpgDecrypt));
    registerMethod("gpgSignUID", make_method(this, &gpgAuthPluginAPI::gpgSignUID));
    registerMethod("gpgDeleteUIDSign", make_method(this, &gpgAuthPluginAPI::gpgDeleteUIDSign));

    // Read-only property
    registerProperty("version",
                     make_property(this,
                        &gpgAuthPluginAPI::get_version));
}

gpgAuthPluginAPI::~gpgAuthPluginAPI()
{
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
    return gpgauth.getKeyList(domain);
}

/*
    This method ensures a given UID <domain> with matching keyid
        <domain_key_fpr> has been signed by a required key
        <required_sig_keyid> and returns a GAU_trust value as the result.
        This method is intended to be called during an iteration of
        trusted key ids.
*/
int gpgAuthPluginAPI::verifyDomainKey(std::string domain, 
        std::string domain_key_fpr, std::string required_sig_keyid) {
    gpgAuth gpgauth;
    return gpgauth.verifyDomainKey(domain, domain_key_fpr, required_sig_keyid);
}

/*
    This method passes a string to encrypt, a key to encrypt to and an
        optional key to encrypt from and calls gpgauth.gpgEncrypt.
        This method returns a string of the encrypted data.
*/
std::string gpgAuthPluginAPI::gpgEncrypt(std::string data, 
        std::string enc_to_keyid, std::string enc_from_keyid,
        std::string sign) {
    gpgAuth gpgauth;
    return gpgauth.gpgEncrypt(data, enc_to_keyid, enc_from_keyid, sign);
}

std::string gpgAuthPluginAPI::gpgDecrypt(std::string data) {
    gpgAuth gpgauth;
    return gpgauth.gpgDecrypt(data);
}

std::string gpgAuthPluginAPI::gpgSignUID(std::string keyid, long sign_uid,
        std::string with_keyid, long local_only, long trust_sign, std::string trust_sign_level) {
        gpgAuth gpgauth;
        return gpgauth.gpgSignUID(keyid, sign_uid, with_keyid, local_only, trust_sign, trust_sign_level);
}

std::string gpgAuthPluginAPI::gpgDeleteUIDSign(std::string keyid, long sign_uid,
        long signature) {
        gpgAuth gpgauth;
        return gpgauth.gpgDeleteUIDSign(keyid, sign_uid, signature);
}

// Read-only property version
std::string gpgAuthPluginAPI::get_version()
{
    return "CURRENT_VERSION";
}
