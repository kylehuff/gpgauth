#include "BrowserObjectAPI.h"
#include "variant_list.h"
#include "DOM/JSAPI_DOMDocument.h"
#include "gpgauth.h"
#include "gpgAuthPluginAPI.h"


gpgAuthPluginAPI::gpgAuthPluginAPI(FB::BrowserHostWrapper *host) : m_host(host)
{
    registerMethod("echo",      make_method(this, &gpgAuthPluginAPI::echo));
    registerMethod("testEvent", make_method(this, &gpgAuthPluginAPI::testEvent));
    registerMethod("getKeyList", make_method(this, &gpgAuthPluginAPI::getKeyList));
    registerMethod("getDomainKey", make_method(this, &gpgAuthPluginAPI::getDomainKey));
    registerMethod("verifyDomainKey", make_method(this, &gpgAuthPluginAPI::verifyDomainKey));
    registerMethod("gpgEncrypt", make_method(this, &gpgAuthPluginAPI::gpgEncrypt));
    registerMethod("gpgDecrypt", make_method(this, &gpgAuthPluginAPI::gpgDecrypt));

    // Read-write property
    registerProperty("testString",
                     make_property(this,
                        &gpgAuthPluginAPI::get_testString,
                        &gpgAuthPluginAPI::set_testString));

    // Read-only property
    registerProperty("version",
                     make_property(this,
                        &gpgAuthPluginAPI::get_version));
    
    registerEvent("onfired");
}

gpgAuthPluginAPI::~gpgAuthPluginAPI()
{
}

std::string gpgAuthPluginAPI::getKeyList(){
    gpgAuth gpgauth;
    return gpgauth.getKeyList("");
}

std::string gpgAuthPluginAPI::getDomainKey(std::string domain){
    gpgAuth gpgauth;
    return gpgauth.getKeyList(domain);
}

int gpgAuthPluginAPI::verifyDomainKey(std::string domain, std::string domain_key_fpr, std::string required_sig_keyid) {
    gpgAuth gpgauth;
    return gpgauth.verifyDomainKey(domain, domain_key_fpr, required_sig_keyid);
}

std::string gpgAuthPluginAPI::gpgEncrypt(std::string data, std::string enc_to_keyid, std::string enc_from_keyid, std::string sign){ 
    gpgAuth gpgauth;
    return gpgauth.gpgEncrypt(data, enc_to_keyid, enc_from_keyid, sign);
}

std::string gpgAuthPluginAPI::gpgDecrypt(std::string data){ 
    gpgAuth gpgauth;
    return gpgauth.gpgDecrypt(data);
}

// Read/Write property testString
std::string gpgAuthPluginAPI::get_testString()
{
    return m_testString;
}

void gpgAuthPluginAPI::set_testString(const std::string& val)
{
    m_testString = val;
}

// Read-only property version
std::string gpgAuthPluginAPI::get_version()
{
    return "CURRENT_VERSION";
}

// Method echo
FB::variant gpgAuthPluginAPI::echo(const FB::variant& msg)
{
    return msg;
}

void gpgAuthPluginAPI::testEvent(const FB::variant& var)
{
    FireEvent("onfired", FB::variant_list_of(var));
}

