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


std::string gpgAuthPluginAPI::getKeyList(const FB::CatchAll& args){ 
    gpgAuth gpgauth;    
    gpgauth.init();
    std::string test = gpgauth.getKeyList();
    return test;
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

