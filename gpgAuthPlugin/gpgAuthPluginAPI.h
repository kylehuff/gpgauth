#include <string>
#include <sstream>
#include "JSAPIAuto.h"
#include "BrowserHostWrapper.h"
#include "JSAPI.h"
#ifndef H_gpgAuthPluginAPI
#define H_gpgAuthPluginAPI

class gpgAuthPluginAPI : public FB::JSAPIAuto
{
public:
    gpgAuthPluginAPI(FB::BrowserHostWrapper *host);
    virtual ~gpgAuthPluginAPI();

    // Read/Write property ${PROPERTY.ident}
    std::string get_testString();
    void set_testString(const std::string& val);

    std::string getKeyList(const FB::CatchAll& args);
    std::string gpgEncrypt(const FB::CatchAll& args);

    // Read-only property ${PROPERTY.ident}
    std::string get_version();

    // Method echo
    FB::variant echo(const FB::variant& msg);
    
    // Method test-event
    void testEvent(const FB::variant& s);

private:
    FB::AutoPtr<FB::BrowserHostWrapper> m_host;

    std::string m_testString;
};

#endif // H_gpgAuthPluginAPI
