#include "NpapiTypes.h"
#include "gpgAuthPluginAPI.h"

#include "gpgAuthPlugin.h"

void gpgAuthPlugin::StaticInitialize()
{
    // Place one-time initialization stuff here; note that there isn't an absolute guarantee that
    // this will only execute once per process, just a guarantee that it won't execute again until
    // after StaticDeinitialize is called
}

void gpgAuthPlugin::StaticDeinitialize()
{
    // Place one-time deinitialization stuff here
}


gpgAuthPlugin::gpgAuthPlugin()
{
}

gpgAuthPlugin::~gpgAuthPlugin()
{
}

void gpgAuthPlugin::onPluginReady()
{
    // When this is called, the BrowserHost is attached, the JSAPI object is
    // created, and we are ready to interact with the page and such.  The
    // PluginWindow may or may not have already fire the AttachedEvent at
    // this point.
}

FB::JSAPIPtr gpgAuthPlugin::createJSAPI()
{
    // m_host is the BrowserHostWrapper
    //return FB::JSAPIPtr(new gpgAuthPluginAPI(m_host));
    return FB::JSAPIPtr(new gpgAuthPluginAPI(FB::ptr_cast<gpgAuthPlugin>(shared_ptr()), m_host));
}


