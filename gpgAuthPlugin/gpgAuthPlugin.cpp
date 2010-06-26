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

FB::JSAPI* gpgAuthPlugin::createJSAPI()
{
    // m_host is the BrowserHostWrapper
    return new gpgAuthPluginAPI(m_host);
}

bool gpgAuthPlugin::onMouseDown(FB::MouseDownEvent *evt, FB::PluginWindow *)
{
    //printf("Mouse down at: %d, %d\n", evt->m_x, evt->m_y);
    return false;
}

bool gpgAuthPlugin::onMouseUp(FB::MouseUpEvent *evt, FB::PluginWindow *)
{
    //printf("Mouse up at: %d, %d\n", evt->m_x, evt->m_y);
    return false;
}

bool gpgAuthPlugin::onMouseMove(FB::MouseMoveEvent *evt, FB::PluginWindow *)
{
    //printf("Mouse move at: %d, %d\n", evt->m_x, evt->m_y);
    return false;
}
bool gpgAuthPlugin::onWindowAttached(FB::AttachedEvent *evt, FB::PluginWindow *)
{
    // The window is attached; act appropriately
    return false;
}

bool gpgAuthPlugin::onWindowDetached(FB::DetachedEvent *evt, FB::PluginWindow *)
{
    // The window is about to be detached; act appropriately
    return false;
}
